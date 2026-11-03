"""Parse the raw whois text bgp.he.net returns for domains and ASNs.

Whois has no single format. Domain records come in (at least) three shapes, and ASN records
in two, so the parsers here are best effort: they pull out what the Synapse model has a place
for, and the full text is always kept with the record.

Domain whois:

- ICANN style ``Key: Value`` lines (gTLDs and most ccTLDs, ex. ``Creation Date: ...``).
- Sectioned records (ex. Nominet's ``.uk``), where a ``Key:`` line is followed by indented
  value lines.
- Terse registries (ex. DENIC's ``.de``), ``Nserver:``/``Changed:`` and little else.

ASN whois:

- ARIN's ``ASNumber:``/``OrgName:`` records.
- RPSL objects (RIPE, APNIC, AFRINIC, and LACNIC), an ``aut-num`` object, plus the
  ``organisation``, ``role``, and ``person`` objects it references.
"""

import datetime
import re
from collections.abc import Iterable

# ---- Shared helpers ----

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
"""Email addresses, used to pick them out of free text (ex. ``Comment:`` lines)."""

REDACTED_RE = re.compile(
    r"redacted|not disclosed|data protected|non-public|statutory masking|"
    r"please query the rdds|contact privacy|gdpr",
    re.IGNORECASE,
)
"""Values registries put in place of personal data."""

TIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%Y.%m.%d %H:%M:%S",
    "%Y.%m.%d",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d",
    "%Y%m%d",
    "%d-%b-%Y",
    "%d-%B-%Y",
    "%d.%m.%Y %H:%M:%S",
    "%d.%m.%Y",
    "%d/%m/%Y",
    "%H:%M:%S %d-%b-%Y",
    "%b %d %Y",
    "%d %b %Y",
)
"""The time formats seen in whois records, tried in order."""


def fixText(text: str) -> str:
    """Undo the mojibake in whois text that was UTF-8 decoded as Latin-1 (ex. ``MajÃ³``).

    bgp.he.net passes some registries' (ex. LACNIC's) UTF-8 text through a Latin-1 decode.
    Lines that don't round trip are left as is.
    """

    lines = []
    for line in text.split("\n"):
        try:
            fixed = line.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            fixed = line
        lines.append(fixed)
    return "\n".join(lines)


def parseTime(valu: str | None) -> int | None:
    """Parse a whois time to epoch millis (naive times are UTC), or None."""

    if not valu:
        return None
    text = valu.strip()
    # Drop trailing zone names and notes, ex. "2020-01-01 (UTC)", "2025-01-01 UTC".
    text = re.sub(r"\s*\(?\b(UTC|GMT|Z)\b\)?$", "", text, flags=re.IGNORECASE).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Python 3.11's %f only takes up to 6 digits, and %z wants +HHMM or +HH:MM.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    for fmt in TIME_FORMATS:
        try:
            # Naive times are UTC, see below.
            when = datetime.datetime.strptime(text, fmt)  # noqa: DTZ007
        except ValueError:
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=datetime.UTC)
        return int(when.timestamp() * 1000)
    return None


def clean(valu: str | None) -> str | None:
    """Strip a value (and any trailing commas), returning None for empty and redacted values."""

    if valu is None:
        return None
    valu = " ".join(valu.split()).rstrip(",").strip()
    if not valu or REDACTED_RE.search(valu):
        return None
    return valu


def phone(valu: str | None) -> str | None:
    """Clean a phone number (ex. RPSL's ``tel:+1-...``)."""

    valu = clean(valu)
    if valu and valu.lower().startswith("tel:"):
        valu = valu[4:].strip() or None
    return valu


def joinParts(parts: Iterable[str | None]) -> str | None:
    """Join address parts with ", ", skipping empty (and redacted) parts."""

    return ", ".join(p for p in map(clean, parts) if p) or None


def emailOf(valu: str | None) -> str | None:
    """The (lowercase) email address in a value, or None."""

    if not valu or REDACTED_RE.search(valu):
        return None
    match = EMAIL_RE.search(valu)
    return match.group(0).lower().strip(".") if match else None


def uniq(valus: Iterable) -> list:
    """Unique, truthy values, in their original order."""

    seen = []
    for valu in valus:
        if valu and valu not in seen:
            seen.append(valu)
    return seen


# ---- Domain whois ----

LINE_RE = re.compile(
    r"^(?P<indent>\s*)(?P<key>[A-Za-z][\w /.()&'-]{0,60}?)\s*:(?:\s+(?P<valu>.*?))?\s*$"
)
"""A ``Key: Value`` line. The value is optional (section headers, empty fields)."""

LOOKUP_RES = (
    re.compile(r">>>\s*Last update of whois database:\s*(?P<time>[^<]+?)\s*<<<", re.IGNORECASE),
    re.compile(r"WHOIS lookup made at\s+(?P<time>.+?)\s*$", re.IGNORECASE | re.MULTILINE),
)
"""When the registry answered the query (bgp.he.net caches whois records)."""

DOMAIN_KEYS = {
    "created": (
        "creation date",
        "created",
        "created on",
        "created date",
        "registered on",
        "registered",
        "registration date",
        "registration time",
        "domain registration date",
        "domain record activated",
    ),
    "updated": (
        "updated date",
        "updated",
        "last updated",
        "last updated on",
        "last update",
        "changed",
        "last modified",
        "last-modified",
        "modified",
        "domain record last updated",
    ),
    "expires": (
        "registry expiry date",
        "registrar registration expiration date",
        "expiry date",
        "expiration date",
        "expires",
        "expires on",
        "expire date",
        "paid-till",
        "renewal date",
        "domain expiration date",
    ),
    "registrar": ("registrar", "sponsoring registrar", "registrar name", "registrar organization"),
    "registrar:url": ("registrar url", "registrar website", "url"),
    "registrar:whois": ("registrar whois server", "whois server", "whois"),
    "registrar:ianaid": ("registrar iana id",),
    "registrar:email": ("registrar abuse contact email",),
    "registrar:phone": ("registrar abuse contact phone",),
    "status": ("domain status", "status", "registration status", "state"),
    "ns": ("name server", "name servers", "nserver", "nameserver", "nameservers", "ns"),
    "dnssec": ("dnssec",),
}

CONTACT_TYPES = {
    "registrant": "registrant",
    "owner": "registrant",
    "holder": "registrant",
    "admin": "admin",
    "administrative": "admin",
    "administrative contact": "admin",
    "tech": "tech",
    "technical": "tech",
    "technical contact": "tech",
    "billing": "billing",
}
"""Contact key prefixes (ex. ``Registrant Name``), mapped to inet:whois:contact:type values."""

CONTACT_FIELDS = {
    "id": "id",
    "name": "name",
    "organization": "orgname",
    "organisation": "orgname",
    "org": "orgname",
    "street": "address",
    "address": "address",
    "city": "city",
    "state/province": "state",
    "state": "state",
    "province": "state",
    "postal code": "postalcode",
    "country": "country",
    "country code": "country",
    "phone": "phone",
    "fax": "fax",
    "email": "email",
    "e-mail": "email",
}
"""Contact key suffixes, mapped to inet:whois:contact props."""


def _domainPairs(text: str) -> list[tuple[str, str]]:
    """Every (lowercase key, value) in a domain whois record, including sectioned values."""

    pairs: list[tuple[str, str]] = []
    section = None
    sindent = -1

    for raw in text.split("\n"):
        if not raw.strip():
            continue
        if raw.lstrip().startswith(("%", "#", ">>>", "--")):
            section = None
            continue
        indent = len(raw) - len(raw.lstrip())
        match = LINE_RE.match(raw)

        if section is not None and indent > sindent:
            # A line inside a section. It can still be a "Key: Value" of its own.
            if match and match.group("valu") and not match.group("valu").startswith("//"):
                pairs.append((_key(match.group("key")), match.group("valu")))
            else:
                pairs.append((section, raw.strip()))
            continue

        section = None
        if not match:
            continue
        key = _key(match.group("key"))
        valu = match.group("valu")
        if valu:
            pairs.append((key, valu))
        else:
            # A section header, ex. Nominet's "Name servers:".
            section = key
            sindent = indent

    return pairs


def _key(key: str) -> str:
    return " ".join(key.lower().split())


def _contactKey(key: str) -> tuple[str, str] | None:
    """Split a contact key (ex. ``registrant organization``) into (type, field), or None."""

    key = key.removeprefix("registry ")
    for prefix, ctype in CONTACT_TYPES.items():
        if not key.startswith(prefix + " "):
            continue
        rest = key[len(prefix) + 1 :]
        if rest.endswith(" ext"):
            return None
        field = CONTACT_FIELDS.get(rest)
        if field:
            return ctype, field
    return None


def parseDomain(fqdn: str, text: str) -> dict:
    """Parse a domain whois record.

    Returns a dict of the record's ``created``/``updated``/``expires`` times (epoch millis),
    ``registrar`` info, ``registrant`` (the registrant organization or name), ``status``,
    ``nameservers``, ``dnssec``, ``contacts`` (registrant/admin/tech/billing), ``emails``, and
    ``asof``: when the registry answered the query, if the record says.
    """

    keymap = {alias: field for field, aliases in DOMAIN_KEYS.items() for alias in aliases}
    found: dict[str, list[str]] = {}
    contacts: dict[str, dict] = {}

    for key, valu in _domainPairs(text):
        ckey = _contactKey(key)
        if ckey:
            ctype, field = ckey
            contact = contacts.setdefault(ctype, {"type": ctype})
            if field == "address" and contact.get("address"):
                contact["address"] = joinParts((contact["address"], valu))
            elif field not in contact:
                contact[field] = valu.strip()
            continue
        field = keymap.get(key)
        if field:
            found.setdefault(field, []).append(valu.strip())

    def first(field: str) -> str | None:
        for valu in found.get(field, ()):
            if clean(valu):
                return clean(valu)
        return None

    def firstTime(field: str) -> int | None:
        for valu in found.get(field, ()):
            when = parseTime(valu)
            if when is not None:
                return when
        return None

    nameservers = []
    for valu in found.get("ns", ()):
        name = valu.split()[0].lower().rstrip(".") if valu.split() else ""
        if "." in name and not name.startswith("http"):
            nameservers.append(name)

    status = uniq(valu.split()[0] for valu in found.get("status", ()) if valu.split())

    # Nominet style registrar values are "Name [Tag = TAG]".
    registrar = first("registrar")
    if registrar:
        registrar = re.sub(r"\s*\[Tag\s*=\s*[^\]]*\]\s*$", "", registrar).strip() or None

    regurl = first("registrar:url")
    if regurl and not regurl.lower().startswith(("http://", "https://")):
        regurl = "http://" + regurl
    regwhois = first("registrar:whois")
    if regwhois:
        regwhois = regwhois.lower().removeprefix("whois://").strip("/") or None

    outcontacts = []
    for ctype in ("registrant", "admin", "tech", "billing"):
        contact = contacts.get(ctype)
        if contact is None:
            continue
        info = {"type": ctype}
        for field in ("id", "name", "orgname", "address", "city", "state", "postalcode"):
            info[field] = clean(contact.get(field))
        country = clean(contact.get("country"))
        info["country"] = country if country and len(country) == 2 else None
        info["phone"] = phone(contact.get("phone"))
        info["fax"] = phone(contact.get("fax"))
        info["email"] = emailOf(contact.get("email"))
        if any(valu for key, valu in info.items() if key != "type"):
            outcontacts.append(info)

    registrant = None
    for contact in outcontacts:
        if contact["type"] == "registrant":
            registrant = contact.get("orgname") or contact.get("name")

    asof = None
    for regx in LOOKUP_RES:
        match = regx.search(text)
        if match:
            asof = parseTime(match.group("time"))
            if asof is not None:
                break

    return {
        "fqdn": fqdn,
        "asof": asof,
        "created": firstTime("created"),
        "updated": firstTime("updated"),
        "expires": firstTime("expires"),
        "registrar": {
            "name": registrar,
            "url": regurl,
            "whois": regwhois,
            "ianaid": first("registrar:ianaid"),
            "email": emailOf(first("registrar:email")),
            "phone": phone(first("registrar:phone")),
        },
        "registrant": registrant,
        "status": status,
        "nameservers": uniq(nameservers),
        "dnssec": first("dnssec"),
        "contacts": outcontacts,
        "emails": uniq(contact["email"] for contact in outcontacts),
    }


# ---- ASN whois ----

RPSL_RE = re.compile(r"^(?P<key>[A-Za-z][\w-]*):\s?(?P<valu>.*)$")
"""An RPSL (and ARIN) attribute line. Keys never have spaces."""

ARIN_CONTACTS = {
    "OrgAbuse": "abuse",
    "OrgTech": "tech",
    "OrgNOC": "noc",
    "OrgRouting": "routing",
    "OrgDNS": "dns",
    "OrgAdmin": "admin",
    "RAbuse": "abuse",
    "RTech": "tech",
    "RNOC": "noc",
    "RRouting": "routing",
}
"""ARIN's POC key prefixes (ex. ``OrgAbuseEmail``), mapped to contact types."""

RPSL_CONTACTS = (("abuse-c", "abuse"), ("admin-c", "admin"), ("tech-c", "tech"))
"""The RPSL contact attributes, and the contact type they're for."""


def blocks(text: str) -> list[list[tuple[str, str]]]:
    """Split whois text into its objects, each a list of (key, value) attributes.

    Comment lines (``%``/``#``) are dropped, and continuation lines are appended to the
    attribute before them.
    """

    objs: list[list[tuple[str, str]]] = []
    cur: list[tuple[str, str]] = []
    for line in text.split("\n"):
        if not line.strip():
            if cur:
                objs.append(cur)
                cur = []
            continue
        if line.lstrip().startswith(("%", "#")):
            continue
        if line[0] in " \t+" and cur:
            key, valu = cur[-1]
            more = line.lstrip(" \t+").strip()
            cur[-1] = (key, f"{valu} {more}".strip() if more else valu)
            continue
        match = RPSL_RE.match(line)
        if match:
            # RPSL values can have trailing comments, ex. "source: AFRINIC # Filtered".
            valu = match.group("valu").split(" # ")[0].strip()
            cur.append((match.group("key"), valu))
    if cur:
        objs.append(cur)
    return objs


def _get(obj: list[tuple[str, str]], key: str) -> str | None:
    for k, v in obj:
        if k.lower() == key.lower() and v:
            return v
    return None


def _getall(obj: list[tuple[str, str]], key: str) -> list[str]:
    return [v for k, v in obj if k.lower() == key.lower() and v]


def _asnRange(valu: str) -> tuple[int, int] | None:
    """Parse ``15169``, ``AS15169``, or ``8068 - 8075`` into an inclusive (min, max)."""

    nums = [int(n) for n in re.findall(r"\d+", valu or "")]
    if len(nums) == 1:
        return nums[0], nums[0]
    if len(nums) == 2:
        return min(nums), max(nums)
    return None


def _emptyAsn(asn: int) -> dict:
    return {
        "asn": asn,
        "registry": None,
        "name": None,
        "handle": None,
        "desc": None,
        "orgname": None,
        "orgid": None,
        "country": None,
        "address": None,
        "created": None,
        "updated": None,
        "status": None,
        "contacts": [],
        "emails": [],
    }


def _country(valu: str | None) -> str | None:
    valu = clean(valu)
    return valu.upper() if valu and len(valu) == 2 and valu.isalpha() else None


def _arin(asn: int, objs: list[list[tuple[str, str]]]) -> dict:
    retn = _emptyAsn(asn)
    retn["registry"] = "arin"

    asobj = None
    for obj in objs:
        rng = _asnRange(_get(obj, "ASNumber") or "")
        if rng and rng[0] <= asn <= rng[1]:
            asobj = obj
            break
    if asobj is None:
        asobj = next((obj for obj in objs if _get(obj, "ASNumber")), [])

    retn["name"] = clean(_get(asobj, "ASName"))
    retn["handle"] = clean(_get(asobj, "ASHandle"))
    retn["created"] = parseTime(_get(asobj, "RegDate"))
    retn["updated"] = parseTime(_get(asobj, "Updated"))
    orgobj = next((obj for obj in objs if _get(obj, "OrgName")), [])

    # The comments (often how to report abuse) are on the ASN, the org, or both.
    comments = [c for c in _getall(asobj, "Comment") + _getall(orgobj, "Comment") if c.strip()]
    retn["desc"] = "\n".join(comments) or None
    retn["orgname"] = clean(_get(orgobj, "OrgName"))
    retn["orgid"] = clean(_get(orgobj, "OrgId"))
    retn["country"] = _country(_get(orgobj, "Country"))
    retn["address"] = joinParts(
        _getall(orgobj, "Address")
        + [_get(orgobj, "City"), _get(orgobj, "StateProv"), _get(orgobj, "PostalCode")]
    )
    if retn["created"] is None:
        retn["created"] = parseTime(_get(orgobj, "RegDate"))

    contacts = {}
    for obj in objs:
        for key, valu in obj:
            for prefix, ctype in ARIN_CONTACTS.items():
                if not key.startswith(prefix):
                    continue
                field = key[len(prefix) :]
                if field not in ("Handle", "Name", "Phone", "Email"):
                    continue
                contact = contacts.setdefault(prefix, {"type": ctype})
                contact.setdefault(field.lower(), valu.strip())
    retn["contacts"] = _contacts(contacts.values())
    retn["emails"] = _emails(retn["contacts"], comments)
    return retn


def _rpsl(asn: int, objs: list[list[tuple[str, str]]]) -> dict:
    retn = _emptyAsn(asn)

    autnum = None
    for obj in objs:
        if obj[0][0].lower() != "aut-num":
            continue
        rng = _asnRange(obj[0][1])
        if rng and rng[0] <= asn <= rng[1]:
            autnum = obj
            break
    if autnum is None:
        return retn

    source = clean(_get(autnum, "source"))
    if source:
        retn["registry"] = source.split()[0].lower()
    elif _get(autnum, "owner"):
        retn["registry"] = "lacnic"

    descr = _getall(autnum, "descr")
    retn["name"] = clean(_get(autnum, "as-name"))
    retn["handle"] = f"AS{asn}"
    retn["desc"] = "\n".join(descr) or None
    retn["status"] = clean(_get(autnum, "status"))
    retn["created"] = parseTime(_get(autnum, "created"))
    retn["updated"] = parseTime(_get(autnum, "last-modified") or _get(autnum, "changed"))
    retn["country"] = _country(_get(autnum, "country"))

    # Index the other objects by their primary key (organisation, nic-hdl, irt).
    index: dict[str, list[tuple[str, str]]] = {}
    for obj in objs:
        if obj is autnum:
            continue
        for key in ("organisation", "nic-hdl", "irt"):
            valu = _get(obj, key)
            if valu:
                index.setdefault(valu.upper(), obj)

    orgid = clean(_get(autnum, "org") or _get(autnum, "ownerid"))
    orgobj = index.get(orgid.upper(), []) if orgid else []
    retn["orgid"] = orgid
    # LACNIC puts the owner in the aut-num, the other RIRs in an organisation object. Without
    # either, the first descr is the best name there is.
    retn["orgname"] = clean(
        _get(orgobj, "org-name") or _get(autnum, "owner") or (descr[0] if descr else None)
    )
    if retn["country"] is None:
        retn["country"] = _country(_get(orgobj, "country"))
    retn["address"] = joinParts(_getall(orgobj, "address") or _getall(autnum, "address"))

    contacts = []
    for attr, ctype in RPSL_CONTACTS:
        for handle in _getall(autnum, attr) + _getall(orgobj, attr):
            obj = index.get(handle.upper(), [])
            contacts.append(
                {
                    "type": ctype,
                    "handle": handle,
                    "name": _get(obj, "role") or _get(obj, "person"),
                    "email": _get(obj, "abuse-mailbox") or _get(obj, "e-mail"),
                    "phone": _get(obj, "phone"),
                }
            )
    irt = _get(autnum, "mnt-irt")
    if irt and irt.upper() in index:
        obj = index[irt.upper()]
        contacts.append(
            {
                "type": "abuse",
                "handle": irt,
                "name": irt,
                "email": _get(obj, "abuse-mailbox") or _get(obj, "e-mail"),
                "phone": _get(obj, "phone"),
            }
        )

    retn["contacts"] = _contacts(contacts)
    retn["emails"] = _emails(retn["contacts"], descr + _getall(autnum, "remarks"))
    return retn


def _contacts(contacts: Iterable[dict]) -> list[dict]:
    """Clean and deduplicate ASN contacts."""

    out = []
    for contact in contacts:
        info = {
            "type": contact["type"],
            "handle": clean(contact.get("handle")),
            "name": clean(contact.get("name")),
            "email": emailOf(contact.get("email")),
            "phone": phone(contact.get("phone")),
        }
        if (info["handle"] or info["email"]) and info not in out:
            out.append(info)
    return out


def _emails(contacts: list[dict], texts: Iterable[str]) -> list[str]:
    """Every email in the contacts, then any mentioned in the record's free text."""

    found = [c["email"] for c in contacts]
    for text in texts:
        found.extend(m.group(0).lower().strip(".") for m in EMAIL_RE.finditer(text or ""))
    return uniq(found)


def parseAsn(asn: int, text: str) -> dict:
    """Parse an ASN whois record (ARIN or RPSL).

    Returns a dict of the ``registry``, the AS ``name`` (ex. GOOGLE) and ``handle``, its
    ``desc``, the organization's ``orgname``/``orgid``/``country``/``address``, the record's
    ``created``/``updated`` times (epoch millis), ``status``, ``contacts``, and ``emails``.
    """

    objs = blocks(text)
    if any(_get(obj, "ASNumber") for obj in objs):
        return _arin(asn, objs)
    return _rpsl(asn, objs)

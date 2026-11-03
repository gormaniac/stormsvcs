"""Parse the domain RDAP (RFC 9083) records bgp.he.net returns.

``/rdap/dns/<domain>`` returns ``[<registry record>, [<registrar records>] or null]``: the TLD
registry's RDAP response, and the responses from the "related" links it points to (the
registrar's own RDAP server, which usually has the registrant and other contacts).

``parseDomain`` reads both into the same dict ``whois.parseDomain`` makes from whois text, so
either can be modeled the same way. The registry is authoritative for the domain's dates,
status, and nameservers, the registrar's record fills anything the registry leaves out, and
its contacts are preferred.
"""

import re
from collections.abc import Iterable, Mapping
from typing import Any

from . import whois

ROLES = {
    "registrant": "registrant",
    "administrative": "admin",
    "technical": "tech",
    "billing": "billing",
}
"""RDAP entity roles, mapped to inet:whois:contact:type values (the registrar is separate)."""

EVENTS = {
    "created": ("registration",),
    "updated": ("last changed",),
    "expires": ("expiration", "registrar expiration"),
    "asof": ("last update of rdap database",),
}
"""The RDAP event actions for each time, in order of preference."""


class BadRdap(ValueError):
    """An RDAP response isn't a domain record."""


def records(payload: Any) -> tuple[dict, list[dict]]:
    """Split a bgp.he.net RDAP payload into (registry record, registrar records).

    Raises ``BadRdap`` if there's no domain record in it.
    """

    related: list[dict] = []
    primary = payload
    if isinstance(payload, list):
        primary = payload[0] if payload else None
        if len(payload) > 1 and isinstance(payload[1], list):
            related = [rec for rec in payload[1] if isinstance(rec, Mapping)]
    if not isinstance(primary, Mapping) or primary.get("objectClassName", "domain") != "domain":
        raise BadRdap("The RDAP response has no domain record.")
    related = [rec for rec in related if rec.get("objectClassName", "domain") == "domain"]
    return dict(primary), [dict(rec) for rec in related]


# ---- jCard (RFC 7095) ----


def _flat(valu: Any) -> list[str]:
    """Every non-empty string in a (nested) jCard value."""

    if isinstance(valu, str):
        return [valu] if valu.strip() else []
    if isinstance(valu, list):
        return [s for item in valu for s in _flat(item)]
    return []


def vcard(entity: Mapping) -> dict[str, list[tuple[dict, Any]]]:
    """An entity's jCard properties, as ``{name: [(params, value)]}``."""

    props: dict[str, list[tuple[dict, Any]]] = {}
    card = entity.get("vcardArray")
    if not isinstance(card, list) or len(card) < 2 or not isinstance(card[1], list):
        return props
    for prop in card[1]:
        if not isinstance(prop, list) or len(prop) < 4 or not isinstance(prop[0], str):
            continue
        params = prop[1] if isinstance(prop[1], Mapping) else {}
        valu = prop[3] if len(prop) == 4 else prop[3:]
        props.setdefault(prop[0].lower(), []).append((dict(params), valu))
    return props


def _text(props: dict, name: str) -> str | None:
    for _, valu in props.get(name, ()):
        text = whois.clean(" ".join(_flat(valu)))
        if text:
            return text
    return None


def _types(params: Mapping) -> set[str]:
    kinds = params.get("type") or ()
    if isinstance(kinds, str):
        kinds = [kinds]
    return {str(k).lower() for k in kinds}


def _tel(props: dict, kind: str) -> str | None:
    """The first ``voice`` (or untyped) or ``fax`` phone number."""

    for params, valu in props.get("tel", ()):
        types = _types(params)
        if (kind == "fax") != ("fax" in types):
            continue
        phone = whois.phone(" ".join(_flat(valu)))
        if phone:
            return phone
    return None


def _email(props: dict) -> str | None:
    for _, valu in props.get("email", ()):
        email = whois.emailOf(" ".join(_flat(valu)))
        if email:
            return email
    return None


def _adr(props: dict) -> dict:
    """The address parts of an entity's first ``adr``."""

    out = {"address": None, "city": None, "state": None, "postalcode": None, "country": None}
    for params, valu in props.get("adr", ()):
        parts = valu if isinstance(valu, list) else []
        parts = (parts + [""] * 7)[:7]
        # (pobox, ext, street, locality, region, code, country)
        street = whois.joinParts(_flat(parts[0]) + _flat(parts[1]) + _flat(parts[2]))
        label = params.get("label")
        out["address"] = street or (whois.clean(label) if isinstance(label, str) else None)
        out["city"] = whois.clean(" ".join(_flat(parts[3])))
        out["state"] = whois.clean(" ".join(_flat(parts[4])))
        out["postalcode"] = whois.clean(" ".join(_flat(parts[5])))
        country = params.get("cc") or " ".join(_flat(parts[6]))
        country = whois.clean(str(country)) if country else None
        out["country"] = country.upper() if country and len(country) == 2 else None
        break
    return out


# ---- Entities ----


def _roles(entity: Mapping) -> set[str]:
    roles = entity.get("roles") or ()
    return {str(r).lower() for r in roles} if isinstance(roles, list) else set()


def _entities(rec: Mapping) -> list[dict]:
    return [dict(e) for e in rec.get("entities") or () if isinstance(e, Mapping)]


def _url(props: dict) -> str | None:
    url = _text(props, "url")
    if url and not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    return url


def contact(entity: Mapping, ctype: str) -> dict | None:
    """An entity as a contact (see ``whois.parseDomain``), or None if everything is redacted."""

    props = vcard(entity)
    handle = entity.get("handle")
    info = {
        "type": ctype,
        "id": whois.clean(handle) if isinstance(handle, str) else None,
        "name": _text(props, "fn"),
        "orgname": _text(props, "org"),
        **_adr(props),
        "phone": _tel(props, "voice"),
        "fax": _tel(props, "fax"),
        "email": _email(props),
    }
    if any(valu for key, valu in info.items() if key != "type"):
        return info
    return None


def registrar(primary: Mapping, related: list[Mapping]) -> dict:
    """The registrar's name, IANA ID, URL, whois server, and abuse email/phone.

    The registry's record is preferred, except for the whois server: the registrar's record
    is the registrar's own server's answer, so its ``port43`` is the registrar's.
    """

    out = {"name": None, "url": None, "whois": None, "ianaid": None, "email": None, "phone": None}

    def fill(key: str, valu: Any):
        if out[key] is None and valu:
            out[key] = valu

    for rec in [*related, primary]:
        port43 = rec.get("port43")
        if isinstance(port43, str):
            fill("whois", whois.clean(port43.lower()))

    for rec in [primary, *related]:
        for entity in _entities(rec):
            if "registrar" not in _roles(entity):
                continue
            props = vcard(entity)
            fill("name", _text(props, "fn") or _text(props, "org"))
            fill("url", _url(props))
            for pid in entity.get("publicIds") or ():
                if isinstance(pid, Mapping) and "iana" in str(pid.get("type", "")).lower():
                    fill("ianaid", whois.clean(str(pid.get("identifier") or "")))
            for sub in _entities(entity):
                if "abuse" in _roles(sub):
                    subprops = vcard(sub)
                    fill("email", _email(subprops))
                    fill("phone", _tel(subprops, "voice"))
    return out


# ---- Domains ----


def _time(recs: Iterable[Mapping], actions: Iterable[str]) -> int | None:
    """The time of the first event with one of the actions, by action then record."""

    for action in actions:
        for rec in recs:
            for event in rec.get("events") or ():
                if not isinstance(event, Mapping):
                    continue
                if str(event.get("eventAction", "")).lower() != action:
                    continue
                when = whois.parseTime(str(event.get("eventDate") or ""))
                if when is not None:
                    return when
    return None


def eppStatus(valu: str) -> str:
    """Convert an RDAP status (ex. ``client delete prohibited``) to its EPP name."""

    words = re.split(r"[\s_-]+", valu.strip())
    return words[0].lower() + "".join(w.capitalize() for w in words[1:])


def _dnssec(recs: list[Mapping]) -> str | None:
    for rec in recs:
        sec = rec.get("secureDNS")
        if isinstance(sec, Mapping) and isinstance(sec.get("delegationSigned"), bool):
            return "signedDelegation" if sec["delegationSigned"] else "unsigned"
    return None


def parseDomain(fqdn: str, payload: Any) -> dict:
    """Parse bgp.he.net's RDAP payload for a domain into a ``whois.parseDomain`` style dict.

    Raises ``BadRdap`` if the payload has no domain record.
    """

    primary, related = records(payload)
    recs = [primary, *related]

    nameservers = []
    for rec in recs:
        for ns in rec.get("nameservers") or ():
            name = ns.get("ldhName") if isinstance(ns, Mapping) else None
            if isinstance(name, str) and name.strip():
                nameservers.append(name.strip().lower().rstrip("."))
        if nameservers:
            break

    status = []
    for rec in recs:
        status = [eppStatus(s) for s in rec.get("status") or () if isinstance(s, str) and s.strip()]
        if status:
            break

    # The registrar's contacts first, they're usually the complete ones.
    contacts: dict[str, dict] = {}
    for rec in [*related, primary]:
        for entity in _entities(rec):
            for role in _roles(entity):
                ctype = ROLES.get(role)
                if ctype and ctype not in contacts:
                    info = contact(entity, ctype)
                    if info:
                        contacts[ctype] = info
    outcontacts = [contacts[c] for c in ("registrant", "admin", "tech", "billing") if c in contacts]

    registrant = None
    if "registrant" in contacts:
        registrant = contacts["registrant"]["orgname"] or contacts["registrant"]["name"]

    return {
        "fqdn": fqdn,
        "asof": _time([primary], EVENTS["asof"]),
        "created": _time(recs, EVENTS["created"]),
        "updated": _time(recs, EVENTS["updated"]),
        "expires": _time(recs, EVENTS["expires"]),
        "registrar": registrar(primary, related),
        "registrant": registrant,
        "status": status,
        "nameservers": whois.uniq(nameservers),
        "dnssec": _dnssec(recs),
        "contacts": outcontacts,
        "emails": whois.uniq(c["email"] for c in outcontacts),
    }

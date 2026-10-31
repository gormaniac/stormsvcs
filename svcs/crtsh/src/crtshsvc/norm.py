"""Parse X.509 certificates from crt.sh into plain dicts for Storm.

crt.sh stores every certificate as DER. Rather than relying on the database's
X.509 functions for every field, the service pulls the DER and parses all of a
certificate's details here, so every certificate a lookup, search, or pivot
returns has the same complete set of details.

The dicts returned here only hold Telepath (msgpack) safe values: str, int,
bool, None, lists, and dicts. Bytes are hex encoded and times are epoch millis.
"""

import base64
import binascii
import datetime
import hashlib
import ipaddress
import json
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID


CRTSH_URL = "https://crt.sh/"
"""The crt.sh web UI, used to build a link to each certificate."""

PRECERT_POISON_OID = "1.3.6.1.4.1.11129.2.4.3"
"""The CT precertificate poison extension (RFC 6962), only present in precertificates."""

REVOCATION_REASONS = {
    0: "unspecified",
    1: "keyCompromise",
    2: "cACompromise",
    3: "affiliationChanged",
    4: "superseded",
    5: "cessationOfOperation",
    6: "certificateHold",
    8: "removeFromCRL",
    9: "privilegeWithdrawn",
    10: "aACompromise",
}
"""CRL reason codes (RFC 5280) to their names."""

# Short names for the subject/issuer attributes, keyed by OID. Anything else is keyed by its OID.
NAME_ATTRS = {
    NameOID.COMMON_NAME.dotted_string: "cn",
    NameOID.ORGANIZATION_NAME.dotted_string: "o",
    NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string: "ou",
    NameOID.COUNTRY_NAME.dotted_string: "c",
    NameOID.STATE_OR_PROVINCE_NAME.dotted_string: "st",
    NameOID.LOCALITY_NAME.dotted_string: "l",
    NameOID.STREET_ADDRESS.dotted_string: "street",
    NameOID.POSTAL_CODE.dotted_string: "postalcode",
    NameOID.EMAIL_ADDRESS.dotted_string: "email",
    NameOID.SERIAL_NUMBER.dotted_string: "serialnumber",
    NameOID.DOMAIN_COMPONENT.dotted_string: "dc",
    NameOID.BUSINESS_CATEGORY.dotted_string: "businesscategory",
    NameOID.JURISDICTION_COUNTRY_NAME.dotted_string: "jurisdiction:c",
    NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME.dotted_string: "jurisdiction:st",
    NameOID.JURISDICTION_LOCALITY_NAME.dotted_string: "jurisdiction:l",
    NameOID.ORGANIZATION_IDENTIFIER.dotted_string: "organizationidentifier",
    NameOID.GIVEN_NAME.dotted_string: "givenname",
    NameOID.SURNAME.dotted_string: "surname",
    NameOID.TITLE.dotted_string: "title",
}


def toMillis(valu: datetime.datetime | None) -> int | None:
    """Convert a datetime (naive ones are UTC) to epoch millis, Synapse's time format."""

    if valu is None:
        return None
    if valu.tzinfo is None:
        valu = valu.replace(tzinfo=datetime.timezone.utc)
    return int(valu.timestamp() * 1000)


def hexBytes(valu: bytes | None) -> str | None:
    """Lowercase hex encode bytes."""

    if valu is None:
        return None
    return binascii.hexlify(valu).decode()


def serialHex(serial: int) -> str:
    """Encode a serial number as the even length hex string crt.sh and Synapse use."""

    if serial < 0:
        # Invalid per RFC 5280 but they exist in CT logs, use the two's complement DER bytes.
        size = (serial.bit_length() + 8) // 8
        return hexBytes(serial.to_bytes(size, "big", signed=True))
    text = format(serial, "x")
    return text if len(text) % 2 == 0 else "0" + text


def serialBytes(serial: str | int) -> bytes:
    """Convert a hex string (or int) serial number to the DER content bytes crt.sh indexes."""

    if isinstance(serial, int):
        serial = serialHex(serial)
    serial = serial.strip().lower().replace(":", "").replace(" ", "")
    if serial.startswith("0x"):
        serial = serial[2:]
    if len(serial) % 2:
        serial = "0" + serial
    return binascii.unhexlify(serial)


def normHex(valu: str) -> str:
    """Normalize a hex string (fingerprint, key id, etc.) that may contain colons or spaces."""

    return valu.strip().lower().replace(":", "").replace(" ", "")


def _nameAttrs(name: x509.Name) -> dict[str, list[str]]:
    attrs: dict[str, list[str]] = {}
    for attr in name:
        key = NAME_ATTRS.get(attr.oid.dotted_string, attr.oid.dotted_string)
        valu = attr.value if isinstance(attr.value, str) else hexBytes(attr.value)
        attrs.setdefault(key, []).append(valu)
    return attrs


def _rfc4514(name: x509.Name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:  # pragma: no cover - malformed names in CT logs
        return str(name)


def normName(name: x509.Name) -> dict:
    """Normalize an X.509 Name (subject or issuer)."""

    return {
        "dn": _rfc4514(name),
        "attrs": _nameAttrs(name),
        "sha1": hashlib.sha1(name.public_bytes()).hexdigest(),
    }


def _oidName(oid: x509.ObjectIdentifier) -> str:
    name = getattr(oid, "_name", None)
    return name if name and name != "Unknown OID" else oid.dotted_string


def _generalName(gname: x509.GeneralName) -> tuple[str, str] | None:
    """Convert a GeneralName to a (type, value) tuple matching crypto:x509:san."""

    if isinstance(gname, x509.DNSName):
        return ("dns", gname.value)
    if isinstance(gname, x509.RFC822Name):
        return ("email", gname.value)
    if isinstance(gname, x509.UniformResourceIdentifier):
        return ("uri", gname.value)
    if isinstance(gname, x509.IPAddress):
        return ("ip", str(gname.value))
    if isinstance(gname, x509.DirectoryName):
        return ("dirname", _rfc4514(gname.value))
    if isinstance(gname, x509.RegisteredID):
        return ("registeredid", gname.value.dotted_string)
    if isinstance(gname, x509.OtherName):
        return ("othername", f"{gname.type_id.dotted_string}:{hexBytes(gname.value)}")
    return None  # pragma: no cover


def normPublicKey(cert: x509.Certificate) -> dict:
    """Normalize a certificate's public key, including its SPKI hashes for pivoting."""

    retn: dict[str, Any] = {"algo": None, "size": None}

    try:
        key = cert.public_key()
    except Exception:
        # A key type cryptography doesn't support, only the certificate's hashes are known.
        return retn

    spki = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    if isinstance(key, rsa.RSAPublicKey):
        nums = key.public_numbers()
        retn.update(algo="rsa", size=key.key_size, rsa={"mod": format(nums.n, "x"), "exp": nums.e})
    elif isinstance(key, ec.EllipticCurvePublicKey):
        retn.update(algo="ec", size=key.key_size, curve=key.curve.name)
    elif isinstance(key, dsa.DSAPublicKey):
        retn.update(algo="dsa", size=key.key_size)
    elif isinstance(key, ed25519.Ed25519PublicKey):
        retn.update(algo="ed25519", size=256)
    elif isinstance(key, ed448.Ed448PublicKey):
        retn.update(algo="ed448", size=456)

    retn["spki"] = hexBytes(spki)
    retn["sha256"] = hashlib.sha256(spki).hexdigest()
    retn["sha1"] = hashlib.sha1(spki).hexdigest()
    return retn


def _extensions(cert: x509.Certificate) -> list:
    try:
        return list(cert.extensions)
    except Exception:
        # A malformed extension makes the whole list unparseable, details are best effort.
        return []


def normExtensions(cert: x509.Certificate) -> dict:
    """Pull every extension crt.sh users care about into a flat dict."""

    retn: dict[str, Any] = {
        "sans": [],
        "ca": None,
        "pathlen": None,
        "keyusage": [],
        "extkeyusage": [],
        "ski": None,
        "aki": None,
        "crls": [],
        "ocsp": [],
        "caissuers": [],
        "policies": [],
        "scts": [],
        "precert": False,
        "mustStaple": False,
        "extensions": [],
    }

    for ext in _extensions(cert):
        oid = ext.oid.dotted_string
        retn["extensions"].append({"oid": oid, "name": _oidName(ext.oid), "critical": ext.critical})

        valu = ext.value
        if oid == PRECERT_POISON_OID:
            retn["precert"] = True
        elif ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            retn["sans"] = [san for san in map(_generalName, valu) if san]
        elif ext.oid == ExtensionOID.BASIC_CONSTRAINTS:
            retn["ca"] = valu.ca
            retn["pathlen"] = valu.path_length
        elif ext.oid == ExtensionOID.KEY_USAGE:
            retn["keyusage"] = _keyUsage(valu)
        elif ext.oid == ExtensionOID.EXTENDED_KEY_USAGE:
            retn["extkeyusage"] = [{"oid": o.dotted_string, "name": _oidName(o)} for o in valu]
        elif ext.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
            retn["ski"] = hexBytes(valu.digest)
        elif ext.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
            retn["aki"] = hexBytes(valu.key_identifier)
        elif ext.oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
            for point in valu:
                for gname in point.full_name or ():
                    if isinstance(gname, x509.UniformResourceIdentifier):
                        retn["crls"].append(gname.value)
        elif ext.oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
            for desc in valu:
                if not isinstance(desc.access_location, x509.UniformResourceIdentifier):
                    continue
                if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                    retn["ocsp"].append(desc.access_location.value)
                elif desc.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                    retn["caissuers"].append(desc.access_location.value)
        elif ext.oid == ExtensionOID.CERTIFICATE_POLICIES:
            retn["policies"] = [p.policy_identifier.dotted_string for p in valu]
        elif ext.oid == ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS:
            retn["scts"] = [
                {
                    "logid": hexBytes(sct.log_id),
                    "time": toMillis(sct.timestamp),
                    "version": sct.version.name,
                }
                for sct in valu
            ]
        elif ext.oid == ExtensionOID.TLS_FEATURE:
            retn["mustStaple"] = any(f.value == 5 for f in valu)

    return retn


def _keyUsage(valu: x509.KeyUsage) -> list[str]:
    names = (
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
    )
    usage = [name for name in names if getattr(valu, name)]
    if valu.key_agreement:
        if valu.encipher_only:
            usage.append("encipher_only")
        if valu.decipher_only:
            usage.append("decipher_only")
    return usage


def identities(sans: list, subject: dict) -> dict:
    """Split SANs and the subject CN/email into the crypto:x509:cert:identities:* props.

    Wildcards (``*.example.com``) aren't valid inet:fqdn values, the base domain is used.
    """

    fqdns, emails, ipv4s, ipv6s, urls = set(), set(), set(), set(), set()

    def addFqdn(valu: str):
        valu = valu.strip().lower().rstrip(".")
        if valu.startswith("*."):
            valu = valu[2:]
        if valu and "." in valu and " " not in valu and "*" not in valu:
            fqdns.add(valu)

    def addIp(valu: str):
        try:
            addr = ipaddress.ip_address(valu)
        except ValueError:
            return False
        (ipv4s if addr.version == 4 else ipv6s).add(str(addr))
        return True

    for kind, valu in sans:
        if kind == "dns":
            addFqdn(valu)
        elif kind == "email":
            emails.add(valu.lower())
        elif kind == "ip":
            addIp(valu)
        elif kind == "uri":
            urls.add(valu)

    for valu in subject["attrs"].get("cn", ()):
        if "@" in valu:
            emails.add(valu.lower())
        elif not addIp(valu):
            addFqdn(valu)
    for valu in subject["attrs"].get("email", ()):
        emails.add(valu.lower())

    return {
        "fqdns": sorted(fqdns),
        "emails": sorted(emails),
        "ipv4s": sorted(ipv4s),
        "ipv6s": sorted(ipv6s),
        "urls": sorted(urls),
    }


def _validity(cert: x509.Certificate) -> tuple:
    try:
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:  # pragma: no cover - cryptography < 42
        return cert.not_valid_before, cert.not_valid_after


def _sigAlgo(cert: x509.Certificate) -> dict:
    oid = cert.signature_algorithm_oid
    hashalg = None
    try:
        if cert.signature_hash_algorithm is not None:
            hashalg = cert.signature_hash_algorithm.name
    except Exception:
        pass
    return {"oid": oid.dotted_string, "name": _oidName(oid), "hash": hashalg}


def parseCert(der: bytes) -> dict:
    """Parse a DER certificate into a dict of all of its details.

    Raises ``ValueError`` if the certificate can't be parsed at all.
    """

    cert = x509.load_der_x509_certificate(bytes(der))
    notbefore, notafter = _validity(cert)
    subject = normName(cert.subject)
    issuer = normName(cert.issuer)
    exts = normExtensions(cert)
    pubkey = normPublicKey(cert)

    selfsigned = subject["dn"] == issuer["dn"] and (
        exts["aki"] is None or exts["aki"] == exts["ski"]
    )

    return {
        "sha256": hashlib.sha256(der).hexdigest(),
        "sha1": hashlib.sha1(der).hexdigest(),
        "md5": hashlib.md5(der).hexdigest(),
        "version": cert.version.value,
        "serial": serialHex(cert.serial_number),
        "subject": subject,
        "issuer": issuer,
        "notbefore": toMillis(notbefore),
        "notafter": toMillis(notafter),
        "sigalgo": _sigAlgo(cert),
        "signature": hexBytes(cert.signature),
        "pubkey": pubkey,
        "selfsigned": selfsigned,
        "identities": identities(exts["sans"], subject),
        **exts,
        "pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
    }


def certDetails(row: dict) -> dict:
    """Build the full details of a certificate from a crt.sh certificate row.

    ``row`` has ``id``, ``issuer_ca_id``, and ``der``, plus the crt.sh metadata every
    certificate query returns (see ``crtshsvc.db._withMeta``): ``issuer_name``,
    ``caids``, and ``ctlog``/``revoked`` as JSON text. A certificate that can't be
    parsed still returns its hashes and crt.sh info, with an ``error`` explaining why.
    """

    der = bytes(row["der"])
    try:
        details = parseCert(der)
    except Exception as err:
        details = {
            "sha256": hashlib.sha256(der).hexdigest(),
            "sha1": hashlib.sha1(der).hexdigest(),
            "md5": hashlib.md5(der).hexdigest(),
            "pem": "-----BEGIN CERTIFICATE-----\n"
            + base64.encodebytes(der).decode()
            + "-----END CERTIFICATE-----\n",
            "error": f"Unable to parse certificate: {err}",
        }

    ctlog = [ctlogEntry(entry) for entry in json.loads(row.get("ctlog") or "[]")]
    times = [entry["time"] for entry in ctlog if entry["time"] is not None]
    revoked = row.get("revoked")
    details["crtsh"] = {
        "id": row["id"],
        "url": f"{CRTSH_URL}?id={row['id']}",
        "issuer": {"id": row["issuer_ca_id"], "name": row.get("issuer_name")},
        "ctlog": ctlog,
        "logged": [min(times), max(times)] if times else None,
        "revoked": revocation(json.loads(revoked)) if revoked else None,
        "caids": sorted(row.get("caids") or []),
    }
    return details


def certTime(details: dict) -> int:
    """A sort key for certificates, newest (by notBefore) first."""

    return -(details.get("notbefore") or 0)


def revocation(info: dict) -> dict:
    """Normalize a certificate's CRL revocation (``code``, ``time`` in epoch millis)."""

    code = info.get("code")
    return {
        "time": info.get("time"),
        "reason": REVOCATION_REASONS.get(code, None if code is None else str(code)),
        "code": code,
    }


def ctlogEntry(info: dict) -> dict:
    """Normalize one of a certificate's CT log entries."""

    return {
        "log": info.get("log"),
        "url": info.get("url"),
        "operator": info.get("operator"),
        "index": info.get("index"),
        "time": info.get("time"),
    }


def matches(details: dict, field: str, valu: str, mode: str = "contains") -> bool:
    """Whether a parsed certificate's ``field`` matches ``valu``.

    ``field`` is one of the search fields (see ``fieldValues``) and ``mode`` is
    ``exact``, ``contains``, or ``suffix`` (for domains: the domain or any subdomain).
    """

    valu = valu.strip().lower()
    for cand in fieldValues(details, field):
        cand = cand.lower()
        if mode == "exact" and cand == valu:
            return True
        if mode == "contains" and valu in cand:
            return True
        if mode == "suffix":
            base = cand[2:] if cand.startswith("*.") else cand
            if cand == valu or base == valu or base.endswith("." + valu):
                return True
    return False


def fieldValues(details: dict, field: str) -> list[str]:
    """The values of a search field in a parsed certificate."""

    subject = details.get("subject") or {"dn": "", "attrs": {}}
    sans = details.get("sans") or []
    attrs = subject["attrs"]

    if field == "dns":
        return [v for k, v in sans if k == "dns"] + attrs.get("cn", [])
    if field == "cn":
        return attrs.get("cn", [])
    if field == "org":
        return attrs.get("o", [])
    if field == "ou":
        return attrs.get("ou", [])
    if field == "email":
        return [v for k, v in sans if k == "email"] + attrs.get("email", [])
    if field == "ip":
        return [v for k, v in sans if k == "ip"]
    if field == "uri":
        return [v for k, v in sans if k == "uri"]
    if field == "subject":
        return [subject["dn"]]
    if field == "identity":
        vals = [v for _, v in sans] + [v for vs in attrs.values() for v in vs]
        return vals + [subject["dn"]]
    raise ValueError(f"Unknown search field: {field}")

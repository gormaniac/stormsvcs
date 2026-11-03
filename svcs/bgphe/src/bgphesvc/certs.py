"""Parse the certificates bgp.he.net returns into plain dicts for Storm.

Every certificate from ``/certs/api/domain`` carries its DER (base64), so the service parses
all of a certificate's details here instead of trusting the summary fields bgp.he.net sends
alongside it. Those summary fields are only used when the DER can't be parsed.

The dicts returned here only hold Telepath (msgpack) safe values: str, int, bool, None, lists,
and dicts. Bytes are hex encoded and times are epoch millis.
"""

import base64
import binascii
import datetime
import hashlib
import ipaddress
from collections.abc import Mapping
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

CERTS_URL = "https://bgp.he.net/certs/"
"""bgp.he.net's certificate search page, used to link to each certificate."""

PRECERT_POISON_OID = "1.3.6.1.4.1.11129.2.4.3"
"""The CT precertificate poison extension (RFC 6962), only present in precertificates."""

HE_TIME_FORMAT = "%b %d %H:%M:%S %Y %z"
"""The format of bgp.he.net's ``notbefore``/``notafter`` fields (ex. Dec 21 18:38:32 2026 +00:00)."""

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

# bgp.he.net's SAN types, mapped to the crypto:x509:san types.
HE_SAN_TYPES = {
    "dns": "dns",
    "email": "email",
    "rfc822": "email",
    "uri": "uri",
    "ip": "ip",
    "ipaddress": "ip",
}


def toMillis(valu: datetime.datetime | None) -> int | None:
    """Convert a datetime (naive ones are UTC) to epoch millis, Synapse's time format."""

    if valu is None:
        return None
    if valu.tzinfo is None:
        valu = valu.replace(tzinfo=datetime.UTC)
    return int(valu.timestamp() * 1000)


def hexBytes(valu: bytes | None) -> str | None:
    """Lowercase hex encode bytes."""

    if valu is None:
        return None
    return binascii.hexlify(valu).decode()


def serialHex(serial: int) -> str:
    """Encode a serial number as the even length, big endian hex string Synapse uses."""

    if serial < 0:
        # Invalid per RFC 5280 but they exist in CT logs, use the two's complement DER bytes.
        size = (serial.bit_length() + 8) // 8
        return hexBytes(serial.to_bytes(size, "big", signed=True))
    text = format(serial, "x")
    return text if len(text) % 2 == 0 else "0" + text


def heSerial(valu: Any) -> str | None:
    """Normalize a bgp.he.net serial (ex. ``00:a3:5b``) like a parsed one, or None."""

    if not isinstance(valu, str):
        return None
    text = valu.strip().lower().replace(":", "").replace(" ", "")
    try:
        return serialHex(int(text, 16))
    except ValueError:
        return None


def heTime(valu: Any) -> int | None:
    """Parse one of bgp.he.net's certificate times to epoch millis, or None."""

    if not isinstance(valu, str) or not valu.strip():
        return None
    text = valu.strip().replace(" UTC", " +00:00")
    try:
        # HE_TIME_FORMAT has a %z, the times are aware.
        return toMillis(datetime.datetime.strptime(text, HE_TIME_FORMAT))  # noqa: DTZ007
    except ValueError:
        return None


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

    return {"dn": _rfc4514(name), "attrs": _nameAttrs(name)}


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
        # A key type cryptography doesn't support.
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


def normExtensions(cert: x509.Certificate) -> dict:
    """Pull the commonly used extensions into a flat dict."""

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
        "precert": False,
    }

    for ext in _extensions(cert):
        valu = ext.value
        if ext.oid.dotted_string == PRECERT_POISON_OID:
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

    return retn


def identities(sans: list, cns: list[str]) -> dict:
    """Split SANs and the subject CNs into the crypto:x509:cert:identities:* props.

    Wildcards (``*.example.com``) aren't valid inet:fqdn values, the base domain is used.
    """

    fqdns, emails, ipv4s, ipv6s, urls = set(), set(), set(), set(), set()

    def addFqdn(valu: str):
        valu = valu.strip().lower().rstrip(".")
        valu = valu.removeprefix("*.")
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

    for valu in cns:
        if "@" in valu:
            emails.add(valu.lower())
        elif not addIp(valu):
            addFqdn(valu)

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
    except Exception:  # noqa: S110
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

    selfsigned = subject["dn"] == issuer["dn"] and (
        exts["aki"] is None or exts["aki"] == exts["ski"]
    )

    return {
        "sha256": hashlib.sha256(der).hexdigest(),
        "sha1": hashlib.sha1(der).hexdigest(),
        "md5": hashlib.md5(der).hexdigest(),
        "size": len(der),
        "version": cert.version.value,
        "serial": serialHex(cert.serial_number),
        "subject": subject,
        "issuer": issuer,
        "notbefore": toMillis(notbefore),
        "notafter": toMillis(notafter),
        "sigalgo": _sigAlgo(cert),
        "signature": hexBytes(cert.signature),
        "pubkey": normPublicKey(cert),
        "selfsigned": selfsigned,
        "identities": identities(exts["sans"], subject["attrs"].get("cn", [])),
        **exts,
    }


def _tlv(buf: bytes, off: int) -> tuple[int, int, int]:
    """Read the DER TLV at ``off``. Returns (tag, content offset, end offset)."""

    if off + 2 > len(buf):
        raise ValueError("Truncated DER")
    tag = buf[off]
    size = buf[off + 1]
    off += 2
    if size & 0x80:
        nbytes = size & 0x7F
        if not 0 < nbytes <= 4 or off + nbytes > len(buf):
            raise ValueError("Bad DER length")
        size = int.from_bytes(buf[off : off + nbytes], "big")
        off += nbytes
    end = off + size
    if end > len(buf):
        raise ValueError("Truncated DER")
    return tag, off, end


def _derLen(size: int) -> bytes:
    if size < 0x80:
        return bytes((size,))
    body = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(body),)) + body


def isTbs(der: bytes) -> bool:
    """Whether DER is a bare TBSCertificate (a CT precertificate entry) instead of a certificate.

    A Certificate's first element is the TBSCertificate SEQUENCE, a TBSCertificate's is its
    ``[0]`` version or its serial INTEGER.
    """

    try:
        tag, off, _ = _tlv(der, 0)
        if tag != 0x30:
            return False
        child, _, _ = _tlv(der, off)
    except ValueError:
        return False
    return child in (0xA0, 0x02)


def wrapTbs(tbs: bytes) -> bytes:
    """Wrap a TBSCertificate in a Certificate (with an empty signature) so it can be parsed.

    The signature algorithm is copied from the TBSCertificate's own ``signature`` field.
    """

    _, pos, end = _tlv(tbs, 0)
    tag, _, stop = _tlv(tbs, pos)
    if tag == 0xA0:
        # Skip the version, then the serial.
        pos = stop
        tag, _, stop = _tlv(tbs, pos)
    if tag != 0x02:
        raise ValueError("TBSCertificate has no serial")
    pos = stop
    tag, _, stop = _tlv(tbs, pos)
    if tag != 0x30 or stop > end:
        raise ValueError("TBSCertificate has no signature algorithm")
    sigalg = tbs[pos:stop]
    body = tbs[:end] + sigalg + b"\x03\x01\x00"
    return b"\x30" + _derLen(len(body)) + body


def parseTbs(tbs: bytes) -> dict:
    """Parse a bare TBSCertificate (see ``isTbs``) like a certificate.

    A TBSCertificate isn't the certificate that was issued (it has no signature), so it has
    no fingerprints. ``tbs`` is its SHA-256 instead, to identify it.
    """

    details = parseCert(wrapTbs(tbs))
    details.update(sha256=None, sha1=None, md5=None, size=None, signature=None)
    details["tbs"] = hashlib.sha256(tbs).hexdigest()
    return details


def heSans(item: Mapping) -> list[tuple[str, str]]:
    """The (type, value) SANs from bgp.he.net's ``subject_alternative_names`` summary."""

    sans = []
    for san in item.get("subject_alternative_names") or ():
        if not isinstance(san, Mapping):
            continue
        kind = HE_SAN_TYPES.get(str(san.get("type", "")).lower())
        valu = san.get("value")
        if kind and isinstance(valu, str) and valu:
            sans.append((kind, valu))
    return sans


def heMeta(item: Mapping) -> dict:
    """bgp.he.net's own metadata about a certificate (its IDs, CT log shards, and log time)."""

    certid = item.get("id")
    shardid = item.get("shard_id")
    shards = [s for s in (item.get("shards") or ()) if isinstance(s, str)]
    if not shards and isinstance(item.get("shard"), str):
        shards = [item["shard"]]

    url = None
    if certid is not None and shardid is not None:
        url = f"{CERTS_URL}#_SearchTab?cert_id={certid}&shard_id={shardid}"

    logged = item.get("timestamp")
    return {
        "id": certid,
        "shard": shardid,
        "shards": shards,
        "logged": logged if isinstance(logged, int) and logged > 0 else None,
        "precert": bool(item.get("pre_cert")),
        "url": url,
    }


def heFallback(item: Mapping, der: bytes, err: Exception) -> dict:
    """The details of a certificate whose DER can't be parsed, from bgp.he.net's summary."""

    sans = heSans(item)
    subject = item.get("subject") if isinstance(item.get("subject"), str) else None
    issuer = item.get("issuer") if isinstance(item.get("issuer"), str) else None
    cns = []
    for part in (subject or "").split(","):
        key, _, valu = part.strip().partition("=")
        if key.strip().upper() == "CN" and valu.strip():
            cns.append(valu.strip())

    if isTbs(der):
        hashes = {"sha256": None, "sha1": None, "md5": None, "size": None}
        hashes["tbs"] = hashlib.sha256(der).hexdigest()
    else:
        hashes = {
            "sha256": hashlib.sha256(der).hexdigest(),
            "sha1": hashlib.sha1(der).hexdigest(),
            "md5": hashlib.md5(der).hexdigest(),
            "size": len(der),
        }

    return {
        **hashes,
        "serial": heSerial(item.get("serial")),
        "subject": {"dn": subject, "attrs": {"cn": cns}},
        "issuer": {"dn": issuer, "attrs": {}},
        "notbefore": heTime(item.get("notbefore")),
        "notafter": heTime(item.get("notafter")),
        "sans": sans,
        "identities": identities(sans, cns),
        "precert": bool(item.get("pre_cert")),
        "error": f"Unable to parse certificate: {err}",
    }


def heCert(item: Mapping) -> dict | None:
    """Build the full details of a certificate from one of bgp.he.net's certificate entries.

    Returns None if the entry has no usable DER, since a certificate can't be identified
    without it. Precertificates are bare TBSCertificates (see ``isTbs``), with no fingerprints
    (``sha256`` etc. are None) and a ``tbs`` SHA-256 instead.
    """

    b64 = item.get("certificate_der")
    if not isinstance(b64, str) or not b64:
        return None
    try:
        der = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not der:
        return None

    try:
        details = parseTbs(der) if isTbs(der) else parseCert(der)
    except Exception as err:
        details = heFallback(item, der, err)

    details["he"] = heMeta(item)
    # Precertificates in CT logs have their poison extension removed.
    details["precert"] = bool(details.get("precert") or details["he"]["precert"])
    return details


def certKey(details: dict) -> str:
    """The value that identifies a certificate: its SHA-256, or a TBSCertificate's SHA-256."""

    return details.get("sha256") or f"tbs:{details['tbs']}"

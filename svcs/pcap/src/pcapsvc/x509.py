"""Parse the X.509 certificates seen in TLS handshakes into plain dicts for Storm.

The dicts only hold Telepath (msgpack) safe values: bytes are hex encoded and times are epoch
millis. Field names follow the ``crypto:x509:cert`` props they're modeled as.
"""

import datetime
import hashlib
import ipaddress
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa


def toMillis(valu: datetime.datetime) -> int:
    """Convert a datetime (naive ones are UTC) to epoch millis, Synapse's time format."""

    if valu.tzinfo is None:
        valu = valu.replace(tzinfo=datetime.UTC)
    return int(valu.timestamp() * 1000)


def serialHex(serial: int) -> str:
    """Encode a serial number as an even length hex string (two's complement if negative)."""

    if serial < 0:
        size = (serial.bit_length() + 8) // 8
        return serial.to_bytes(size, "big", signed=True).hex()
    text = format(serial, "x")
    return text if len(text) % 2 == 0 else "0" + text


def _dn(name: x509.Name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:  # pragma: no cover - malformed names
        return str(name)


def _san(gname: x509.GeneralName) -> tuple[str, str] | None:
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
        return ("dirname", _dn(gname.value))
    if isinstance(gname, x509.RegisteredID):
        return ("registeredid", gname.value.dotted_string)
    if isinstance(gname, x509.OtherName):
        return ("othername", f"{gname.type_id.dotted_string}:{gname.value.hex()}")
    return None  # pragma: no cover


def _pubkey(cert: x509.Certificate) -> dict:
    """The certificate's public key: its algorithm, SPKI, and SPKI hashes."""

    try:
        key = cert.public_key()
    except Exception:
        return {"algo": None}

    retn: dict[str, Any] = {"algo": None}
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

    spki = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    retn["spki"] = spki.hex()
    retn["sha256"] = hashlib.sha256(spki).hexdigest()
    retn["sha1"] = hashlib.sha1(spki).hexdigest()
    return retn


def identities(sans: list[tuple[str, str]], cert: x509.Certificate) -> dict:
    """Split the SANs and subject CN into the crypto:x509:cert:identities:* props.

    Wildcards (``*.example.com``) aren't valid inet:fqdn values, the base domain is used.
    """

    fqdns, emails, ipv4s, ipv6s, urls = set(), set(), set(), set(), set()

    def addFqdn(valu: str) -> None:
        valu = valu.strip().lower().rstrip(".").removeprefix("*.")
        if valu and "." in valu and " " not in valu and "*" not in valu:
            fqdns.add(valu)

    def addIp(valu: str) -> bool:
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

    for attr in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
        valu = str(attr.value)
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


def parseCert(der: bytes) -> dict:
    """Parse a DER certificate.

    A certificate that can't be parsed still has its hashes, plus an ``error`` saying why.
    """

    retn: dict[str, Any] = {
        "sha256": hashlib.sha256(der).hexdigest(),
        "sha1": hashlib.sha1(der).hexdigest(),
        "md5": hashlib.md5(der, usedforsecurity=False).hexdigest(),
        "size": len(der),
        "error": None,
    }

    try:
        cert = x509.load_der_x509_certificate(der)
        notbefore, notafter = cert.not_valid_before_utc, cert.not_valid_after_utc
        subject, issuer = _dn(cert.subject), _dn(cert.issuer)
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [san for gname in ext.value if (san := _san(gname)) is not None]
        except x509.ExtensionNotFound:
            sans = []

        ski = aki = None
        try:
            ski = cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value.digest.hex()
        except x509.ExtensionNotFound:
            pass
        try:
            akival = cert.extensions.get_extension_for_class(
                x509.AuthorityKeyIdentifier
            ).value.key_identifier
            aki = akival.hex() if akival else None
        except x509.ExtensionNotFound:
            pass

        retn.update(
            {
                "version": cert.version.value,
                "serial": serialHex(cert.serial_number),
                "subject": subject,
                "issuer": issuer,
                "notbefore": toMillis(notbefore),
                "notafter": toMillis(notafter),
                "algo": cert.signature_algorithm_oid.dotted_string,
                "signature": cert.signature.hex(),
                "selfsigned": subject == issuer and (aki is None or aki == ski),
                "sans": sans,
                "identities": identities(sans, cert),
                "pubkey": _pubkey(cert),
            }
        )
    except Exception as err:
        retn["error"] = f"Unable to parse the certificate: {err}"

    return retn

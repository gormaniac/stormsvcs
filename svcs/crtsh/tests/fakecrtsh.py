"""A fake crt.sh database for tests.

``FakeCrtshDb`` has every query method of ``crtshsvc.db.CrtshDb``, answered from
an in-memory PKI built with ``cryptography``. It emulates crt.sh's semantics
(full text search, identity name types, CA membership, partitions aside) closely
enough to exercise the service and Storm package end to end, and records every
call so tests can assert what the service asked for.

The PKI (crt.sh certificate IDs, issuing CA IDs)::

    1  Test Root R1 (RSA, self-signed)            CA 1
    3  Test Root E2 (EC, self-signed)              CA 3
    2  Test Issuing CA 1, signed by R1             CA 2
    4  Test Issuing CA 1, cross-signed by E2       CA 2  (same name and key as 2)
    9  www.vertex.link precertificate, by CA 2
    10 www.vertex.link certificate, by CA 2       (same serial as 9, embedded SCTs)
    11 old.vertex.link, by CA 2, revoked
    12 expired.vertex.link, by CA 2, expired      (Ed25519 key)
    13 an unparsable certificate, by CA 2
    14 shop.example.com, by CA 2
    15 www.vertex.link, by CA 2, expired          (a reissue of 10's key and subject)
"""

import contextlib
import datetime
import hashlib
import ipaddress
import json
import re
import struct
import unicodedata

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from crtshsvc import CrtshSvc
from crtshsvc.db import CrtshDbError, tsquery

NOW = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
DAY = datetime.timedelta(days=1)

CA_NAMES = {
    1: "C=US, O=Test Trust, CN=Test Root R1",
    2: "C=US, O=Test Trust, CN=Test Issuing CA 1",
    3: "C=US, O=Test Trust, CN=Test Root E2",
}

CRL_URL = "http://crl.test.example/issuing1.crl"
PRECERT_POISON = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3")

# The name types of crt.sh's certificate_and_identities view.
SAN_TYPES = {
    x509.DNSName: "san:dNSName",
    x509.RFC822Name: "san:rfc822Name",
    x509.IPAddress: "san:iPAddress",
    x509.UniformResourceIdentifier: "san:uniformResourceIdentifier",
}


def name(cn: str, org: str = "Test Trust", ou: str | None = None) -> x509.Name:
    attrs = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
    ]
    if ou:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(attrs)


def sctList(count: int = 2) -> bytes:
    """A DER OCTET STRING holding a TLS encoded SignedCertificateTimestampList (RFC 6962)."""

    scts = b""
    for i in range(count):
        sct = (
            b"\x00"
            + bytes([i + 1]) * 32
            + struct.pack(">Q", int(NOW.timestamp() * 1000))
            + b"\x00\x00"
            + b"\x04\x03"
            + struct.pack(">H", 4)
            + b"sig!"
        )
        scts += struct.pack(">H", len(sct)) + sct
    body = struct.pack(">H", len(scts)) + scts
    return (
        b"\x04" + bytes([0x81, len(body)]) + body
        if len(body) > 127
        else b"\x04" + bytes([len(body)]) + body
    )


def makeCert(
    subject: x509.Name,
    key,
    issuer: x509.Name,
    issuerKey,
    serial: int,
    notbefore: datetime.datetime,
    notafter: datetime.datetime,
    ca: bool = False,
    sans: list | None = None,
    precert: bool = False,
    scts: bool = False,
    full: bool = False,
    aki=None,
) -> bytes:
    """Build and sign a DER certificate."""

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(notbefore)
        .not_valid_after(notafter)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if aki is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(aki.public_key()), critical=False
        )
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    if precert:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(PRECERT_POISON, b"\x05\x00"), critical=True
        )
    if scts:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"), sctList()),
            critical=False,
        )
    if full:
        builder = (
            builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=True,
                    decipher_only=True,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.SERVER_AUTH,
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            [x509.UniformResourceIdentifier(CRL_URL)], None, None, None
                        ),
                        x509.DistributionPoint(
                            None,
                            x509.RelativeDistinguishedName(
                                [x509.NameAttribute(NameOID.COMMON_NAME, "crl")]
                            ),
                            None,
                            None,
                        ),
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            x509.AuthorityInformationAccessOID.OCSP,
                            x509.UniformResourceIdentifier("http://ocsp.test.example"),
                        ),
                        x509.AccessDescription(
                            x509.AuthorityInformationAccessOID.CA_ISSUERS,
                            x509.UniformResourceIdentifier("http://ca.test.example/i1.der"),
                        ),
                        x509.AccessDescription(
                            x509.AuthorityInformationAccessOID.CA_ISSUERS,
                            x509.DNSName("ca.test.example"),
                        ),
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.CertificatePolicies(
                    [
                        x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.2"), None),
                    ]
                ),
                critical=False,
            )
            .add_extension(x509.TLSFeature([x509.TLSFeatureType.status_request]), critical=False)
        )

    algo = None if isinstance(issuerKey, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(issuerKey, algo).public_bytes(serialization.Encoding.DER)


class Pki:
    """The test certificates (and their keys) as crt.sh rows."""

    def __init__(self):
        r1key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        e2key = ec.generate_private_key(ec.SECP256R1())
        i1key = ec.generate_private_key(ec.SECP256R1())
        leafkey = ec.generate_private_key(ec.SECP256R1())
        oldkey = ec.generate_private_key(ec.SECP256R1())
        expkey = ed25519.Ed25519PrivateKey.generate()
        shopkey = ec.generate_private_key(ec.SECP256R1())

        r1, e2, i1 = name("Test Root R1"), name("Test Root E2"), name("Test Issuing CA 1")
        www = name("www.vertex.link", org="The Vertex Project", ou="Engineering")
        leafsans = [
            x509.DNSName("www.vertex.link"),
            x509.DNSName("vertex.link"),
            x509.DNSName("*.vertex.link"),
            x509.RFC822Name("visi@vertex.link"),
            x509.IPAddress(ipaddress.ip_address("1.2.3.4")),
            x509.IPAddress(ipaddress.ip_address("2001:db8::1")),
            x509.UniformResourceIdentifier("https://vertex.link/"),
        ]
        self.leafSerial = 0x5A0B1C2D3E4F

        self.rows = [
            {
                "id": 1,
                "issuer_ca_id": 1,
                "der": makeCert(
                    r1, r1key, r1, r1key, 1, NOW - 3650 * DAY, NOW + 3650 * DAY, ca=True
                ),
            },
            {
                "id": 3,
                "issuer_ca_id": 3,
                "der": makeCert(
                    e2, e2key, e2, e2key, 3, NOW - 3000 * DAY, NOW + 3000 * DAY, ca=True
                ),
            },
            {
                "id": 2,
                "issuer_ca_id": 1,
                "der": makeCert(
                    i1, i1key, r1, r1key, 2, NOW - 1000 * DAY, NOW + 1000 * DAY, ca=True, aki=r1key
                ),
            },
            {
                "id": 4,
                "issuer_ca_id": 3,
                "der": makeCert(
                    i1, i1key, e2, e2key, 4, NOW - 500 * DAY, NOW + 500 * DAY, ca=True, aki=e2key
                ),
            },
            {
                "id": 9,
                "issuer_ca_id": 2,
                "der": makeCert(
                    www,
                    leafkey,
                    i1,
                    i1key,
                    self.leafSerial,
                    NOW - 10 * DAY,
                    NOW + 80 * DAY,
                    sans=leafsans,
                    precert=True,
                    full=True,
                    aki=i1key,
                ),
            },
            {
                "id": 10,
                "issuer_ca_id": 2,
                "der": makeCert(
                    www,
                    leafkey,
                    i1,
                    i1key,
                    self.leafSerial,
                    NOW - 10 * DAY,
                    NOW + 80 * DAY,
                    sans=leafsans,
                    scts=True,
                    full=True,
                    aki=i1key,
                ),
            },
            {
                "id": 11,
                "issuer_ca_id": 2,
                "der": makeCert(
                    name("old.vertex.link", org="The Vertex Project"),
                    oldkey,
                    i1,
                    i1key,
                    0xF00D,
                    NOW - 200 * DAY,
                    NOW + 100 * DAY,
                    sans=[x509.DNSName("old.vertex.link")],
                    full=True,
                    aki=i1key,
                ),
            },
            {
                "id": 12,
                "issuer_ca_id": 2,
                "der": makeCert(
                    name("expired.vertex.link", org="The Vertex Project"),
                    expkey,
                    i1,
                    i1key,
                    12,
                    NOW - 800 * DAY,
                    NOW - 400 * DAY,
                    sans=[x509.DNSName("expired.vertex.link")],
                    aki=i1key,
                ),
            },
            {"id": 13, "issuer_ca_id": 2, "der": b"not a certificate"},
            {
                "id": 14,
                "issuer_ca_id": 2,
                "der": makeCert(
                    name("shop.example.com", org="Example Inc"),
                    shopkey,
                    i1,
                    i1key,
                    14,
                    NOW - 5 * DAY,
                    NOW + 85 * DAY,
                    sans=[x509.DNSName("shop.example.com"), x509.DNSName("notvertex.link")],
                    aki=i1key,
                ),
            },
            {
                "id": 15,
                "issuer_ca_id": 2,
                "der": makeCert(
                    www,
                    leafkey,
                    i1,
                    i1key,
                    15,
                    NOW - 100 * DAY,
                    NOW - 10 * DAY,
                    sans=[x509.DNSName("www.vertex.link")],
                    aki=i1key,
                ),
            },
        ]
        self.cacerts = {1: 1, 3: 3, 2: 2, 4: 2}

        def ms(when):
            return int(when.timestamp() * 1000)

        # CT log entries and CRL revocations, as the certificate queries return them.
        self.ctlog = {
            9: [
                {
                    "log": "Test Log A",
                    "url": "https://a.ct.test.example",
                    "operator": "Test",
                    "index": 100,
                    "time": ms(NOW - 10 * DAY),
                }
            ],
            10: [
                {
                    "log": "Test Log A",
                    "url": "https://a.ct.test.example",
                    "operator": "Test",
                    "index": 200,
                    "time": ms(NOW - 9 * DAY),
                },
                {
                    "log": "Test Log B",
                    "url": "https://b.ct.test.example",
                    "operator": "Test",
                    "index": 300,
                    "time": ms(NOW - 8 * DAY),
                },
            ],
        }
        # crt.sh stores serials as the DER INTEGER body, with the sign byte.
        self.revoked = {(2, b"\x00\xf0\x0d"): {"code": 1, "time": ms(NOW - 50 * DAY)}}

        self.certs = {}
        for row in self.rows:
            try:
                self.certs[row["id"]] = x509.load_der_x509_certificate(row["der"])
            except ValueError:
                pass

    def sha256(self, certid: int) -> str:
        return hashlib.sha256(self.row(certid)["der"]).hexdigest()

    def row(self, certid: int) -> dict:
        return next(r for r in self.rows if r["id"] == certid)


PKI = Pki()
"""Built once, key generation is slow."""


def _derSerial(cert: x509.Certificate) -> bytes:
    serial = cert.serial_number
    size = (serial.bit_length() + 8) // 8  # Room for the sign bit, like DER.
    return serial.to_bytes(size, "big")


def _spki(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _ski(cert: x509.Certificate) -> bytes | None:
    try:
        return cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    except x509.ExtensionNotFound:  # pragma: no cover - every test cert has one
        return None


def _identities(cert: x509.Certificate) -> list[tuple[str, str]]:
    """(NAME_TYPE, NAME_VALUE) rows, like crt.sh's certificate_and_identities view."""

    rows = [(attr.oid.dotted_string, attr.value) for attr in cert.subject]
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        sans = []
    for gname in sans:
        valu = gname.value
        if isinstance(gname, x509.IPAddress):
            if valu.version == 6:
                valu = ":" + ":".join(format(int(g, 16), "X") for g in valu.exploded.split(":"))
            else:
                valu = str(valu)
        rows.append((SAN_TYPES[type(gname)], valu))
    return rows


# The identity types identities() treats as domain names, and as email addresses.
_DOMAIN_TYPES = ("2.5.4.3", "san:dNSName")
_EMAIL_TYPES = ("1.2.840.113549.1.9.1", "san:rfc822Name")


def identityText(cert) -> str:
    """The text crt.sh's ``identities()`` indexes, ported from certwatch_db's fnc/identities.fnc.

    Each identity (subject attribute and SAN), lowercased and longest first. A name with no
    domain (not a commonName, dNSName, or email address) is followed by its reverse. An email
    address is followed by its domain and its reverse. Then every parent domain of the domain,
    down to its TLD, follows, and the first parent's reverse (unless it's already there).
    """

    rows: list[tuple[str, str | None]] = []
    for nametype, valu in _identities(cert):
        ident = valu.lower()
        if nametype in _DOMAIN_TYPES:
            domain = ident
        elif nametype in _EMAIL_TYPES:
            domain = ident[ident.find("@") + 1 :]
        else:
            domain = None
        if (ident, domain) not in rows:  # GROUP BY IDENTITY, DOMAIN_NAME
            rows.append((ident, domain))
    rows.sort(key=lambda row: len(row[0]), reverse=True)

    text = ""
    for ident, domain in rows:
        text += " " + ident
        if not domain:
            text += " " + ident[::-1]
            continue
        if domain != ident:
            text += " " + domain + " " + ident[::-1]
        reverse = True
        while "." in domain:
            domain = domain[domain.index(".") + 1 :]
            text += " " + domain
            if reverse:
                if domain[::-1] + "." not in text:
                    text += " " + domain[::-1]
                reverse = False
    return text.lstrip()


# PostgreSQL's default text search parser (src/backend/tsearch/wparser_def.c), as far as the
# fakes need it: what follows is its state machine's outcome for each kind of token, not the
# state machine itself. Patterns are ASCII-only, like the parser's host, email, URL and file
# states.
_HOST = re.compile(  # Labels of [a-z0-9] joined by - or _, an all-letter TLD of 2+, a port.
    r"[a-z0-9]+(?:[-_][a-z0-9]+)*(?:\.[a-z0-9]+(?:[-_][a-z0-9]+)*)*\.[a-z]{2,}(?![a-z0-9])"
    r"(?::[0-9]+)?",
    re.ASCII | re.IGNORECASE,
)
_LOCAL = re.compile(r"[a-z0-9]+(?:[-_.][a-z0-9]+)*(?=@)", re.ASCII | re.IGNORECASE)
_URLPATH = re.compile(r"/[!#-;=?-\[\]_a-z~]+", re.ASCII | re.IGNORECASE)  # RFC 3986 chars.
_NUMBER = re.compile(r"[0-9]+(?:\.[0-9]+(?:(?:\.[0-9]+)+|[eE][-+]?[0-9]+)?|[eE][-+]?[0-9]+)?")
_SCIENTIFIC = re.compile(r"[0-9]+[eE][-+]?[0-9]+")  # Beats a host or email: 1e5.com is 1e5, com.
_SIGNED = re.compile(r"[-+][0-9]+(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?(?!\.[0-9])")
_ENTITY = re.compile(r"&(?:[a-zA-Z:_][\w:.-]*|#[0-9]+|#[xX][0-9a-fA-F]+);")
_TAG = re.compile(r"</?[a-zA-Z_:][\w:.-]*(?:\s[^<>'\"]*)?/?>")


def _ascdigit(c: str) -> bool:
    return c.isascii() and c.isdigit()


def _alnum(c: str) -> bool:
    return c.isalpha() or _ascdigit(c)


def _mark(c: str) -> bool:
    """A combining mark, which continues a word but doesn't start one."""
    return unicodedata.category(c) in ("Mn", "Mc", "Me")


def _wordEnd(s: str, i: int) -> int:
    while i < len(s) and (_alnum(s[i]) or _mark(s[i])):
        i += 1
    return i


def _fchar(s: str, k: int) -> bool:
    return k < len(s) and s[k].isascii() and (s[k].isalnum() or s[k] == "_")


def _fileFirst(s: str, k: int) -> tuple[int, bool] | None:
    """After a path's ``/``: (end, whether the path ends there), or None if it isn't a path."""
    if _fchar(s, k):
        return _inFile(s, k + 1), False
    if k < len(s) and s[k] in ".~":
        return _pathDot(s, k + 1) if s[k] == "." else _pathTwiddle(s, k + 1)
    return None


def _pathTwiddle(s: str, k: int) -> tuple[int, bool] | None:  # After ``~``.
    if _fchar(s, k):
        return _inFile(s, k + 1), False
    return _fileFirst(s, k + 1) if k < len(s) and s[k] == "/" else None


def _pathDot(s: str, k: int) -> tuple[int, bool] | None:  # After a path's leading ``.``.
    if _fchar(s, k):
        return _inFile(s, k + 1), False
    if k < len(s) and s[k] == ".":
        return _pathDots(s, k + 1)
    return _fileFirst(s, k + 1) if k < len(s) and s[k] == "/" else None


def _pathDots(s: str, k: int) -> tuple[int, bool] | None:  # After ``..``.
    if k >= len(s) or s[k].isspace():
        return k, True
    if s[k] == "/":
        return _fileFirst(s, k + 1) or (k, True)
    return None


def _inFile(s: str, k: int) -> int:
    """The end of a file path whose name chars continue at s[k]."""
    while k < len(s):
        if _fchar(s, k) or s[k] == "-":
            k += 1
        elif s[k] == "." and _fchar(s, k + 1):
            k += 2
        elif s[k] == "/" and (nxt := _fileFirst(s, k + 1)):
            if nxt[1]:
                return nxt[0]
            k = nxt[0]
        else:
            break
    return k


def _file(s: str, k: int) -> int | None:
    """The end of the file path a word becomes at its ``.`` or ``/`` at s[k], if it does."""
    if s[k] == "." and _fchar(s, k + 1):
        return _inFile(s, k + 2)
    nxt = _fileFirst(s, k + 1) if s[k] == "/" else None
    return nxt[0] if nxt else None


def _hyphenWord(s: str, i: int, k: int) -> tuple[int, list[str]] | None:
    """A hyphenated word whose first part is s[i:k] (s[k] is ``-``): the word and its parts.

    Every later part needs a letter, so ``a-b-12`` is ``a-b`` and then ``12`` (the ``-`` after a
    hyphenated word is never a sign).
    """
    end = None
    while k < len(s) and s[k] == "-":
        j = k + 1
        while j < len(s) and _ascdigit(s[j]):
            j += 1
        if j >= len(s) or not (s[j].isalpha() or (j > k + 1 and _mark(s[j]))):
            break
        k = end = _wordEnd(s, j)
    if end is None:
        return None
    word = s[i:end]
    if end + 1 < len(s) and s[end] == "-" and (_alnum(s[end + 1]) or _mark(s[end + 1])):
        end += 1
    return end, [word, *word.split("-")]


def _wordTail(s: str, i: int, k: int) -> tuple[int, list[str]]:
    """The token a word s[i:k] (with digits) makes with what follows it: an email, path, etc."""
    if k < len(s) and s[k] == "@" and (host := _HOST.match(s, k + 1)):
        return host.end(), [s[i : host.end()]]
    if k < len(s) and s[k] in "./" and (end := _file(s, k)):
        return end, [s[i:end]]
    return (k < len(s) and s[k] == "-" and _hyphenWord(s, i, k)) or (k, [s[i:k]])


def _token(s: str, i: int) -> tuple[int, list[str]]:
    """The end of the token the parser reads at s[i], and the words it indexes for it."""

    n, c = len(s), s[i]
    if num := _SCIENTIFIC.match(s, i):
        return num.end(), [num.group()]
    if c.isascii() and c.isalnum():
        # An email address (its domain must be a host), or a host, or a URL: its host/path,
        # its host and its path.
        if (local := _LOCAL.match(s, i)) and (host := _HOST.match(s, local.end() + 1)):
            return host.end(), [s[i : host.end()]]
        if host := _HOST.match(s, i):
            if path := _URLPATH.match(s, host.end()):
                return path.end(), [s[i : path.end()], host.group(), path.group()]
            return host.end(), [host.group()]
    if _ascdigit(c):
        num = _NUMBER.match(s, i)
        j = num.end()
        if num.group().isdigit() and j < n:
            if s[j] == "/" and (end := _file(s, j)):
                return end, [s[i:end]]
            if s[j].isalpha() or _mark(s[j]):
                return _wordTail(s, i, _wordEnd(s, j))
        return j, [num.group()]
    if c.isalpha():
        j = i
        while j < n and c.isascii() and s[j].isascii() and s[j].isalpha():
            j += 1
        if j > i and (j == n or not (_alnum(s[j]) or _mark(s[j]))):  # An ASCII word.
            if s.startswith("://", j):
                return j + 3, []  # A protocol isn't indexed.
            if j < n and s[j] in "./" and (end := _file(s, j)):
                return end, [s[i:end]]
            return (j < n and s[j] == "-" and _hyphenWord(s, i, j)) or (j, [s[i:j]])
        j = max(j, i + 1)
        while j < n and (s[j].isalpha() or _mark(s[j])):
            j += 1
        if j < n and _ascdigit(s[j]):
            return _wordTail(s, i, _wordEnd(s, j))
        return (j < n and s[j] == "-" and _hyphenWord(s, i, j)) or (j, [s[i:j]])
    if c in "-+" and (num := _SIGNED.match(s, i)):
        return num.end(), [num.group()]
    path = None
    if c == "/":
        path = _fileFirst(s, i + 1)
    elif c == "~":
        path = _pathTwiddle(s, i + 1)
    elif c == "." and i + 1 < n and s[i + 1] in "./":
        path = _pathDots(s, i + 2) if s[i + 1] == "." else _fileFirst(s, i + 2)
    if path:
        return path[0], [s[i : path[0]]]
    if (c == "&" and (skip := _ENTITY.match(s, i))) or (c == "<" and (skip := _TAG.match(s, i))):
        return skip.end(), []  # XML entities and tags aren't indexed.
    # Blank: this char and those after it that aren't alphanumeric or able to start a token.
    j = i + 1
    while j < n and not (_alnum(s[j]) or s[j] in "<-+&/"):
        j += 1
    return j, []


def tsTokens(text: str) -> set[str]:
    """The words ``to_tsvector('simple', text)`` (and ``plainto_tsquery``) makes of text.

    A pure-Python stand-in for PostgreSQL's default text search parser, lowercased like the
    ``simple`` dictionary, which is how crt.sh's ``certwatch`` config indexes ``identities()``.
    It's checked against PostgreSQL (``tests/test_pg.py``, ``test_identity_tokens``) and agrees
    on identity text: hosts and emails are single words (``old`` doesn't match
    ``old.vertex.link``, ``visi`` doesn't match ``visi@vertex.link``), but an ``@`` whose domain
    isn't a host (has no dot) splits; ``:`` separates words, so a crt.sh IPv6 address is its
    groups; a URL is its ``host/path``, its host and its path, while a slash path that doesn't
    start with a host (like a reversed URL) is one file path word; a hyphenated word is itself
    and its parts; numbers, versions and signed numbers are words.

    Known not to match PostgreSQL: a word that starts with a combining mark (PostgreSQL's
    ``iswalpha`` counts some as letters), tags with characters PostgreSQL's tag states reject,
    and other locale-dependent classes of non-ASCII characters.
    """

    tokens, i = set(), 0
    while i < len(text):
        i, words = _token(text, i)
        tokens.update(word.lower() for word in words)
    return tokens


def _likeRegex(pattern: str) -> re.Pattern:
    out, i = "", 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and i + 1 < len(pattern):
            out += re.escape(pattern[i + 1])
            i += 2
            continue
        out += ".*" if char == "%" else "." if char == "_" else re.escape(char)
        i += 1
    return re.compile(f"^{out}$", re.IGNORECASE | re.DOTALL)


class FakeCrtshDb:
    """Answers CrtshDb's queries from ``PKI``, recording every call in ``calls``.

    Every certificate row carries the metadata CrtshDb's queries return (``issuer_name``,
    ``caids``, and ``ctlog``/``revoked`` as JSON text).
    """

    def __init__(self, pki: Pki = PKI):
        self.pki = pki
        self.calls: list[tuple[str, dict]] = []
        self.fail: str | None = None
        self.closed = False

    def _call(self, meth: str, **kwargs):
        self.calls.append((meth, kwargs))
        if self.fail:
            raise CrtshDbError(self.fail)

    def last(self, meth: str) -> dict:
        """The arguments of the most recent call to ``meth``."""
        return next(kw for m, kw in reversed(self.calls) if m == meth)

    def called(self, meth: str) -> int:
        """How many times ``meth`` was called. It must be a query method, so typos fail loudly."""
        assert callable(getattr(self, meth, None)), f"FakeCrtshDb has no method {meth}"
        return sum(1 for m, _ in self.calls if m == meth)

    def _valid(self, cert, valid=False, since=None, until=None) -> bool:
        if cert is None:
            # The x509_* functions return null for unparsable certificates, so any filter drops them.
            return not valid and since is None and until is None
        if valid and cert.not_valid_after_utc < datetime.datetime.now(datetime.UTC):
            return False
        nb = int(cert.not_valid_before_utc.timestamp() * 1000)
        if since is not None and nb < since:
            return False
        return until is None or nb < until

    def _row(self, row: dict, **extra) -> dict:
        """A certificate row with its metadata."""

        cert = self.pki.certs.get(row["id"])
        revoked = self.pki.revoked.get((row["issuer_ca_id"], _derSerial(cert))) if cert else None
        ctlog = self.pki.ctlog.get(row["id"])
        return dict(
            row,
            **extra,
            issuer_name=CA_NAMES.get(row["issuer_ca_id"]),
            caids=[a for c, a in self.pki.cacerts.items() if c == row["id"]],
            ctlog=json.dumps(ctlog) if ctlog else None,
            revoked=json.dumps(revoked) if revoked else None,
        )

    def _match(self, row: dict, lookups: dict) -> bool:
        cert = self.pki.certs.get(row["id"])
        keys = {
            "id": lambda c, r: r["id"],
            "sha256": lambda c, r: hashlib.sha256(r["der"]).digest(),
            "sha1": lambda c, r: hashlib.sha1(r["der"]).digest(),
            "serial": lambda c, r: _derSerial(c),
            "ski": lambda c, r: _ski(c),
            "spki": lambda c, r: hashlib.sha256(_spki(c)).digest(),
            "spkisha1": lambda c, r: hashlib.sha1(_spki(c)).digest(),
            "subjectsha1": lambda c, r: hashlib.sha1(c.subject.public_bytes()).digest(),
        }
        for kind, valus in lookups.items():
            if kind not in keys:
                raise CrtshDbError(f"Unknown lookup type {kind}")
            # Like the x509_* functions, unparsable certificates only match on their ID and hashes.
            if cert is None and kind not in ("id", "sha256", "sha1"):
                continue
            if keys[kind](cert, row) in valus:
                return True
        return False

    def _related(self, by: str, cert: x509.Certificate | None, row: dict):
        if by == "siblings":
            return row["issuer_ca_id"]
        if cert is None:
            return None  # The x509_* functions return null for unparsable certificates.
        return {
            "key": lambda: hashlib.sha256(_spki(cert)).digest(),
            "subject": lambda: hashlib.sha1(cert.subject.public_bytes()).digest(),
            "serial": lambda: _derSerial(cert),
            "ski": lambda: _ski(cert),
        }[by]()

    def _newest(self, rows: list[dict]) -> list[dict]:
        """ORDER BY x509_notBefore(...) DESC, which puts nulls (unparsable certificates) first."""

        def key(row):
            cert = self.pki.certs.get(row["id"])
            return (cert is None, cert.not_valid_before_utc if cert else NOW)

        return sorted(rows, key=key, reverse=True)

    async def close(self):
        self.closed = True

    async def certs(self, lookups, limit=100):
        self._call("certs", lookups=lookups, limit=limit)
        return [self._row(r) for r in self.pki.rows if self._match(r, lookups)][:limit]

    async def certsByIdentity(
        self,
        text,
        like=None,
        nametypes=None,
        caids=None,
        issuer=None,
        valid=False,
        since=None,
        until=None,
        limit=1000,
    ):
        self._call(
            "certsByIdentity",
            text=text,
            like=like,
            nametypes=nametypes,
            caids=caids,
            issuer=issuer,
            valid=valid,
            since=since,
            until=until,
            limit=limit,
        )
        # plainto_tsquery(text) @@ identities(...): every token of the text is a token of the cert.
        words = tsTokens(tsquery(text))
        if not words:
            return []  # An empty tsquery matches nothing.
        regex = _likeRegex(like) if like is not None else None
        issuers = (
            {i for i, n in CA_NAMES.items() if issuer.lower() in n.lower()} if issuer else None
        )
        found = []
        for row in self.pki.rows:
            cert = self.pki.certs.get(row["id"])
            if cert is None:
                continue
            idents = _identities(cert)
            if not words <= tsTokens(identityText(cert)):
                continue
            if (regex is not None or nametypes) and not any(
                (regex is None or regex.match(v)) and (not nametypes or t in nametypes)
                for t, v in idents
            ):
                continue
            if caids and row["issuer_ca_id"] not in caids:
                continue
            if issuers is not None and row["issuer_ca_id"] not in issuers:
                continue
            if self._valid(cert, valid, since, until):
                found.append(self._row(row))
        return found[:limit]

    async def certsByIssuer(
        self, caids=None, issuer=None, cert=None, valid=False, since=None, until=None, limit=1000
    ):
        self._call(
            "certsByIssuer",
            caids=caids,
            issuer=issuer,
            cert=cert,
            valid=valid,
            since=since,
            until=until,
            limit=limit,
        )
        sources = set(caids or [])
        if issuer:
            sources |= {i for i, n in CA_NAMES.items() if issuer.lower() in n.lower()}
        if cert:
            source = next((r for r in self.pki.rows if self._match(r, cert)), None)
            if source is not None and source["id"] in self.pki.cacerts:
                sources.add(self.pki.cacerts[source["id"]])
        found = []
        for caid in sorted(sources):
            rows = [
                r
                for r in self.pki.rows
                if r["issuer_ca_id"] == caid
                and self._valid(self.pki.certs.get(r["id"]), valid, since, until)
            ]
            found.extend(self._row(r) for r in self._newest(rows)[:limit])
        return found

    async def related(self, by, cert, valid=False, limit=100):
        self._call("related", by=by, cert=cert, valid=valid, limit=limit)
        source = next((r for r in self.pki.rows if self._match(r, cert)), None)
        if source is None:
            return []
        valu = self._related(by, self.pki.certs.get(source["id"]), source)
        if valu is None:
            return []
        rows = [
            r
            for r in self.pki.rows
            if not self._match(r, cert)
            and self._related(by, self.pki.certs.get(r["id"]), r) == valu
            and self._valid(self.pki.certs.get(r["id"]), valid)
        ]
        if by == "siblings":
            rows = self._newest(rows)
        return [self._row(r) for r in rows[:limit]]

    async def chain(self, cert, maxdepth=10, maxrows=500):
        self._call("chain", cert=cert, maxdepth=maxdepth, maxrows=maxrows)
        leaf = next((r for r in self.pki.rows if self._match(r, cert)), None)
        if leaf is None:
            return []
        out = [self._row(leaf, child_id=None, depth=0)]
        frontier = [(leaf, 0, [leaf["id"]])]
        while frontier and len(out) < maxrows:
            child, depth, path = frontier.pop(0)
            if depth >= maxdepth or self.pki.cacerts.get(child["id"]) == child["issuer_ca_id"]:
                continue  # Too deep, or a self-issued root.
            for row in self.pki.rows:
                # Never revisit a certificate on the path, CAs cross-sign each other.
                if (
                    self.pki.cacerts.get(row["id"]) == child["issuer_ca_id"]
                    and row["id"] not in path
                ):
                    out.append(self._row(row, child_id=child["id"], depth=depth + 1))
                    frontier.append((row, depth + 1, path + [row["id"]]))
        return out[:maxrows]

    async def cas(self, caids=None, name=None, certs=False, limit=100):
        self._call("cas", caids=caids, name=name, certs=certs, limit=limit)
        ids = [
            i
            for i, n in CA_NAMES.items()
            if (caids and i in [int(c) for c in caids]) or (name and name.lower() in n.lower())
        ]
        out = []
        for caid in sorted(ids)[:limit]:
            members = [r for r in self.pki.rows if self.pki.cacerts.get(r["id"]) == caid]
            for row in members or [None]:
                if not certs:
                    out.append({"ca_id": caid, "ca_name": CA_NAMES[caid], "id": row and row["id"]})
                elif row is None:
                    out.append({"ca_id": caid, "ca_name": CA_NAMES[caid], "id": None})
                else:
                    out.append(self._row(row, ca_id=caid, ca_name=CA_NAMES[caid]))
        return out

    async def raw(self, sql, args=None, limit=1000):
        self._call("raw", sql=sql, args=args, limit=limit)
        if "nope" in sql:
            raise CrtshDbError('relation "nope" does not exist')
        return [
            {
                "id": 1,
                "name": CA_NAMES[1],
                "key": memoryview(b"\x01\x02"),
                # crt.sh's timestamps are naive (UTC).
                "seen": datetime.datetime(2026, 1, 1),  # noqa: DTZ001
                "ids": [1, b"\xff"],
                "ok": True,
                "none": None,
                "score": 1.5,
                "other": complex(1, 2),
            }
        ]


@contextlib.asynccontextmanager
async def crtshSvc(test, conf: dict | None = None):
    """Yield (core, svc, fake) - a Cortex with slib.crtsh added, backed by a FakeCrtshDb."""

    async with test.getTestCoreProxSvc(CrtshSvc, ssvc_conf=conf or {}) as (core, prox, svc):
        await svc.db.close()
        fake = FakeCrtshDb()
        svc.db = fake
        yield core, svc, fake

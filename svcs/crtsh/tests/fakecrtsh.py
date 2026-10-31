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

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from crtshsvc import CrtshSvc
from crtshsvc.db import CrtshDbError


NOW = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
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
    attrs = [x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
             x509.NameAttribute(NameOID.ORGANIZATION_NAME, org)]
    if ou:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(attrs)


def sctList(count: int = 2) -> bytes:
    """A DER OCTET STRING holding a TLS encoded SignedCertificateTimestampList (RFC 6962)."""

    scts = b""
    for i in range(count):
        sct = (b"\x00" + bytes([i + 1]) * 32 + struct.pack(">Q", int(NOW.timestamp() * 1000))
               + b"\x00\x00" + b"\x04\x03" + struct.pack(">H", 4) + b"sig!")
        scts += struct.pack(">H", len(sct)) + sct
    body = struct.pack(">H", len(scts)) + scts
    return b"\x04" + bytes([0x81, len(body)]) + body if len(body) > 127 else b"\x04" + bytes([len(body)]) + body


def makeCert(subject: x509.Name, key, issuer: x509.Name, issuerKey, serial: int,
             notbefore: datetime.datetime, notafter: datetime.datetime, ca: bool = False,
             sans: list | None = None, precert: bool = False, scts: bool = False,
             full: bool = False, aki=None) -> bytes:
    """Build and sign a DER certificate."""

    builder = (x509.CertificateBuilder()
               .subject_name(subject).issuer_name(issuer).public_key(key.public_key())
               .serial_number(serial).not_valid_before(notbefore).not_valid_after(notafter)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                              critical=False))
    if aki is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(aki.public_key()), critical=False)
    if ca:
        builder = (builder
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                   .add_extension(x509.KeyUsage(
                       digital_signature=False, content_commitment=False, key_encipherment=False,
                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                       crl_sign=True, encipher_only=False, decipher_only=False), critical=True))
    else:
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None),
                                        critical=True)
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    if precert:
        builder = builder.add_extension(x509.UnrecognizedExtension(PRECERT_POISON, b"\x05\x00"),
                                        critical=True)
    if scts:
        builder = builder.add_extension(x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"), sctList()), critical=False)
    if full:
        builder = (builder
                   .add_extension(x509.KeyUsage(
                       digital_signature=True, content_commitment=False, key_encipherment=False,
                       data_encipherment=False, key_agreement=True, key_cert_sign=False,
                       crl_sign=False, encipher_only=True, decipher_only=True), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([
                       ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH,
                   ]), critical=False)
                   .add_extension(x509.CRLDistributionPoints([
                       x509.DistributionPoint([x509.UniformResourceIdentifier(CRL_URL)],
                                              None, None, None),
                       x509.DistributionPoint(None, x509.RelativeDistinguishedName([
                           x509.NameAttribute(NameOID.COMMON_NAME, "crl")]), None, None),
                   ]), critical=False)
                   .add_extension(x509.AuthorityInformationAccess([
                       x509.AccessDescription(x509.AuthorityInformationAccessOID.OCSP,
                                              x509.UniformResourceIdentifier("http://ocsp.test.example")),
                       x509.AccessDescription(x509.AuthorityInformationAccessOID.CA_ISSUERS,
                                              x509.UniformResourceIdentifier("http://ca.test.example/i1.der")),
                       x509.AccessDescription(x509.AuthorityInformationAccessOID.CA_ISSUERS,
                                              x509.DNSName("ca.test.example")),
                   ]), critical=False)
                   .add_extension(x509.CertificatePolicies([
                       x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.2"), None),
                   ]), critical=False)
                   .add_extension(x509.TLSFeature([x509.TLSFeatureType.status_request]),
                                  critical=False))

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
            x509.DNSName("www.vertex.link"), x509.DNSName("vertex.link"),
            x509.DNSName("*.vertex.link"), x509.RFC822Name("visi@vertex.link"),
            x509.IPAddress(ipaddress.ip_address("1.2.3.4")),
            x509.IPAddress(ipaddress.ip_address("2001:db8::1")),
            x509.UniformResourceIdentifier("https://vertex.link/"),
        ]
        self.leafSerial = 0x5a0b1c2d3e4f

        self.rows = [
            {"id": 1, "issuer_ca_id": 1, "der": makeCert(
                r1, r1key, r1, r1key, 1, NOW - 3650 * DAY, NOW + 3650 * DAY, ca=True)},
            {"id": 3, "issuer_ca_id": 3, "der": makeCert(
                e2, e2key, e2, e2key, 3, NOW - 3000 * DAY, NOW + 3000 * DAY, ca=True)},
            {"id": 2, "issuer_ca_id": 1, "der": makeCert(
                i1, i1key, r1, r1key, 2, NOW - 1000 * DAY, NOW + 1000 * DAY, ca=True, aki=r1key)},
            {"id": 4, "issuer_ca_id": 3, "der": makeCert(
                i1, i1key, e2, e2key, 4, NOW - 500 * DAY, NOW + 500 * DAY, ca=True, aki=e2key)},
            {"id": 9, "issuer_ca_id": 2, "der": makeCert(
                www, leafkey, i1, i1key, self.leafSerial, NOW - 10 * DAY, NOW + 80 * DAY,
                sans=leafsans, precert=True, full=True, aki=i1key)},
            {"id": 10, "issuer_ca_id": 2, "der": makeCert(
                www, leafkey, i1, i1key, self.leafSerial, NOW - 10 * DAY, NOW + 80 * DAY,
                sans=leafsans, scts=True, full=True, aki=i1key)},
            {"id": 11, "issuer_ca_id": 2, "der": makeCert(
                name("old.vertex.link", org="The Vertex Project"), oldkey, i1, i1key,
                0xF00D, NOW - 200 * DAY, NOW + 100 * DAY,
                sans=[x509.DNSName("old.vertex.link")], full=True, aki=i1key)},
            {"id": 12, "issuer_ca_id": 2, "der": makeCert(
                name("expired.vertex.link", org="The Vertex Project"), expkey, i1, i1key,
                12, NOW - 800 * DAY, NOW - 400 * DAY,
                sans=[x509.DNSName("expired.vertex.link")], aki=i1key)},
            {"id": 13, "issuer_ca_id": 2, "der": b"not a certificate"},
            {"id": 14, "issuer_ca_id": 2, "der": makeCert(
                name("shop.example.com", org="Example Inc"), shopkey, i1, i1key,
                14, NOW - 5 * DAY, NOW + 85 * DAY,
                sans=[x509.DNSName("shop.example.com"), x509.DNSName("notvertex.link")],
                aki=i1key)},
            {"id": 15, "issuer_ca_id": 2, "der": makeCert(
                www, leafkey, i1, i1key, 15, NOW - 100 * DAY, NOW - 10 * DAY,
                sans=[x509.DNSName("www.vertex.link")], aki=i1key)},
        ]
        self.cacerts = {1: 1, 3: 3, 2: 2, 4: 2}
        def ms(when):
            return int(when.timestamp() * 1000)

        # CT log entries and CRL revocations, as the certificate queries return them.
        self.ctlog = {
            9: [{"log": "Test Log A", "url": "https://a.ct.test.example", "operator": "Test",
                 "index": 100, "time": ms(NOW - 10 * DAY)}],
            10: [{"log": "Test Log A", "url": "https://a.ct.test.example", "operator": "Test",
                  "index": 200, "time": ms(NOW - 9 * DAY)},
                 {"log": "Test Log B", "url": "https://b.ct.test.example", "operator": "Test",
                  "index": 300, "time": ms(NOW - 8 * DAY)}],
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
    return cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)


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
        return sum(1 for m, _ in self.calls if m == meth)

    def _valid(self, cert, valid=False, since=None, until=None) -> bool:
        if cert is None:
            # The x509_* functions return null for unparsable certificates, so any filter drops them.
            return not valid and since is None and until is None
        if valid and cert.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc):
            return False
        nb = int(cert.not_valid_before_utc.timestamp() * 1000)
        if since is not None and nb < since:
            return False
        if until is not None and nb >= until:
            return False
        return True

    def _row(self, row: dict, **extra) -> dict:
        """A certificate row with its metadata."""

        cert = self.pki.certs.get(row["id"])
        revoked = self.pki.revoked.get((row["issuer_ca_id"], _derSerial(cert))) if cert else None
        ctlog = self.pki.ctlog.get(row["id"])
        return dict(row, **extra,
                    issuer_name=CA_NAMES.get(row["issuer_ca_id"]),
                    caids=[a for c, a in self.pki.cacerts.items() if c == row["id"]],
                    ctlog=json.dumps(ctlog) if ctlog else None,
                    revoked=json.dumps(revoked) if revoked else None)

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

    async def certsByIdentity(self, text, like=None, nametypes=None, caids=None, issuer=None,
                              valid=False, since=None, until=None, limit=1000):
        self._call("certsByIdentity", text=text, like=like, nametypes=nametypes, caids=caids,
                   issuer=issuer, valid=valid, since=since, until=until, limit=limit)
        words = text.lower().split()
        regex = _likeRegex(like) if like is not None else None
        issuers = {i for i, n in CA_NAMES.items() if issuer.lower() in n.lower()} if issuer else None
        found = []
        for row in self.pki.rows:
            cert = self.pki.certs.get(row["id"])
            if cert is None:
                continue
            idents = _identities(cert)
            blob = " ".join(v.lower() for _, v in idents)
            if not all(word in blob for word in words):
                continue
            if regex is not None or nametypes:
                if not any((regex is None or regex.match(v)) and (not nametypes or t in nametypes)
                           for t, v in idents):
                    continue
            if caids and row["issuer_ca_id"] not in caids:
                continue
            if issuers is not None and row["issuer_ca_id"] not in issuers:
                continue
            if self._valid(cert, valid, since, until):
                found.append(self._row(row))
        return found[:limit]

    async def certsByIssuer(self, caids=None, issuer=None, cert=None, valid=False, since=None,
                            until=None, limit=1000):
        self._call("certsByIssuer", caids=caids, issuer=issuer, cert=cert, valid=valid,
                   since=since, until=until, limit=limit)
        sources = set(caids or [])
        if issuer:
            sources |= {i for i, n in CA_NAMES.items() if issuer.lower() in n.lower()}
        if cert:
            source = next((r for r in self.pki.rows if self._match(r, cert)), None)
            if source is not None and source["id"] in self.pki.cacerts:
                sources.add(self.pki.cacerts[source["id"]])
        found = []
        for caid in sorted(sources):
            rows = [r for r in self.pki.rows if r["issuer_ca_id"] == caid
                    and self._valid(self.pki.certs.get(r["id"]), valid, since, until)]
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
        rows = [r for r in self.pki.rows if not self._match(r, cert)
                and self._related(by, self.pki.certs.get(r["id"]), r) == valu
                and self._valid(self.pki.certs.get(r["id"]), valid)]
        if by == "siblings":
            rows = self._newest(rows)
        return [self._row(r) for r in rows[:limit]]

    async def chain(self, cert, maxdepth=10):
        self._call("chain", cert=cert, maxdepth=maxdepth)
        leaf = next((r for r in self.pki.rows if self._match(r, cert)), None)
        if leaf is None:
            return []
        out = [self._row(leaf, child_id=None, depth=0)]
        frontier = [(leaf, 0)]
        while frontier:
            child, depth = frontier.pop(0)
            if depth >= maxdepth or self.pki.cacerts.get(child["id"]) == child["issuer_ca_id"]:
                continue  # Too deep, or a self-issued root.
            for row in self.pki.rows:
                if self.pki.cacerts.get(row["id"]) == child["issuer_ca_id"]:
                    out.append(self._row(row, child_id=child["id"], depth=depth + 1))
                    frontier.append((row, depth + 1))
        return out

    async def cas(self, caids=None, name=None, certs=False, limit=100):
        self._call("cas", caids=caids, name=name, certs=certs, limit=limit)
        ids = [i for i, n in CA_NAMES.items()
               if (caids and i in [int(c) for c in caids]) or (name and name.lower() in n.lower())]
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

    async def raw(self, sql, args=None):
        self._call("raw", sql=sql, args=args)
        if "nope" in sql:
            raise CrtshDbError('relation "nope" does not exist')
        return [{
            "id": 1, "name": CA_NAMES[1], "key": memoryview(b"\x01\x02"),
            "seen": datetime.datetime(2026, 1, 1), "ids": [1, b"\xff"], "ok": True,
            "none": None, "score": 1.5, "other": complex(1, 2),
        }]


@contextlib.asynccontextmanager
async def crtshSvc(test, conf: dict | None = None):
    """Yield (core, svc, fake) - a Cortex with slib.crtsh added, backed by a FakeCrtshDb."""

    async with test.getTestCoreProxSvc(CrtshSvc, ssvc_conf=conf or {}) as (core, prox, svc):
        await svc.db.close()
        fake = FakeCrtshDb()
        svc.db = fake
        yield core, svc, fake

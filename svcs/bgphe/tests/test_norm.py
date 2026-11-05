"""Tests for parsing bgp.he.net's responses: certificates, whois records, and the rest."""

import base64
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from bgphesvc import certs, norm, whois

from .fakebgphe import load


def ms(*args) -> int:
    """Epoch millis of a UTC datetime."""
    return int(datetime.datetime(*args, tzinfo=datetime.UTC).timestamp() * 1000)


def selfSigned(cn="test.example.com", sans=("test.example.com",)) -> bytes:
    """A self-signed EC certificate, as DER."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x0ABC)
        .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2099, 1, 1, tzinfo=datetime.UTC))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
    )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


# ---- Certificates ----


def test_cert_full():
    items = load("certs_gormo.co.json")["certificates"]
    item = items[0]
    assert not item["pre_cert"]
    der = base64.b64decode(item["certificate_der"])

    c = certs.heCert(item)
    assert c["sha256"] == __import__("hashlib").sha256(der).hexdigest()
    assert c["size"] == len(der)
    assert "tbs" not in c
    assert c["subject"]["dn"] == "CN=gormo.co"
    # RFC 4514 orders the RDNs the other way around.
    assert c["issuer"]["dn"] == ",".join(reversed(item["issuer"].split(", ")))
    assert c["serial"] == certs.heSerial(item["serial"])
    assert c["notbefore"] == certs.heTime(item["notbefore"])
    assert c["notafter"] == certs.heTime(item["notafter"])
    assert c["precert"] is False
    assert c["selfsigned"] is False
    assert c["signature"]
    assert c["pubkey"]["sha256"] and c["pubkey"]["spki"]
    assert ("dns", "gormo.co") in [tuple(s) for s in c["sans"]]
    assert c["identities"]["fqdns"] == ["gormo.co"]
    assert c["he"] == {
        "id": item["id"],
        "shard": item["shard_id"],
        "shards": item["shards"],
        "logged": item["timestamp"],
        "precert": False,
        "url": f"https://bgp.he.net/certs/#_SearchTab?cert_id={item['id']}&shard_id={item['shard_id']}",
    }
    assert certs.certKey(c) == c["sha256"]


def test_cert_precert_tbs():
    # bgp.he.net only has the TBSCertificate of a precertificate.
    item = next(i for i in load("certs_gormo.co.json")["certificates"] if i["pre_cert"])
    der = base64.b64decode(item["certificate_der"])
    assert certs.isTbs(der)
    with pytest.raises(ValueError):
        x509.load_der_x509_certificate(der)

    c = certs.heCert(item)
    assert "error" not in c
    assert c["sha256"] is None and c["sha1"] is None and c["md5"] is None
    assert c["signature"] is None
    assert c["tbs"] == __import__("hashlib").sha256(der).hexdigest()
    assert certs.certKey(c) == f"tbs:{c['tbs']}"
    assert c["precert"] is True
    assert c["subject"]["dn"] == "CN=gormo.co"
    assert c["serial"] == certs.heSerial(item["serial"])
    assert c["notbefore"] == certs.heTime(item["notbefore"])
    assert c["sigalgo"]["name"] == "sha256WithRSAEncryption"
    assert c["pubkey"]["algo"] == "rsa"
    assert c["identities"]["fqdns"] == ["gormo.co"]


def test_cert_google():
    full, pre = load("certs_google.com.json")["certificates"]
    c = certs.heCert(full)
    assert c["sha256"] and c["subject"]["dn"] == "CN=*.google.com"
    assert c["pubkey"]["algo"] == "ec"
    # Wildcards become their base domain.
    assert "google.com" in c["identities"]["fqdns"]
    assert not any("*" in f for f in c["identities"]["fqdns"])
    assert c["crls"] or c["ocsp"] or c["caissuers"]

    p = certs.heCert(pre)
    assert p["tbs"] and p["sha256"] is None and p["precert"] is True
    assert p["sigalgo"]["name"] == "ecdsa-with-SHA256"


def test_cert_selfsigned():
    der = selfSigned()
    assert not certs.isTbs(der)
    c = certs.heCert({"certificate_der": base64.b64encode(der).decode(), "id": 1})
    assert c["selfsigned"] is True
    assert c["ca"] is True
    assert c["serial"] == "0abc"
    assert c["notbefore"] == ms(2025, 1, 1)
    # No shard, no link.
    assert c["he"]["url"] is None
    assert c["he"]["logged"] is None


def test_cert_fallback():
    # DER that isn't a certificate falls back to bgp.he.net's summary fields.
    item = {
        "certificate_der": base64.b64encode(b"\x30\x03\x01\x01\xff").decode(),
        "subject": "C=US, CN=bad.example.com",
        "issuer": "CN=Some CA",
        "serial": "00:0a:bc",
        "notbefore": "Jan  2 03:04:05 2026 +00:00",
        "notafter": "Jan  2 03:04:05 2027 UTC",
        "pre_cert": False,
        "subject_alternative_names": [
            {"type": "DNS", "value": "*.bad.example.com"},
            {"type": "IPAddress", "value": "1.2.3.4"},
            {"type": "weird", "value": "x"},
            "nope",
        ],
    }
    c = certs.heCert(item)
    assert c["error"].startswith("Unable to parse certificate")
    assert c["sha256"] and c["size"] == 5
    assert c["serial"] == "0abc"
    assert c["subject"]["dn"] == "C=US, CN=bad.example.com"
    assert c["notbefore"] == ms(2026, 1, 2, 3, 4, 5)
    assert c["notafter"] == ms(2027, 1, 2, 3, 4, 5)
    assert c["sans"] == [("dns", "*.bad.example.com"), ("ip", "1.2.3.4")]
    assert c["identities"]["fqdns"] == ["bad.example.com"]
    assert c["identities"]["ipv4s"] == ["1.2.3.4"]

    # A TBS that can't be parsed has no fingerprints either.
    tbs = b"\x30\x03\x02\x01\x01"
    assert certs.isTbs(tbs)
    c = certs.heCert({"certificate_der": base64.b64encode(tbs).decode()})
    assert c["error"] and c["sha256"] is None and c["tbs"]
    assert c["subject"] == {"dn": None, "attrs": {"cn": []}}


def test_cert_unusable():
    assert certs.heCert({}) is None
    assert certs.heCert({"certificate_der": ""}) is None
    assert certs.heCert({"certificate_der": "!!notbase64!!"}) is None


def test_cert_helpers():
    assert certs.heSerial("00:a3:5b") == "a35b"
    assert certs.heSerial("0") == "00"
    assert certs.heSerial("zz") is None
    assert certs.heSerial(None) is None
    assert certs.serialHex(-1) == "ff"
    assert certs.heTime("nope") is None
    assert certs.heTime(None) is None
    assert certs.isTbs(b"") is False
    assert certs.isTbs(b"\x04\x00") is False
    with pytest.raises(ValueError):
        certs.wrapTbs(b"\x30\x03\x04\x01\x00")
    with pytest.raises(ValueError):
        certs._tlv(b"\x30\x85\x00\x00\x00\x00\x00", 0)


# ---- Inputs ----


def test_norm_inputs():
    assert norm.normDomain(" WWW.Vertex.Link. ") == "www.vertex.link"
    assert norm.normDomain("*.vertex.link") == "vertex.link"
    assert norm.normDomain("bücher.de") == "xn--bcher-kva.de"
    for bad in ("", "localhost", "a b.com", "-bad.com.", None, 5, "x" * 300 + ".com"):
        with pytest.raises(norm.BadValu):
            norm.normDomain(bad)

    assert norm.normAsn(15169) == 15169
    assert norm.normAsn(" as15169 ") == 15169
    assert norm.normAsn("AS4294967295") == 4294967295
    for bad in (True, -1, 2**32, "AS", "15169x", None, 1.5):
        with pytest.raises(norm.BadValu):
            norm.normAsn(bad)

    assert norm.normPrefix("8.8.8.8") == {
        "addr": "8.8.8.8",
        "len": 32,
        "cidr": "8.8.8.8/32",
        "version": 4,
    }
    assert norm.normPrefix("8.8.8.9/24")["cidr"] == "8.8.8.0/24"
    assert norm.normPrefix("2001:4860:4860::8888")["len"] == 128
    for bad in ("nope", "1.2.3.4/33", None):
        with pytest.raises(norm.BadValu):
            norm.normPrefix(bad)


def test_norm_prefixes():
    rows = norm.normPrefixes(load("prefixes_15169.json")["prefixes"] + ["nope", {"Prefix": 5}])
    # IPv4 first, sorted, deduplicated, invalid rows dropped.
    assert [r["prefix"] for r in rows] == [
        "8.8.4.0/24",
        "8.8.8.0/24",
        "34.0.0.0/15",
        "34.0.0.0/20",
        "2001:4860::/32",
        "2001:4860:4820::/48",
    ]
    assert rows[0] == {"prefix": "8.8.4.0/24", "version": 4, "count": 1061, "total": 1065}
    assert norm.normPrefixes([{"Prefix": "1.2.3.0/24", "Count": "x", "Total": 2.0}]) == [
        {"prefix": "1.2.3.0/24", "version": 4, "count": None, "total": 2}
    ]


def test_norm_hosts():
    data = norm.normHosts(norm.normPrefix("8.8.8.0/24"), load("prefix_8.8.8.0-24.json"))
    assert data["prefix"] == "8.8.8.0/24"
    assert data["truncated"] is True
    assert data["ips"] == 2
    assert data["hostnames"] == 73882
    assert [e["ip"] for e in data["entries"]] == ["8.8.8.4", "8.8.8.8"]
    fqdns = data["entries"][1]["fqdns"]
    assert "wild.example.com" in fqdns
    assert "not a host" not in fqdns
    assert fqdns == sorted(fqdns)

    data = norm.normHosts(
        norm.normPrefix("1.2.3.4"),
        {"entries": [{"ip": "bad"}, "nope", {"ip": "1.2.3.4", "hostnames": ["a.com", "A.com"]}]},
    )
    assert data["entries"] == [{"ip": "1.2.3.4", "version": 4, "fqdns": ["a.com"]}]
    assert data["truncated"] is False


def test_norm_subdomains():
    data = norm.normSubdomains("gormo.co", load("certlist_gormo.co.json"))
    assert data["domains"][0] == {"fqdn": "url.gormo.co", "certs": 13}
    assert [d["fqdn"] for d in data["domains"]] == [
        "url.gormo.co",
        "gormo.co",
        "www.gormo.co",
        "docs.gormo.co",
    ]
    assert data["certs"] == 27
    assert data["truncated"] is False

    data = norm.normSubdomains(
        "x.com",
        {
            "domains": [
                {"domain": "a.x.com", "certificate_count": 1},
                {"domain": "A.x.com", "certificate_count": 3},
                {"domain": "bad domain"},
                "nope",
            ],
            "truncated": True,
        },
    )
    assert data["domains"] == [{"fqdn": "a.x.com", "certs": 3}]
    assert data["truncated"] is True


# ---- Whois ----


def test_whois_helpers():
    assert whois.parseTime("2026-09-01T03:37:59.507Z") == ms(2026, 9, 1, 3, 37, 59, 507000)
    assert whois.parseTime("2026-09-01T03:37:59.5071234Z") == ms(2026, 9, 1, 3, 37, 59, 507123)
    assert whois.parseTime("2018-03-12T21:44:25+01:00") == ms(2018, 3, 12, 20, 44, 25)
    assert whois.parseTime("13-Dec-2025") == ms(2025, 12, 13)
    assert whois.parseTime("20051005") == ms(2005, 10, 5)
    assert whois.parseTime("2020-01-01 (UTC)") == ms(2020, 1, 1)
    assert whois.parseTime("11:32:37 28-Apr-2025") == ms(2025, 4, 28, 11, 32, 37)
    assert whois.parseTime("before Aug-1996") is None
    assert whois.parseTime("") is None

    assert whois.fixText("MajÃ³") == "Majó"
    assert whois.fixText("Majó ☃") == "Majó ☃"
    assert whois.clean("  REDACTED FOR PRIVACY ") is None
    assert whois.clean(" One  Way, ") == "One Way"
    assert whois.phone("tel:+1-555") == "+1-555"
    assert whois.emailOf("Contact: Foo@Example.COM.") == "foo@example.com"
    assert whois.emailOf("REDACTED@example.com") is None
    assert whois.emailOf(None) is None


def test_whois_domain_icann():
    rec = whois.parseDomain("microsoft.com", load("whois_microsoft.com.json")["data"])
    assert rec["asof"] == ms(2026, 9, 17, 16, 47, 14)
    assert rec["created"] == ms(1991, 5, 2, 4)
    assert rec["updated"] == ms(2026, 1, 29, 18, 46, 57)
    assert rec["expires"] == ms(2027, 5, 3, 4)
    assert rec["registrar"] == {
        "name": "MarkMonitor Inc.",
        "url": "http://www.markmonitor.com",
        "whois": "whois.markmonitor.com",
        "ianaid": "292",
        "email": "abusecomplaints@markmonitor.com",
        "phone": "+1.2086851750",
    }
    assert rec["registrant"] == "Microsoft Corporation"
    assert "clientDeleteProhibited" in rec["status"]
    assert rec["nameservers"] == [
        "ns1-39.azure-dns.com",
        "ns2-39.azure-dns.net",
        "ns3-39.azure-dns.org",
        "ns4-39.azure-dns.info",
    ]
    assert rec["dnssec"] == "unsigned"
    types = [c["type"] for c in rec["contacts"]]
    assert types == ["registrant", "tech"]
    registrant = rec["contacts"][0]
    assert registrant["orgname"] == "Microsoft Corporation"
    assert registrant["city"] == "Redmond"
    assert registrant["country"] == "US"
    assert registrant["address"] == "One Microsoft Way"
    assert registrant["email"] and registrant["email"] in rec["emails"]


def test_whois_domain_redacted():
    rec = whois.parseDomain("example.org", load("whois_example.org.json")["data"])
    assert rec["registrant"] == "ICANN"
    assert rec["registrar"]["url"] is None
    assert rec["registrar"]["whois"] is None
    assert rec["contacts"] == [
        {
            "type": "registrant",
            "id": None,
            "name": None,
            "orgname": "ICANN",
            "address": None,
            "city": None,
            "state": "CA",
            "postalcode": None,
            "country": "US",
            "phone": None,
            "fax": None,
            "email": None,
        }
    ]
    assert rec["emails"] == []

    rec = whois.parseDomain("vertex.link", load("whois_vertex.link.json")["data"])
    assert rec["asof"] == ms(2026, 11, 3, 4, 48, 3, 699000)
    assert rec["registrar"]["name"] == "NAMECHEAP"
    assert rec["contacts"] == []


def test_whois_domain_sectioned():
    # Nominet's .uk records are sections of indented values.
    rec = whois.parseDomain("bbc.co.uk", load("whois_bbc.co.uk.json")["data"])
    assert rec["asof"] == ms(2025, 4, 28, 11, 32, 37)
    assert rec["created"] is None  # "before Aug-1996"
    assert rec["updated"] == ms(2020, 12, 10)
    assert rec["expires"] == ms(2025, 12, 13)
    assert rec["registrar"]["name"] == "British Broadcasting Corporation"
    assert rec["registrar"]["url"] == "https://www.bbc.co.uk"
    assert rec["nameservers"][:2] == ["ddns0.bbc.co.uk", "ddns0.bbc.com"]
    assert len(rec["nameservers"]) == 8

    # DENIC's .de records are terse.
    rec = whois.parseDomain("google.de", load("whois_google.de.json")["data"])
    assert rec["nameservers"] == [f"ns{i}.google.com" for i in range(1, 5)]
    assert rec["updated"] == ms(2018, 3, 12, 20, 44, 25)
    assert rec["status"] == ["connect"]
    assert rec["asof"] is None
    assert rec["registrar"]["name"] is None


def test_whois_domain_misc():
    text = "\n".join(
        (
            "Domain Name: x.com",
            "Registrar URL: www.registrar.example",
            "Registrar WHOIS Server: whois://whois.registrar.example/",
            "Registrant Street: 1 Main St",
            "Registrant Street: Suite 2",
            "Registrant Country: USA",
            "Registrant Phone Ext: 5",
            "Tech Email: tech@x.com",
            "Name Server: http://not-a-ns",
            "% a comment",
        )
    )
    rec = whois.parseDomain("x.com", text)
    assert rec["registrar"]["url"] == "http://www.registrar.example"
    assert rec["registrar"]["whois"] == "whois.registrar.example"
    assert rec["contacts"][0]["address"] == "1 Main St, Suite 2"
    assert rec["contacts"][0]["country"] is None
    assert rec["contacts"][1] == {**rec["contacts"][1], "type": "tech", "email": "tech@x.com"}
    assert rec["emails"] == ["tech@x.com"]
    assert rec["nameservers"] == []
    assert rec["registrant"] is None


def test_whois_asn_arin():
    rec = whois.parseAsn(15169, load("whois_as15169.json")["data"])
    assert rec["registry"] == "arin"
    assert rec["name"] == "GOOGLE"
    assert rec["handle"] == "AS15169"
    assert rec["orgname"] == "Google LLC"
    assert rec["orgid"] == "GOGL"
    assert rec["country"] == "US"
    assert rec["address"] == "1600 Amphitheatre Parkway, Mountain View, CA, 94043"
    assert rec["created"] == ms(2000, 3, 30)
    assert rec["updated"] == ms(2012, 2, 24)
    assert rec["contacts"][0] == {
        "type": "abuse",
        "handle": "ABUSE5250-ARIN",
        "name": "Abuse",
        "email": "network-abuse@google.com",
        "phone": "+1-650-253-0000",
    }
    assert rec["emails"][:2] == ["network-abuse@google.com", "arin-contact@google.com"]
    assert "Google Team" in rec["desc"]

    # ASNs in a block (8068 - 8075) match the block's record.
    rec = whois.parseAsn(8075, load("whois_as8075.json")["data"])
    assert rec["name"] == "MICROSOFT-CORP-MSN-AS-BLOCK"
    assert rec["handle"] == "AS8068"
    assert "abuse@microsoft.com" in rec["emails"]


def test_whois_asn_rpsl():
    rec = whois.parseAsn(3333, load("whois_as3333.json")["data"])
    assert rec["registry"] == "ripe"
    assert rec["name"] == "RIPE-NCC-AS"
    assert rec["orgid"] == "ORG-RIEN1-RIPE"
    assert rec["orgname"] == "Reseaux IP Europeens Network Coordination Centre (RIPE NCC)"
    assert rec["country"] == "NL"
    assert rec["status"] == "ASSIGNED"
    assert rec["contacts"][0]["type"] == "abuse"
    assert rec["contacts"][0]["email"] == "abuse@ripe.net"
    assert rec["emails"][0] == "abuse@ripe.net"

    rec = whois.parseAsn(4608, load("whois_as4608.json")["data"])
    assert rec["registry"] == "apnic"
    assert rec["orgname"] == "Asia Pacific Network Information Centre"
    assert rec["country"] == "AU"
    assert ",," not in rec["address"]
    # The mnt-irt object is an abuse contact too.
    assert {"abuse"} == {
        c["type"] for c in rec["contacts"] if c["handle"].startswith(("AA", "IRT"))
    }

    # AFRINIC values have "# Filtered" comments and tel: phones.
    rec = whois.parseAsn(37100, load("whois_as37100.json")["data"])
    assert rec["registry"] == "afrinic"
    assert rec["orgname"] == "SEACOM Limited"
    assert rec["country"] == "MU"
    assert all(not (c["phone"] or "").startswith("tel:") for c in rec["contacts"])
    assert "abuse@seacom.mu" in rec["emails"]

    # LACNIC's aut-num has the owner and its text is double encoded by bgp.he.net.
    rec = whois.parseAsn(28000, whois.fixText(load("whois_as28000.json")["data"]))
    assert rec["registry"] == "lacnic"
    assert rec["name"] is None
    assert rec["orgname"] == "LACNIC - Latin American and Caribbean IP address"
    assert rec["orgid"] == "UY-LACN-LACNIC"
    assert rec["created"] == ms(2005, 10, 5)
    assert rec["updated"] == ms(2024, 9, 17)
    assert rec["address"].startswith("Rambla República de México")
    assert rec["contacts"][0]["name"] == "Carlos M Martínez"


def test_whois_asn_missing():
    rec = whois.parseAsn(1, "% no entries found\n\naut-num: AS2\nas-name: OTHER\n")
    assert rec["name"] is None and rec["registry"] is None
    rec = whois.parseAsn(5, "aut-num: AS5\nas-name: FIVE\nowner: Five Inc\ncountry: usa\n")
    assert rec["registry"] == "lacnic"
    assert rec["country"] is None
    rec = whois.parseAsn(5, "ASNumber: 6\nASName: SIX\n")
    assert rec["name"] == "SIX"
    assert whois.blocks("key: value\n continued\n+ more\n") == [[("key", "value continued more")]]


def test_cert_extensions():
    # A certificate with every extension, SAN type, and attribute the parser handles.
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
    from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID

    import ipaddress

    issuerkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "admin@example.com"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example"),
            x509.NameAttribute(x509.ObjectIdentifier("1.2.3.4"), "custom"),
        ]
    )
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Example CA")])
    uri = "http://example.com/x"
    der = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(12345)
        .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("*.example.com"),
                    x509.RFC822Name("User@Example.com"),
                    x509.UniformResourceIdentifier(uri),
                    x509.IPAddress(ipaddress.ip_address("1.2.3.4")),
                    x509.IPAddress(ipaddress.ip_address("::1")),
                    x509.DirectoryName(issuer),
                    x509.RegisteredID(x509.ObjectIdentifier("1.2.3")),
                    x509.OtherName(x509.ObjectIdentifier("1.2.3.5"), b"\x04\x00"),
                ]
            ),
            False,
        )
        .add_extension(
            x509.KeyUsage(True, False, False, False, True, False, False, True, False), True
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuerkey.public_key()), False
        )
        .add_extension(
            x509.CRLDistributionPoints(
                [x509.DistributionPoint([x509.UniformResourceIdentifier(uri)], None, None, None)]
            ),
            False,
        )
        .add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(uri)
                    ),
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(uri),
                    ),
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP, x509.DNSName("ocsp.example.com")
                    ),
                ]
            ),
            False,
        )
        .add_extension(
            x509.CertificatePolicies(
                [x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), None)]
            ),
            False,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(certs.PRECERT_POISON_OID), b"\x05\x00"
            ),
            True,
        )
        .sign(issuerkey, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )

    c = certs.parseCert(der)
    assert c["pubkey"]["algo"] == "ed25519" and c["pubkey"]["size"] == 256
    assert c["subject"]["attrs"] == {
        "cn": ["admin@example.com"],
        "o": ["Example"],
        "1.2.3.4": ["custom"],
    }
    kinds = [kind for kind, _ in c["sans"]]
    assert kinds == ["dns", "email", "uri", "ip", "ip", "dirname", "registeredid", "othername"]
    assert c["keyusage"] == ["digital_signature", "key_agreement", "encipher_only"]
    assert c["extkeyusage"] == [{"oid": "1.3.6.1.5.5.7.3.1", "name": "serverAuth"}]
    assert c["ski"] and c["aki"] and c["ski"] != c["aki"]
    assert c["crls"] == [uri] and c["ocsp"] == [uri] and c["caissuers"] == [uri]
    assert c["policies"] == ["2.23.140.1.2.1"]
    assert c["precert"] is True
    assert c["selfsigned"] is False
    assert c["identities"] == {
        "fqdns": ["example.com"],
        "emails": ["admin@example.com", "user@example.com"],
        "ipv4s": ["1.2.3.4"],
        "ipv6s": ["::1"],
        "urls": [uri],
    }


def test_cert_keys():
    from cryptography.hazmat.primitives.asymmetric import dsa, ed448

    for key, algo in (
        (dsa.generate_private_key(2048), "dsa"),
        (ed448.Ed448PrivateKey.generate(), "ed448"),
    ):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "k.example.com")])
        algorithm = None if algo == "ed448" else hashes.SHA256()
        der = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC))
            .not_valid_after(datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC))
            .sign(key, algorithm)
            .public_bytes(serialization.Encoding.DER)
        )
        c = certs.parseCert(der)
        assert c["pubkey"]["algo"] == algo
        assert c["sigalgo"]["hash"] == (None if algo == "ed448" else "sha256")
        assert c["selfsigned"] is True

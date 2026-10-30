"""Pytests for crtshsvc.norm, parsing every certificate detail."""

import datetime
import ipaddress
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, x25519
from cryptography.x509.oid import NameOID

from crtshsvc import norm

from .fakecrtsh import CRL_URL, NOW, PKI, DAY


def details(certid: int) -> dict:
    return norm.certDetails(PKI.row(certid))


def selfSigned(key, signer=None, names=None, sans=None, exts=(), algo=hashes.SHA256()) -> bytes:
    """A minimal self-issued certificate for ``key``, signed by ``signer`` (default ``key``)."""

    signer = signer or key
    subject = x509.Name(names or [x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
               .public_key(key.public_key()).serial_number(1)
               .not_valid_before(NOW - DAY).not_valid_after(NOW + DAY))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    for ext in exts:
        builder = builder.add_extension(ext, critical=False)
    return builder.sign(signer, algo).public_bytes(serialization.Encoding.DER)


def test_leaf():
    leaf = details(10)
    assert leaf["sha256"] == PKI.sha256(10)
    assert len(leaf["sha1"]) == 40 and len(leaf["md5"]) == 32
    assert leaf["version"] == 2
    assert leaf["serial"] == "5a0b1c2d3e4f"
    assert leaf["subject"]["dn"] == "CN=www.vertex.link,OU=Engineering,O=The Vertex Project,C=US"
    assert leaf["subject"]["attrs"] == {
        "c": ["US"], "o": ["The Vertex Project"], "ou": ["Engineering"], "cn": ["www.vertex.link"],
    }
    assert len(leaf["subject"]["sha1"]) == 40
    assert leaf["issuer"]["attrs"]["cn"] == ["Test Issuing CA 1"]
    assert leaf["notbefore"] == int((NOW - 10 * DAY).timestamp() * 1000)
    assert leaf["notafter"] == int((NOW + 80 * DAY).timestamp() * 1000)
    assert leaf["sigalgo"] == {"oid": "1.2.840.10045.4.3.2", "name": "ecdsa-with-SHA256",
                               "hash": "sha256"}
    assert leaf["signature"]
    assert leaf["pubkey"]["algo"] == "ec"
    assert leaf["pubkey"]["curve"] == "secp256r1"
    assert leaf["pubkey"]["size"] == 256
    assert len(leaf["pubkey"]["sha256"]) == 64 and len(leaf["pubkey"]["sha1"]) == 40
    assert leaf["selfsigned"] is False
    assert leaf["precert"] is False
    assert leaf["ca"] is False and leaf["pathlen"] is None
    assert leaf["keyusage"] == ["digital_signature", "key_agreement", "encipher_only", "decipher_only"]
    assert [e["name"] for e in leaf["extkeyusage"]] == ["serverAuth", "clientAuth"]
    assert leaf["ski"] and leaf["aki"] and leaf["ski"] != leaf["aki"]
    assert leaf["crls"] == [CRL_URL]
    assert leaf["ocsp"] == ["http://ocsp.test.example"]
    assert leaf["caissuers"] == ["http://ca.test.example/i1.der"]
    assert leaf["policies"] == ["2.23.140.1.2.2"]
    assert leaf["mustStaple"] is True
    assert len(leaf["scts"]) == 2
    assert leaf["scts"][0] == {"logid": "01" * 32, "time": int(NOW.timestamp() * 1000), "version": "v1"}
    assert ("dns", "*.vertex.link") in leaf["sans"]
    assert ("ip", "2001:db8::1") in leaf["sans"]
    assert leaf["identities"] == {
        "fqdns": ["vertex.link", "www.vertex.link"],
        "emails": ["visi@vertex.link"],
        "ipv4s": ["1.2.3.4"],
        "ipv6s": ["2001:db8::1"],
        "urls": ["https://vertex.link/"],
    }
    assert {e["name"] for e in leaf["extensions"]} >= {"subjectAltName", "basicConstraints"}
    assert leaf["pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert leaf["crtsh"] == {
        "id": 10, "url": "https://crt.sh/?id=10", "issuer": {"id": 2, "name": None},
        "ctlog": [], "logged": None, "revoked": None, "caids": [],
    }


def test_certs():
    assert details(9)["precert"] is True
    assert any(e["oid"] == norm.PRECERT_POISON_OID for e in details(9)["extensions"])

    root = details(1)
    assert root["selfsigned"] is True
    assert root["ca"] is True and root["pathlen"] == 0
    assert root["pubkey"]["algo"] == "rsa"
    assert root["pubkey"]["rsa"]["exp"] == 65537
    assert len(root["pubkey"]["rsa"]["mod"]) == 512
    assert root["sigalgo"]["name"] == "sha256WithRSAEncryption"

    expired = details(12)["pubkey"]
    assert (expired["algo"], expired["size"]) == ("ed25519", 256)

    junk = details(13)
    assert junk["error"].startswith("Unable to parse certificate")
    assert junk["pem"].startswith("-----BEGIN CERTIFICATE-----\n")
    assert junk["crtsh"]["id"] == 13
    assert "subject" not in junk


def test_keys():
    dsakey = dsa.generate_private_key(key_size=2048)
    signer = ec.generate_private_key(ec.SECP256R1())
    assert norm.parseCert(selfSigned(dsakey, signer))["pubkey"]["algo"] == "dsa"

    edkey = ed448.Ed448PrivateKey.generate()
    pubkey = norm.parseCert(selfSigned(edkey, signer))["pubkey"]
    assert pubkey["algo"] == "ed448" and pubkey["size"] == 456

    # A key type that can't sign, and isn't otherwise described.
    xkey = x25519.X25519PrivateKey.generate()
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
               .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
               .public_key(xkey.public_key()).serial_number(1)
               .not_valid_before(NOW - DAY).not_valid_after(NOW + DAY))
    der = builder.sign(signer, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    pubkey = norm.parseCert(der)["pubkey"]
    assert pubkey["algo"] is None and pubkey["sha256"]

    # Ed25519 signatures have no separate hash algorithm.
    edsigner = ed25519.Ed25519PrivateKey.generate()
    assert norm.parseCert(selfSigned(edsigner, algo=None))["sigalgo"]["hash"] is None

    # A key type cryptography can't load.
    cert = mock.Mock()
    cert.public_key.side_effect = ValueError("unsupported")
    assert norm.normPublicKey(cert) == {"algo": None, "size": None}


def test_names_and_sans():
    key = ec.generate_private_key(ec.SECP256R1())
    names = [
        x509.NameAttribute(NameOID.COMMON_NAME, "visi@vertex.link"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "Admin@Vertex.Link"),
        x509.NameAttribute(NameOID.X500_UNIQUE_IDENTIFIER, b"\x01\x02",
                           _type=x509.name._ASN1Type.BitString),
        x509.NameAttribute(x509.ObjectIdentifier("1.2.3.4"), "custom"),
    ]
    sans = [
        x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dir")])),
        x509.RegisteredID(x509.ObjectIdentifier("1.2.3.4.5")),
        x509.OtherName(x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"), b"\x0c\x03abc"),
        x509.DNSName("Bad Name"),
        x509.DNSName("nodots"),
    ]
    info = norm.parseCert(selfSigned(key, names=names, sans=sans))
    assert info["subject"]["attrs"]["email"] == ["Admin@Vertex.Link"]
    assert info["subject"]["attrs"]["2.5.4.45"] == ["0102"]
    assert info["subject"]["attrs"]["1.2.3.4"] == ["custom"]
    assert ("dirname", "CN=dir") in info["sans"]
    assert ("registeredid", "1.2.3.4.5") in info["sans"]
    assert ("othername", "1.3.6.1.4.1.311.20.2.3:0c03616263") in info["sans"]
    assert info["identities"]["emails"] == ["admin@vertex.link", "visi@vertex.link"]
    assert info["identities"]["fqdns"] == []
    # No basic constraints.
    assert info["ca"] is None

    # An IP address common name.
    info = norm.parseCert(selfSigned(key, names=[x509.NameAttribute(NameOID.COMMON_NAME, "10.0.0.1")],
                                     sans=[x509.IPAddress(ipaddress.ip_address("10.0.0.2"))]))
    assert info["identities"]["ipv4s"] == ["10.0.0.1", "10.0.0.2"]


def test_identities():
    subject = {"attrs": {"cn": ["*.Example.COM."]}}
    sans = [("dns", "a.example.com"), ("dns", "*"), ("ip", "not an ip"), ("uri", "ldap://x"),
            ("dirname", "CN=x")]
    assert norm.identities(sans, subject) == {
        "fqdns": ["a.example.com", "example.com"], "emails": [], "ipv4s": [], "ipv6s": [],
        "urls": ["ldap://x"],
    }


def test_other_extensions():
    key = ec.generate_private_key(ec.SECP256R1())
    dirname = x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "crl")]))
    exts = [
        x509.CRLDistributionPoints([x509.DistributionPoint([dirname], None, None, None)]),
        x509.AuthorityInformationAccess([x509.AccessDescription(
            x509.ObjectIdentifier("1.3.6.1.5.5.7.48.5"), x509.UniformResourceIdentifier("http://x"))]),
        x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4.5"), b"\x05\x00"),
        x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                      data_encipherment=False, key_agreement=True, key_cert_sign=False,
                      crl_sign=False, encipher_only=False, decipher_only=False),
    ]
    info = norm.parseCert(selfSigned(key, exts=exts))
    assert info["crls"] == [] and info["ocsp"] == [] and info["caissuers"] == []
    assert {"oid": "1.2.3.4.5", "name": "1.2.3.4.5", "critical": False} in info["extensions"]
    assert info["keyusage"] == ["key_agreement"]


def test_bad_extensions():
    # A malformed extension makes cryptography refuse to list any of them.
    cert = mock.Mock()
    type(cert).extensions = mock.PropertyMock(side_effect=x509.DuplicateExtension("dup", None))
    exts = norm.normExtensions(cert)
    assert exts["extensions"] == [] and exts["sans"] == []

    # A signature algorithm cryptography doesn't know the hash of.
    cert = mock.Mock()
    cert.signature_algorithm_oid = x509.ObjectIdentifier("1.2.3.4")
    type(cert).signature_hash_algorithm = mock.PropertyMock(side_effect=Exception("unsupported"))
    assert norm._sigAlgo(cert) == {"oid": "1.2.3.4", "name": "1.2.3.4", "hash": None}


def test_helpers():
    assert norm.toMillis(None) is None
    assert norm.toMillis(datetime.datetime(1970, 1, 1, 0, 0, 1)) == 1000
    assert norm.hexBytes(None) is None
    assert norm.hexBytes(b"\x0a\xff") == "0aff"

    assert norm.serialHex(0xabc) == "0abc"
    assert norm.serialHex(0xabcd) == "abcd"
    assert norm.serialHex(-1) == "ff"
    assert norm.serialHex(-129) == "ff7f"

    assert norm.serialBytes(0xabc) == b"\x0a\xbc"
    assert norm.serialBytes("0x0A:BC") == b"\x0a\xbc"
    assert norm.serialBytes("abc") == b"\x0a\xbc"
    assert norm.normHex(" AB:cd ef ") == "abcdef"

    assert norm.certTime({"notbefore": 5}) == -5
    assert norm.certTime({}) == 0

    assert norm.revocation({"reason_code": 1, "revocation_date": datetime.datetime(1970, 1, 1)}) == {
        "time": 0, "reason": "keyCompromise", "code": 1}
    assert norm.revocation({"reason_code": 99})["reason"] == "99"
    assert norm.revocation({})["reason"] is None

    assert norm.ctlogEntry({"log_name": "A", "log_url": "u", "log_operator": "o", "entry_id": 1,
                            "entry_timestamp": datetime.datetime(1970, 1, 1)}) == {
        "log": "A", "url": "u", "operator": "o", "index": 1, "time": 0}


def test_matches():
    leaf = details(10)
    assert norm.matches(leaf, "dns", "vertex.link", "suffix")
    assert norm.matches(leaf, "dns", "VERTEX.LINK", "exact")
    assert norm.matches(leaf, "dns", "foo.vertex.link", "suffix") is False
    assert norm.matches(leaf, "dns", "ertex.link", "suffix") is False
    assert norm.matches(details(14), "dns", "vertex.link", "suffix") is False  # notvertex.link
    assert norm.matches(leaf, "cn", "www", "contains")
    assert norm.matches(leaf, "org", "the vertex project", "exact")
    assert norm.matches(leaf, "ou", "engineer", "contains")
    assert norm.matches(leaf, "email", "visi@vertex.link", "exact")
    assert norm.matches(leaf, "ip", "1.2.3.4", "exact")
    assert norm.matches(leaf, "uri", "vertex.link", "contains")
    assert norm.matches(leaf, "subject", "o=the vertex project", "contains")
    assert norm.matches(leaf, "identity", "engineering", "exact")
    assert norm.matches(leaf, "identity", "nope", "contains") is False

    # Unparsed certificates have no fields.
    assert norm.fieldValues(details(13), "dns") == []
    with pytest.raises(ValueError):
        norm.fieldValues(leaf, "nope")

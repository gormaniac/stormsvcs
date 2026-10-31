"""Pytests for the slib.crtsh service that don't need the crt.sh database."""

import datetime
import pathlib
import tomllib

import synapse.tests.utils as s_tests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from crtshsvc import CrtshSvc, __version__, norm
from crtshsvc.defs import PKGDEFS, SVC_GUID, SVC_NAME


def makeCert() -> bytes:
    """A self-signed DER certificate with a few SANs."""

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "vertex.link"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "The Vertex Project"),
        ]
    )
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x8A0B)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("*.vertex.link"),
                    x509.DNSName("vertex.link"),
                    x509.RFC822Name("visi@vertex.link"),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class TestCrtshNorm:
    def test_parse(self):
        der = makeCert()
        details = norm.certDetails({"id": 1, "issuer_ca_id": 2, "der": der})
        assert details["serial"] == "8a0b"
        assert details["subject"]["attrs"]["o"] == ["The Vertex Project"]
        assert ("dns", "*.vertex.link") in details["sans"]
        assert details["identities"]["fqdns"] == ["vertex.link"]
        assert details["identities"]["emails"] == ["visi@vertex.link"]
        assert details["ca"] is True
        assert details["selfsigned"] is True
        assert details["pubkey"]["algo"] == "ec"
        assert details["crtsh"]["url"] == "https://crt.sh/?id=1"

        assert norm.matches(details, "dns", "vertex.link", "suffix")
        assert norm.matches(details, "org", "vertex", "contains")
        assert not norm.matches(details, "org", "vertex", "exact")

    def test_parse_error(self):
        details = norm.certDetails({"id": 1, "issuer_ca_id": 2, "der": b"junk"})
        assert details["error"]
        assert details["sha256"]


class TestCrtshStormPkg(s_tests.SynTest):
    def test_versions_match(self):
        pyproject = pathlib.Path(__file__).parent.parent / "pyproject.toml"
        with pyproject.open("rb") as fd:
            assert tomllib.load(fd)["project"]["version"] == __version__
        assert PKGDEFS[0]["version"] == __version__

    async def test_pkg(self):
        async with self.getTestCoreProxSvc(CrtshSvc) as (core, prox, svc):
            msgs = await core.stormlist("service.list")
            self.stormIsInPrint(f"true (svc) ({SVC_NAME} @ {__version__})", msgs)

            for cmd in PKGDEFS[0]["commands"]:
                assert cmd["name"] in core.stormcmds
                # The "forms" key is deprecated and removed in Synapse 3.0.0, use "cmdinputs".
                assert "forms" not in cmd, cmd["name"]
                for cmdinput in cmd.get("cmdinputs", ()):
                    assert core.model.form(cmdinput["form"]) is not None, (cmd["name"], cmdinput)

            msgs = await core.stormlist("slib.crtsh.search --help")
            self.stormIsInPrint("Searched for as a DNS name", msgs)
            for mod in PKGDEFS[0]["modules"]:
                self.stormHasNoErr(await core.stormlist(f"$mod = $lib.import({mod['name']})"))

            assert len(await core.nodes(f"meta:source={SVC_GUID}")) == 1
            msgs = await core.stormlist("slib.crtsh.admin.tags")
            self.stormIsInPrint("enabled=true prefix=rep.crtsh", msgs)

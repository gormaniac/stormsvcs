"""Pytests for the slib.bgphe Storm package (commands, modules, modeling, and perms)."""

import base64
import hashlib
import pathlib
import tomllib

import synapse.lib.time as s_time
import synapse.tests.utils as s_tests

from bgphesvc import __version__, norm
from bgphesvc.defs import PKGDEFS, SVC_GUID, SVC_NAME

from . import fakebgphe as fb
from .test_norm import selfSigned

CMDS = tuple(cmd["name"] for cmd in PKGDEFS[0]["commands"])
MODS = tuple(mod["name"] for mod in PKGDEFS[0]["modules"])

USER_PERM = ("slib", "bgphe", "user")

SEEN = f"meta:source={SVC_GUID} -(seen)>"


async def nodeset(core, query, opts=None):
    """Return the set of (form, repr) for the nodes a query lifts."""
    return {(node.form.name, node.repr()) for node in await core.nodes(query, opts=opts)}


async def count(core, query, opts=None):
    return len(await core.nodes(query, opts=opts))


class TestBgpHeStormPkg(s_tests.SynTest):
    def test_versions_match(self):
        # The version lives in pyproject.toml (the image tag), __init__.py, the package yaml,
        # and the service's uv.lock entry.
        root = pathlib.Path(__file__).parent.parent
        with (root / "pyproject.toml").open("rb") as fd:
            assert tomllib.load(fd)["project"]["version"] == __version__
        assert PKGDEFS[0]["version"] == __version__
        with (root / "uv.lock").open("rb") as fd:
            pkgs = tomllib.load(fd)["package"]
        assert [p["version"] for p in pkgs if p["name"] == "bgphesvc"] == [__version__]

    async def test_pkg(self):
        assert len(CMDS) == 6

        async with fb.bgpheSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("service.list")
            self.stormIsInPrint(f"true (svc) ({SVC_NAME} @ {__version__})", msgs)

            for cmd in CMDS:
                assert cmd in core.stormcmds, cmd

            for cdef in PKGDEFS[0]["commands"]:
                assert "forms" not in cdef, cdef["name"]
                for cmdinput in cdef.get("cmdinputs", ()):
                    assert core.model.form(cmdinput["form"]) is not None, (cdef["name"], cmdinput)

            for mod in MODS:
                msgs = await core.stormlist(f"$mod = $lib.import({mod})")
                self.stormHasNoErr(msgs)

            # The service add event creates the meta:source.
            nodes = await core.nodes(f"meta:source={SVC_GUID}")
            assert len(nodes) == 1
            assert nodes[0].get("name") == "bgp.he.net"
            assert nodes[0].get("type") == "slib.bgphe"
            assert nodes[0].get("url") == "https://bgp.he.net"

            # No request is made until a command is run.
            assert fake.requests == []

    async def test_certs(self):
        async with fb.bgpheSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.bgphe.certs gormo.co")
            self.stormHasNoWarnErr(msgs)
            nodes = [m[1] for m in msgs if m[0] == "node"]
            assert len(nodes) == 12
            assert all(n[0][0] == "crypto:x509:cert" for n in nodes)

            item = fake.state["certs"]["gormo.co"][0]
            sha256 = hashlib.sha256(base64.b64decode(item["certificate_der"])).hexdigest()
            nodes = await core.nodes(f"crypto:x509:cert:sha256={sha256}")
            assert len(nodes) == 1
            node = nodes[0]
            assert node.get("sha256") and node.get("sha1") and node.get("md5")
            assert node.get("file") == f"sha256:{node.get('sha256')}"
            assert node.get("serial")
            assert node.get("issuer").startswith("CN=")
            assert node.get("version") == 2
            data = await node.getData("slib:bgphe")
            assert node.get("algo") == data["sigalgo"]["oid"]
            assert node.get("signature")
            assert node.get("selfsigned") == 0
            assert node.get("identities:fqdns") == ("gormo.co",)
            assert ("dns", "gormo.co") in node.get("ext:sans")
            assert (node.get("rsa:key") is not None) == (data["pubkey"]["algo"] == "rsa")
            data = await node.getData("slib:bgphe")
            assert data["he"]["id"] == item["id"]
            assert list(data["he"]["shards"]) == item["shards"]
            assert data["sha256"] == node.get("sha256")
            # .seen covers when bgp.he.net saw it logged.
            assert node.get(".seen")[0] == item["timestamp"]

            assert await count(core, f"{SEEN} crypto:x509:cert") == 12
            assert await count(core, "crypto:x509:cert +:rsa:key") > 0
            assert await count(core, "crypto:x509:cert -(refs)> crypto:key") == 12
            # The same key was reused across several renewals.
            assert await count(core, "crypto:key") < 12
            assert await count(core, f"{SEEN} crypto:key") == await count(core, "crypto:key")
            assert await count(core, "crypto:x509:cert:identities:fqdns*[=www.gormo.co]") == 10

            # The precertificate (a bare TBSCertificate) has no fingerprints.
            nodes = await core.nodes("crypto:x509:cert -:sha256")
            assert len(nodes) == 1
            assert nodes[0].get("subject") == "CN=gormo.co"
            assert nodes[0].get("serial")
            assert nodes[0].get("file") is None
            data = await nodes[0].getData("slib:bgphe")
            assert data["precert"] is True and data["tbs"]

            # Lookups are idempotent.
            msgs = await core.stormlist("slib.bgphe.certs gormo.co")
            self.stormHasNoWarnErr(msgs)
            assert await count(core, "crypto:x509:cert") == 12

            # Inbound nodes, filtered.
            await core.nodes("crypto:x509:cert | delnode --force")
            msgs = await core.stormlist("[ inet:fqdn=gormo.co ] | slib.bgphe.certs --no-precerts")
            self.stormHasNoWarnErr(msgs)
            assert [m[1][0] for m in msgs if m[0] == "node"] == [("inet:fqdn", "gormo.co")]
            assert await count(core, "crypto:x509:cert") == 11

            nodes = await core.nodes("inet:fqdn=gormo.co | slib.bgphe.certs --yield")
            assert len(nodes) == 12
            assert all(n.form.name == "crypto:x509:cert" for n in nodes)

            # Only the self-signed certificate (valid until 2099) is valid.
            fake.state["certs"]["mix.com"] = [
                fake.state["certs"]["gormo.co"][3],
                {"certificate_der": base64.b64encode(selfSigned()).decode()},
            ]
            nodes = await core.nodes("slib.bgphe.certs mix.com --valid")
            assert [n.get("subject") for n in nodes] == ["CN=test.example.com"]
            assert nodes[0].get("selfsigned") == 1

            # Another domain's certificates (an EC key and wildcards).
            nodes = await core.nodes("slib.bgphe.certs google.com")
            assert len(nodes) == 2
            assert await count(core, "crypto:x509:cert:subject='CN=*.google.com' +:sha256") == 1
            assert await count(core, "crypto:x509:cert:identities:fqdns*[=google.com]") == 2

    async def test_certs_msgs(self):
        async with fb.bgpheSvc(self) as (core, svc, fake):
            fake.state["pagesize"] = 5
            msgs = await core.stormlist("slib.bgphe.certs gormo.co --limit 3")
            self.stormIsInPrint(
                "slib.bgphe: Modeled 3 of the 12 certificates for gormo.co, raise --limit for more.",
                msgs,
            )
            assert len([m for m in msgs if m[0] == "node"]) == 3

            msgs = await core.stormlist("slib.bgphe.certs nope.com")
            self.stormIsInWarn("slib.bgphe: bgp.he.net has no matching certificates for nope.com.", msgs)

            msgs = await core.stormlist("slib.bgphe.certs 'bad domain'")
            self.stormIsInWarn(
                "slib.bgphe: Looking up the certificates of bad domain failed: Invalid domain: 'bad domain'",
                msgs,
            )
            self.stormHasNoErr(msgs)

            fake.state["errors"]["/certs/api/domain"] = [400]
            msgs = await core.stormlist("[ inet:fqdn=gormo.co ] | slib.bgphe.certs")
            self.stormIsInWarn("fake error 400", msgs)
            self.stormHasNoErr(msgs)

            msgs = await core.stormlist("[ inet:ipv4=1.2.3.4 ] | slib.bgphe.certs")
            self.stormIsInWarn("slib.bgphe.certs: Unable to look up inet:ipv4 1.2.3.4, it needs an inet:fqdn.", msgs)
            assert [m[1][0][0] for m in msgs if m[0] == "node"] == ["inet:ipv4"]

            msgs = await core.stormlist("$lib.debug = (true) slib.bgphe.certs gormo.co --limit 2")
            self.stormIsInPrint("slib.bgphe: gormo.co: 2 certificates (0 filtered) from 1 pages, of 12", msgs)

    async def test_subdomains(self):
        async with fb.bgpheSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.bgphe.certs.subdomains gormo.co --print")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("4 domains with 27 certificates under gormo.co:", msgs)
            self.stormIsInPrint("url.gormo.co", msgs)
            assert [m[1][0][1] for m in msgs if m[0] == "node"] == [
                "url.gormo.co",
                "gormo.co",
                "www.gormo.co",
                "docs.gormo.co",
            ]
            assert await count(core, f"{SEEN} inet:fqdn") == 4

            nodes = await core.nodes("[ inet:fqdn=gormo.co ] | slib.bgphe.certs.subdomains")
            assert [n.repr() for n in nodes] == ["gormo.co"]
            nodes = await core.nodes("inet:fqdn=gormo.co | slib.bgphe.certs.subdomains --yield")
            assert len(nodes) == 4

            # Subdomains pipe into the certificate lookups.
            nodes = await core.nodes(
                "inet:fqdn=gormo.co | slib.bgphe.certs.subdomains --yield | +inet:fqdn=gormo.co "
                "| slib.bgphe.certs --yield"
            )
            assert len(nodes) == 12

            msgs = await core.stormlist("slib.bgphe.certs.subdomains nope.com")
            self.stormIsInWarn("bgp.he.net has no certificates for nope.com or its subdomains.", msgs)
            self.stormHasNoErr(msgs)

            fake.state["certlist"]["big.com"] = {
                "domains": [{"domain": "a.big.com", "certificate_count": 1}],
                "truncated": True,
                "total_certificates": 1,
            }
            msgs = await core.stormlist("slib.bgphe.certs.subdomains big.com")
            self.stormIsInWarn("bgp.he.net truncated the subdomains of big.com, some may be missing.", msgs)

            msgs = await core.stormlist("slib.bgphe.certs.subdomains bad")
            self.stormIsInWarn("Looking up the subdomains of bad failed: Invalid domain: 'bad'", msgs)
            self.stormHasNoErr(msgs)

            msgs = await core.stormlist("[ inet:ipv4=1.2.3.4 ] | slib.bgphe.certs.subdomains")
            self.stormIsInWarn("it needs an inet:fqdn.", msgs)

    async def test_hosts(self):
        async with fb.bgpheSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.bgphe.certs.ip 8.8.8.0/24 --print")
            self.stormIsInWarn(
                "slib.bgphe: bgp.he.net only returned a sample of the 73882 certificate hostnames on 8.8.8.0/24.",
                msgs,
            )
            self.stormIsInPrint("8.8.8.4: sabievtimbers.co.za, test.radium.red", msgs)
            self.stormHasNoErr(msgs)
            assert await count(core, "inet:dns:a") == 9
            assert await count(core, f"{SEEN} inet:dns:a") == 9
            assert await count(core, "inet:dns:a:ipv4=8.8.8.4") == 2
            assert await count(core, "inet:dns:a:fqdn=wild.example.com") == 1

            hosts = fake.state["prefix"]["2001:4860:4860::8888/128"]["entries"][0]["hostnames"]
            nv6 = len({norm.normFqdn(h) for h in hosts} - {None})
            nodes = await core.nodes("slib.bgphe.certs.ip 2001:4860:4860::8888")
            assert len(nodes) == nv6
            assert all(n.form.name == "inet:dns:aaaa" for n in nodes)

            # Inbound IPs and CIDRs.
            await core.nodes("inet:dns:a inet:dns:aaaa | delnode --force")
            nodes = await core.nodes("[ inet:cidr4=8.8.8.0/24 ] | slib.bgphe.certs.ip")
            assert [n.ndef for n in nodes] == [("inet:cidr4", "8.8.8.0/24")]
            assert await count(core, "inet:dns:a") == 9

            nodes = await core.nodes("[ inet:ipv6=2001:4860:4860::8888 ] | slib.bgphe.certs.ip --yield | -> inet:fqdn")
            assert len(nodes) == nv6

            msgs = await core.stormlist("[ inet:ipv4=10.0.0.1 ] | slib.bgphe.certs.ip")
            self.stormIsInWarn("bgp.he.net has no certificate hostnames on 10.0.0.1/32.", msgs)
            self.stormHasNoErr(msgs)

            msgs = await core.stormlist("slib.bgphe.certs.ip nope")
            self.stormIsInWarn("Looking up the certificate hostnames on nope failed: Invalid IP or CIDR: 'nope'", msgs)
            self.stormHasNoErr(msgs)

            msgs = await core.stormlist("[ inet:fqdn=x.com ] | slib.bgphe.certs.ip")
            self.stormIsInWarn("slib.bgphe.certs.ip: Unable to look up inet:fqdn x.com, it needs an IP or CIDR.", msgs)

    async def test_whois(self):
        async with fb.bgpheSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.bgphe.whois microsoft.com")
            self.stormHasNoWarnErr(msgs)
            nodes = await core.nodes("inet:whois:rec")
            assert len(nodes) == 1
            rec = nodes[0]
            assert rec.get("fqdn") == "microsoft.com"
            assert rec.get("asof") == s_time.parse("2026-09-17 16:47:14")
            assert rec.get("created") == s_time.parse("1991-05-02 04:00:00")
            assert rec.get("updated") == s_time.parse("2026-01-29 18:46:57")
            assert rec.get("expires") == s_time.parse("2027-05-03 04:00:00")
            assert rec.get("registrar") == "markmonitor inc."
            assert rec.get("registrant:name") == "microsoft corporation"
            # The model lowercases :text, the node data has the original.
            assert "domain name: microsoft.com" in rec.get("text")
            data = await rec.getData("slib:bgphe")
            assert "Domain Name: MICROSOFT.COM" in data["text"]
            assert data["rec"]["dnssec"] == "unsigned"

            assert await count(core, "inet:whois:rec -> inet:whois:recns") == 4
            assert await count(core, "inet:whois:recns:ns=ns1-39.azure-dns.com") == 1
            # The contacts' emails. (Synapse also adds every email in :text.)
            assert await nodeset(core, f"{SEEN} inet:whois:email") == {
                ("inet:whois:email", ("microsoft.com", "admin@domains.microsoft")),
                ("inet:whois:email", ("microsoft.com", "msnhst@microsoft.com")),
            }
            nodes = await core.nodes("inet:whois:contact:type=registrant")
            assert len(nodes) == 1
            assert nodes[0].get("orgname") == "microsoft corporation"
            assert nodes[0].get("name") == "domain administrator"
            assert nodes[0].get("city") == "redmond"
            assert nodes[0].get("country") == "us"
            assert nodes[0].get("email") == "admin@domains.microsoft"
            assert nodes[0].get("phone") == "14258828080"
            nodes = await core.nodes("inet:whois:contact:type=registrar")
            assert nodes[0].get("orgname") == "markmonitor inc."
            assert nodes[0].get("email") == "abusecomplaints@markmonitor.com"
            assert nodes[0].get("url") == "http://www.markmonitor.com"
            assert nodes[0].get("whois:fqdn") == "whois.markmonitor.com"
            assert nodes[0].get("id") == "292"
            assert await count(core, "inet:whois:contact") == 3
            for form in ("inet:whois:rec", "inet:whois:recns", "inet:whois:contact"):
                assert await count(core, f"{SEEN} {form}") == await count(core, form), form

            # Idempotent, the record's asof is from the record.
            await core.nodes("slib.bgphe.whois microsoft.com")
            assert await count(core, "inet:whois:rec") == 1

            # asof falls back to the record's update time, then to now.
            nodes = await core.nodes("slib.bgphe.whois google.de")
            assert nodes[0].get("asof") == s_time.parse("2018-03-12 20:44:25")
            assert await count(core, "inet:whois:rec:fqdn=google.de -> inet:whois:contact") == 0
            fake.state["whoisdns"]["bare.com"] = "Domain: bare.com\n"
            nodes = await core.nodes("slib.bgphe.whois bare.com")
            assert len(nodes) == 1 and nodes[0].get("asof") > s_time.parse("2026-01-01")

            # Inbound nodes and --print.
            msgs = await core.stormlist("[ inet:fqdn=vertex.link ] | slib.bgphe.whois --print")
            self.stormIsInPrint("Domain Name: vertex.link", msgs)
            assert [m[1][0] for m in msgs if m[0] == "node"] == [("inet:fqdn", "vertex.link")]
            nodes = await core.nodes("inet:fqdn=bbc.co.uk | slib.bgphe.whois --yield")
            assert len(nodes) == 0
            nodes = await core.nodes("[ inet:fqdn=bbc.co.uk ] | slib.bgphe.whois --yield")
            assert [n.form.name for n in nodes] == ["inet:whois:rec"]
            assert await count(core, "inet:whois:rec:fqdn=bbc.co.uk -> inet:whois:recns") == 8

            msgs = await core.stormlist("slib.bgphe.whois nope.com")
            self.stormIsInWarn(
                "slib.bgphe: Looking up the whois of nope.com failed: bgp.he.net returned HTTP 400 "
                "for /whois/dns/nope.com: whois unavailable",
                msgs,
            )
            self.stormHasNoErr(msgs)

            msgs = await core.stormlist("[ inet:ipv4=1.2.3.4 ] | slib.bgphe.whois --yield")
            self.stormIsInWarn("it needs an inet:fqdn.", msgs)

    async def test_asn(self):
        async with fb.bgpheSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.bgphe.asn AS15169 --print")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(
                "AS15169 GOOGLE: Google LLC (US), arin, registered 2000-03-30, updated 2012-02-24", msgs
            )
            self.stormIsInPrint("abuse: ABUSE5250-ARIN Abuse network-abuse@google.com +1-650-253-0000", msgs)
            assert [m[1][0] for m in msgs if m[0] == "node"] == [("inet:asn", 15169)]

            nodes = await core.nodes("inet:asn=15169")
            assert nodes[0].get("name") == "google"
            data = await nodes[0].getData("slib:bgphe:whois")
            assert data["rec"]["orgid"] == "GOGL"
            assert "OrgName:        Google LLC" in data["text"]

            nodes = await core.nodes("inet:asn=15169 -> ou:org")
            assert len(nodes) == 1
            assert nodes[0].get("name") == "google llc"
            assert nodes[0].get("country:code") == "us"
            assert await count(core, f"{SEEN} inet:asn") == 1
            assert await count(core, f"{SEEN} ou:org") == 1

            # Orgs are deconflicted by name.
            await core.nodes("slib.bgphe.asn 15169")
            assert await count(core, "ou:org") == 1

            # --yield on inbound nodes yields the orgs.
            nodes = await core.nodes("[ inet:asn=3333 inet:asn=28000 ] | slib.bgphe.asn --yield")
            assert {n.get("name") for n in nodes} == {
                "reseaux ip europeens network coordination centre (ripe ncc)",
                "lacnic - latin american and caribbean ip address",
            }
            nodes = await core.nodes("inet:asn=28000")
            assert nodes[0].get("name") is None
            assert nodes[0].get("owner")

            nodes = await core.nodes("inet:asn=4608 | slib.bgphe.asn")
            assert len(nodes) == 0
            nodes = await core.nodes("[ inet:asn=4608 ] | slib.bgphe.asn")
            assert [n.ndef for n in nodes] == [("inet:asn", 4608)]

            # An ASN record without an org has no owner.
            fake.state["whoisasn"][5] = "aut-num: AS5\nas-name: FIVE\nsource: RIPE\n"
            nodes = await core.nodes("slib.bgphe.asn 5")
            assert nodes[0].get("name") == "five" and nodes[0].get("owner") is None
            nodes = await core.nodes("[ inet:asn=5 ] | slib.bgphe.asn --yield")
            assert nodes == []

            msgs = await core.stormlist("slib.bgphe.asn 99 ASX")
            self.stormIsInWarn(
                "slib.bgphe: Looking up the whois of ASN 99 failed: bgp.he.net returned HTTP 400 "
                "for /whois/as99: unallocated asn",
                msgs,
            )
            self.stormIsInWarn("Looking up the whois of ASN ASX failed: Invalid ASN: 'ASX'", msgs)
            self.stormHasNoErr(msgs)

            msgs = await core.stormlist("[ inet:fqdn=x.com ] | slib.bgphe.asn")
            self.stormIsInWarn("slib.bgphe.asn: Unable to look up inet:fqdn x.com, it needs an inet:asn.", msgs)

    async def test_prefixes(self):
        async with fb.bgpheSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.bgphe.asn.prefixes 15169")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("slib.bgphe: AS15169 originates 4 IPv4 and 2 IPv6 prefixes.", msgs)
            assert len([m for m in msgs if m[0] == "node"]) == 6

            nodes = await core.nodes("inet:asnet4=(15169, 8.8.8.0/24)")
            assert len(nodes) == 1
            assert nodes[0].get("net4:min") == 0x08080800
            assert nodes[0].get(".seen")
            assert await nodes[0].getData("slib:bgphe") == {"count": 1061, "total": 1065}
            assert await count(core, "inet:asnet6:asn=15169") == 2
            assert await count(core, f"{SEEN} inet:asnet4") == 4
            assert await count(core, f"{SEEN} inet:asnet6") == 2

            nodes = await core.nodes("[ inet:asn=15169 ] | slib.bgphe.asn.prefixes")
            assert [n.ndef for n in nodes] == [("inet:asn", 15169)]
            nodes = await core.nodes("inet:asn=15169 | slib.bgphe.asn.prefixes --yield | +inet:asnet4")
            assert len(nodes) == 4

            msgs = await core.stormlist("slib.bgphe.asn.prefixes 99")
            self.stormIsInWarn("slib.bgphe: AS99 doesn't originate any prefixes.", msgs)
            self.stormHasNoErr(msgs)

            msgs = await core.stormlist("slib.bgphe.asn.prefixes nope")
            self.stormIsInWarn("Looking up the prefixes of ASN nope failed: Invalid ASN: 'nope'", msgs)
            self.stormHasNoErr(msgs)

            msgs = await core.stormlist("[ inet:fqdn=x.com ] | slib.bgphe.asn.prefixes")
            self.stormIsInWarn("it needs an inet:asn.", msgs)

    async def test_lib(self):
        async with fb.bgpheSvc(self) as (core, svc, fake):
            q = """
                $bgphe = $lib.import(slib.bgphe.lib)
                $n = (0)
                for $cert in $bgphe.certs(gormo.co, limit=(5)) { $n = ($n + 1) }
                $rec = $bgphe.whois(microsoft.com)
                $asn = $bgphe.asn(15169)
                return(($n, $rec.form(), $asn.asn.repr(), $asn.org.form()))
            """
            assert await core.callStorm(q) == (5, "inet:whois:rec", "15169", "ou:org")

    async def test_perms(self):
        async with fb.bgpheSvc(self) as (core, svc, fake):
            # A user doesn't need service.get, the privileged module handles that.
            user = await core.auth.addUser("user")
            await user.addRule((True, ("node",)))
            await user.addRule((True, USER_PERM))
            noperms = await core.auth.addUser("noperms")
            await noperms.addRule((True, ("node",)))

            queries = (
                "slib.bgphe.certs gormo.co",
                "slib.bgphe.certs.subdomains gormo.co",
                "slib.bgphe.certs.ip 8.8.8.0/24",
                "slib.bgphe.whois microsoft.com",
                "slib.bgphe.asn 15169",
                "slib.bgphe.asn.prefixes 15169",
            )
            for query in queries:
                msgs = await core.stormlist(query, opts={"user": user.iden})
                self.stormHasNoErr(msgs)
                assert any(m[0] == "node" for m in msgs), query
                msgs = await core.stormlist(query, opts={"user": noperms.iden})
                self.stormIsInErr("requires permission: slib.bgphe.user", msgs)

            msgs = await core.stormlist('$lib.service.get("slib.bgphe").whoisAsn(15169)', opts={"user": user.iden})
            self.stormIsInErr("must have permission service.get", msgs)

            # Edits run as the user, so the user needs permission to make them.
            limited = await core.auth.addUser("limited")
            await limited.addRule((True, USER_PERM))
            msgs = await core.stormlist("slib.bgphe.asn 15169", opts={"user": limited.iden})
            self.stormIsInErr("must have permission node.add", msgs)

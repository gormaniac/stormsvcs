"""Pytests for the slib.shodan Storm package (commands, modules, modeling, and perms)."""

import hashlib
import pathlib
import tomllib

import synapse.tests.utils as s_tests

from shodansvc import __version__, norm
from shodansvc.defs import PKGDEFS, SVC_GUID, SVC_NAME

from .fakeshodan import HOST_SSH, SSH_KEY_B64, shodanSvc


CMDS = tuple(cmd["name"] for cmd in PKGDEFS[0]["commands"])
MODS = tuple(mod["name"] for mod in PKGDEFS[0]["modules"])

USER_PERM = ("slib", "shodan", "user")


async def nodeset(core, query):
    """Return the set of (form, repr) for the nodes a query lifts."""
    return {(node.form.name, node.repr()) for node in await core.nodes(query)}


class TestShodanStormPkg(s_tests.SynTest):
    """The package loads and the service registers with the Cortex."""

    def test_versions_match(self):
        # The version lives in pyproject.toml (the image tag), __init__.py, and the package yaml.
        pyproject = pathlib.Path(__file__).parent.parent / "pyproject.toml"
        with pyproject.open("rb") as fd:
            assert tomllib.load(fd)["project"]["version"] == __version__
        assert PKGDEFS[0]["version"] == __version__

    async def test_pkg(self):
        assert len(CMDS) == 30

        async with shodanSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("service.list")
            self.stormIsInPrint(f"true (svc) ({SVC_NAME} @ {__version__})", msgs)

            for cmd in CMDS:
                assert cmd in core.stormcmds, cmd

            for cdef in PKGDEFS[0]["commands"]:
                # The "forms" key is deprecated and removed in Synapse 3.0.0, use "cmdinputs".
                assert "forms" not in cdef, cdef["name"]
                for cmdinput in cdef.get("cmdinputs", ()):
                    assert core.model.form(cmdinput["form"]) is not None, (cdef["name"], cmdinput)

            for mod in MODS:
                msgs = await core.stormlist(f"$mod = $lib.import({mod})")
                self.stormHasNoErr(msgs)

            # The service add event creates the meta:source and default tag settings.
            assert len(await core.nodes(f"meta:source={SVC_GUID}")) == 1
            msgs = await core.stormlist("slib.shodan.admin.tags")
            self.stormIsInPrint("enabled=true prefix=rep.shodan", msgs)


class TestShodanStormHost(s_tests.SynTest):
    async def test_host(self):
        async with shodanSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.shodan.host --ip 8.8.8.8 --yield")
            self.stormHasNoErr(msgs)

            nodes = await core.nodes("inet:ipv4=8.8.8.8")
            assert len(nodes) == 1
            ip = nodes[0]
            assert ip.get("asn") == 15169
            assert ip.get("loc") == "us"
            assert ip.get("latlong") == (37.4056, -122.0775)
            for tag in ("rep.shodan.cloud", "rep.shodan.honeypot"):
                assert tag in ip.tags

            assert await nodeset(core, "inet:ipv4=8.8.8.8 -> inet:server") == {
                ("inet:server", "tcp://8.8.8.8:443"),
                ("inet:server", "udp://8.8.8.8:53"),
            }
            assert len(await core.nodes("inet:server=tcp://8.8.8.8:443 +#rep.shodan.cdn")) == 1
            assert len(await core.nodes("inet:server -> inet:banner")) == 2
            assert len(await core.nodes("inet:asn=15169 :owner -> ou:org +:name='google llc'")) == 1
            assert len(await core.nodes("inet:dns:a=(dns.google, 8.8.8.8)")) == 1

            nodes = await core.nodes(
                "inet:server=tcp://8.8.8.8:443 -(uses)> it:prod:softver +:name"
            )
            assert len(nodes) == 1
            assert nodes[0].get("cpe") == "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"
            assert nodes[0].get("vers") == "1.25.3"
            # The banner's product/version aren't applied to its other CPEs.
            nodes = await core.nodes(
                "it:prod:softver:cpe='cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*'"
            )
            assert len(nodes) == 1
            assert nodes[0].get("name") is None and nodes[0].get("vers") is None

            nodes = await core.nodes(
                "inet:tls:servercert:server=tcp://8.8.8.8:443 -> crypto:x509:cert"
            )
            assert len(nodes) == 1
            assert nodes[0].get("sha256") == "a" * 64
            assert nodes[0].get("identities:fqdns") == ("dns.google",)

            vulnerable = await core.nodes("risk:vulnerable")
            assert {n.get("node") for n in vulnerable} == {
                ("inet:ipv4", 134744072),
                ("inet:server", "tcp://8.8.8.8:443"),
            }
            nodes = await core.nodes("risk:vuln:cve=cve-2021-44228")
            assert len(nodes) == 1
            assert nodes[0].get("desc") == "Log4Shell"

            # Everything is linked back to the service's meta:source.
            assert len(await core.nodes(f"meta:source={SVC_GUID} -(seen)> inet:ipv4")) == 1
            assert len(await core.nodes(f"meta:source={SVC_GUID} -(seen)> inet:server")) == 2

            # Running it again doesn't duplicate guid nodes.
            await core.nodes("slib.shodan.host --ip 8.8.8.8")
            assert len(await core.nodes("risk:vulnerable")) == 2
            assert len(await core.nodes("crypto:x509:cert")) == 1
            assert len(await core.nodes("it:prod:softver")) == 2

    async def test_host_pipeline(self):
        async with shodanSvc(self) as (core, svc, fake):
            await core.nodes("[ inet:ipv4=8.8.8.8 inet:fqdn=vertex.link ]")

            # Inbound nodes pass through without --yield.
            msgs = await core.stormlist(
                "inet:ipv4=8.8.8.8 inet:fqdn=vertex.link | slib.shodan.host"
            )
            self.stormIsInWarn("inet:fqdn is not supported", msgs)
            nodes = [m[1][0][0] for m in msgs if m[0] == "node"]
            assert nodes == ["inet:ipv4"]
            assert fake.last()["query"]["history"] == "false"

            await core.nodes("inet:ipv4=8.8.8.8 | slib.shodan.host --history --minify")
            assert fake.last()["query"]["history"] == "true"
            assert fake.last()["query"]["minify"] == "true"

    async def test_host_unsupported_node(self):
        # An unsupported inbound node only warns: it isn't sent to Shodan and doesn't stop the others.
        async with shodanSvc(self) as (core, svc, fake):
            await core.nodes("[ inet:ipv4=8.8.8.8 inet:fqdn=vertex.link ]")
            msgs = await core.stormlist(
                "inet:fqdn=vertex.link inet:ipv4=8.8.8.8 | slib.shodan.host --yield"
            )
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("inet:fqdn is not supported", msgs)
            paths = [r["path"] for r in fake.requests]
            assert "/api/shodan/host/vertex.link" not in paths
            assert "/api/shodan/host/8.8.8.8" in paths
            assert [m[1][0][0] for m in msgs if m[0] == "node"] == ["inet:ipv4"]

    async def test_host_errors(self):
        async with shodanSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.shodan.host --ip 10.0.0.1 --yield")
            self.stormIsInWarn("Host lookup of 10.0.0.1 failed: No information available", msgs)
            assert not [m for m in msgs if m[0] == "node"]

    async def test_host_internetdb(self):
        async with shodanSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.shodan.host --ip 1.1.1.1 --internetdb --yield")
            self.stormHasNoErr(msgs)
            assert fake.last()["path"] == "/internetdb/1.1.1.1"

            nodes = await core.nodes("inet:ipv4=1.1.1.1")
            assert "rep.shodan.cdn" in nodes[0].tags
            assert await nodeset(core, "inet:ipv4=1.1.1.1 -> inet:server") == {
                ("inet:server", "tcp://1.1.1.1:53"),
                ("inet:server", "tcp://1.1.1.1:80"),
            }
            assert len(await core.nodes("inet:ipv4=1.1.1.1 -(uses)> it:prod:softver")) == 1
            assert len(await core.nodes("inet:dns:a=(one.one.one.one, 1.1.1.1)")) == 1
            assert len(await core.nodes("risk:vulnerable:node=(inet:ipv4, 1.1.1.1)")) == 1

    async def test_host_no_key_falls_back(self):
        async with shodanSvc(self, apikey=None) as (core, svc, fake):
            msgs = await core.stormlist("slib.shodan.host --ip 1.1.1.1 --yield")
            self.stormIsInWarn("falling back to InternetDB", msgs)
            assert fake.last()["path"] == "/internetdb/1.1.1.1"
            assert len([m for m in msgs if m[0] == "node"]) == 1

    async def test_tags_disabled(self):
        async with shodanSvc(self) as (core, svc, fake):
            await core.nodes("slib.shodan.admin.tags --disable")
            await core.nodes("slib.shodan.host --ip 8.8.8.8")
            assert not (await core.nodes("inet:ipv4=8.8.8.8"))[0].tags

            await core.nodes("slib.shodan.admin.tags --enable --prefix my.shodan")
            await core.nodes("slib.shodan.host --ip 8.8.8.8")
            assert "my.shodan.cloud" in (await core.nodes("inet:ipv4=8.8.8.8"))[0].tags


    async def test_host_ipv4_creates_no_ipv6(self):
        async with shodanSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.shodan.host --ip 8.8.8.8")
            self.stormHasNoErr(msgs)

            # Synapse also parses "8.8.8.8" as inet:ipv6=::ffff:8.8.8.8, which must not be made.
            assert len(await core.nodes("inet:ipv4=8.8.8.8")) == 1
            assert len(await core.nodes("inet:ipv6")) == 0

    async def test_isipv6(self):
        async with shodanSvc(self) as (core, svc, fake):
            q = "$util = $lib.import(slib.shodan.util) return($util.isIpv6($ip))"
            for ip, expected in (
                ("8.8.8.8", False),
                (134744072, False),
                ("2001:4860:4860::8888", True),
                ("::ffff:8.8.8.8", True),
            ):
                assert await core.callStorm(q, opts={"vars": {"ip": ip}}) is expected, ip

            model = "$model = $lib.import(slib.shodan.model)"
            await core.nodes(f"{model} $model.ipNode(8.8.8.8)")
            await core.nodes(f"{model} $model.dnsNode(vertex.link, 8.8.8.8)")
            await core.nodes(f"{model} $model.serverNode(8.8.8.8, (80))")
            assert len(await core.nodes("inet:ipv4=8.8.8.8")) == 1
            assert len(await core.nodes("inet:dns:a=(vertex.link, 8.8.8.8)")) == 1
            assert len(await core.nodes("inet:server=tcp://8.8.8.8:80")) == 1
            assert len(await core.nodes("inet:ipv6")) == 0
            assert len(await core.nodes("inet:dns:aaaa")) == 0


class TestShodanStormSsh(s_tests.SynTest):
    SSH_TEXT = f"ssh-rsa {''.join(SSH_KEY_B64.split())}\n"
    SSH_SHA256 = hashlib.sha256(SSH_TEXT.encode()).hexdigest()
    SERVER = "tcp://45.33.32.156:22"

    async def test_ssh_key_servfile(self):
        async with shodanSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.shodan.host --ip 45.33.32.156")
            self.stormHasNoErr(msgs)

            nodes = await core.nodes(f"inet:server={self.SERVER} -> inet:servfile -> file:bytes")
            assert len(nodes) == 1
            file = nodes[0]
            byts = self.SSH_TEXT.encode()
            assert file.ndef[1] == f"sha256:{self.SSH_SHA256}"
            assert file.get("size") == len(byts)
            assert file.get("md5") == hashlib.md5(byts).hexdigest()
            assert file.get("sha1") == hashlib.sha1(byts).hexdigest()
            assert file.get("sha512") == hashlib.sha512(byts).hexdigest()
            assert file.get("mime") == "text/plain"

            # The key file is saved in the Axon, exactly as it would be on disk.
            assert await core.axon.get(bytes.fromhex(self.SSH_SHA256)).__anext__() == byts

            servfile = (await core.nodes("inet:servfile"))[0]
            assert servfile.get(".seen") is not None
            for node in (file, servfile):
                assert len(await core.nodes(f"iden {node.iden()} <(seen)- meta:source +:name=shodan")) == 1

            # Both are tagged as extracted from a Shodan banner.
            for node in (file, servfile):
                assert "rep.shodan.banner" in node.tags

            # Nothing is stored on the banner, its hash is always calculated from the text.
            banner = (await core.nodes(f"inet:server={self.SERVER} -> inet:banner"))[0]
            assert banner.get("text") == HOST_SSH["data"][0]["data"]
            assert not [d async for d in banner.iterData()]

    async def test_ssh_key_tag_prefix(self):
        async with shodanSvc(self) as (core, svc, fake):
            await core.nodes("slib.shodan.admin.tags --enable --prefix my.shodan")
            await core.nodes("slib.shodan.host --ip 45.33.32.156")
            assert len(await core.nodes("file:bytes#my.shodan.banner")) == 1
            assert len(await core.nodes("inet:servfile#my.shodan.banner")) == 1

            await core.nodes("slib.shodan.admin.tags --disable")
            await core.nodes("file:bytes inet:servfile | [ -#my ]")
            await core.nodes("slib.shodan.host --ip 45.33.32.156")
            assert not (await core.nodes("file:bytes"))[0].tags
            assert not (await core.nodes("inet:servfile"))[0].tags

    async def test_ssh_key_no_axon_perm(self):
        async with shodanSvc(self) as (core, svc, fake):
            user = await core.auth.addUser("user")
            await user.addRule((True, ("node",)))
            await user.addRule((True, ("slib", "shodan", "user")))

            msgs = await core.stormlist("slib.shodan.host --ip 45.33.32.156", opts={"user": user.iden})
            self.stormHasNoErr(msgs)

            # Without axon.upload the bytes aren't saved, but the file:bytes is still modeled.
            assert len(await core.nodes(f"file:bytes=sha256:{self.SSH_SHA256} -> inet:servfile")) == 1
            assert not await core.axon.has(bytes.fromhex(self.SSH_SHA256))

    async def test_banner_hash(self):
        async with shodanSvc(self) as (core, svc, fake):
            await core.nodes("slib.shodan.host --ip 45.33.32.156")
            shodanhash = HOST_SSH["data"][0]["hash"]

            q = "$shodan = $lib.import(slib.shodan.lib) return($shodan.bannerHash($valu))"
            assert await core.callStorm(q, opts={"vars": {"valu": "foo"}}) == -156908512

            q = "$shodan = $lib.import(slib.shodan.lib) inet:banner return($shodan.bannerHash($node))"
            assert await core.callStorm(q) == shodanhash

            # Banners from other sources get the hash calculated from their text.
            q = """
                $shodan = $lib.import(slib.shodan.lib)
                [ inet:banner=(tcp://1.2.3.4:22, $text) ]
                return($shodan.bannerHash($node))
            """
            text = HOST_SSH["data"][0]["data"]
            assert await core.callStorm(q, opts={"vars": {"text": text}}) == shodanhash

            # Long banners aren't truncated, so the hash of the node still matches Shodan's.
            longtext = "HTTP/1.1 200 OK\r\n" + "X-Pad: " + "a" * 50_000 + "\r\n\r\n"
            fake.routes[("GET", "/api/shodan/host/192.0.2.10")] = (
                200,
                {
                    "ip_str": "192.0.2.10",
                    "data": [
                        {
                            "ip_str": "192.0.2.10",
                            "port": 80,
                            "data": longtext,
                            "hash": norm.bannerHash(longtext),
                        }
                    ],
                },
            )
            await core.nodes("slib.shodan.host --ip 192.0.2.10")
            q = """
                $shodan = $lib.import(slib.shodan.lib)
                inet:server=tcp://192.0.2.10:80 -> inet:banner
                return($shodan.bannerHash($node))
            """
            assert await core.callStorm(q) == norm.bannerHash(longtext)

            q = "$shodan = $lib.import(slib.shodan.lib) [ inet:fqdn=vertex.link ] return($shodan.bannerHash($node))"
            msgs = await core.stormlist(q)
            self.stormIsInWarn("Only inet:banner nodes have a banner hash", msgs)

    async def test_hash_cmd(self):
        async with shodanSvc(self) as (core, svc, fake):
            await core.nodes("slib.shodan.host --ip 45.33.32.156")
            shodanhash = HOST_SSH["data"][0]["hash"]

            msgs = await core.stormlist("inet:banner | slib.shodan.hash")
            self.stormHasNoErr(msgs)
            self.stormIsInPrint(f"hash:{shodanhash} (the banner from {self.SERVER})", msgs)
            # The banner passes through.
            assert [m[1][0][0] for m in msgs if m[0] == "node"] == ["inet:banner"]

            msgs = await core.stormlist('slib.shodan.hash --text foo --text "Hello, world!"')
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("hash:-156908512", msgs)
            self.stormIsInPrint("hash:-1070186941", msgs)

            msgs = await core.stormlist("[ inet:fqdn=vertex.link ] | slib.shodan.hash")
            self.stormIsInWarn("The node form inet:fqdn is not supported", msgs)

            # Local only, no Shodan API calls.
            assert not [r for r in fake.requests if r["path"] != "/api/shodan/host/45.33.32.156"]

    async def test_search_banner(self):
        async with shodanSvc(self) as (core, svc, fake):
            await core.nodes("slib.shodan.host --ip 45.33.32.156")
            shodanhash = HOST_SSH["data"][0]["hash"]

            msgs = await core.stormlist(f"inet:server={self.SERVER} -> inet:banner | slib.shodan.search")
            self.stormHasNoErr(msgs)
            searches = [r for r in fake.requests if r["path"] == "/api/shodan/host/search"]
            assert [r["query"]["query"] for r in searches] == [f"hash:{shodanhash}"]
            nodes = [m[1][0] for m in msgs if m[0] == "node"]
            assert nodes == [("inet:ipv4", 134744072), ("inet:ipv6", "2001:4860:4860::8888")]

            msgs = await core.stormlist(f'inet:server={self.SERVER} -> inet:banner | slib.shodan.search "country:US"')
            self.stormHasNoErr(msgs)
            assert fake.last("/api/shodan/host/search")["query"]["query"] == f"hash:{shodanhash} country:US"
            searches = [r for r in fake.requests if r["path"] == "/api/shodan/host/search"]
            assert len(searches) == 2

            msgs = await core.stormlist(f"inet:server={self.SERVER} -> inet:banner | slib.shodan.search --count")
            self.stormHasNoErr(msgs)
            self.stormIsInPrint(f"Total results: 1234 (hash:{shodanhash})", msgs)
            assert fake.last("/api/shodan/host/count")["query"]["query"] == f"hash:{shodanhash}"
            assert not [m for m in msgs if m[0] == "node"]
            assert len([r for r in fake.requests if r["path"] == "/api/shodan/host/search"]) == 2

            # Unsupported forms are skipped, and without banners the query runs on its own.
            msgs = await core.stormlist('[ inet:fqdn=vertex.link ] | slib.shodan.search "nginx"')
            self.stormIsInWarn("The node form inet:fqdn is not supported", msgs)
            assert fake.last("/api/shodan/host/search")["query"]["query"] == "nginx"
            assert len([r for r in fake.requests if r["path"] == "/api/shodan/host/search"]) == 3


class TestShodanStormSearch(s_tests.SynTest):
    async def test_search(self):
        async with shodanSvc(self) as (core, svc, fake):
            msgs = await core.stormlist('slib.shodan.search "product:nginx" --facets country')
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("Total results: 1234", msgs)
            nodes = [m[1][0] for m in msgs if m[0] == "node"]
            assert nodes == [("inet:ipv4", 134744072), ("inet:ipv6", "2001:4860:4860::8888")]
            assert fake.last("/api/shodan/host/search")["query"]["minify"] == "false"
            assert len(await core.nodes('inet:server="tcp://[2001:4860:4860::8888]:443"')) == 1

    async def test_search_print_modes(self):
        async with shodanSvc(self) as (core, svc, fake):
            msgs = await core.stormlist('slib.shodan.search "nginx" --count --facets port')
            self.stormIsInPrint("Total results: 1234", msgs)
            self.stormIsInPrint("443", msgs)
            assert not [m for m in msgs if m[0] == "node"]
            assert not [r for r in fake.requests if r["path"] == "/api/shodan/host/search"]

            msgs = await core.stormlist('slib.shodan.search "nginx" --tokens')
            self.stormIsInPrint('"string": "nginx"', msgs)

            msgs = await core.stormlist("slib.shodan.search --filters")
            self.stormIsInPrint("Filters: port, product", msgs)
            self.stormIsInPrint("Facets: country, port", msgs)

            msgs = await core.stormlist("slib.shodan.search")
            self.stormIsInErr("requires a query", msgs)

    async def test_search_error(self):
        async with shodanSvc(self) as (core, svc, fake):
            fake.routes[("GET", "/api/shodan/host/search")] = (403, {"error": "Access denied"})
            msgs = await core.stormlist('slib.shodan.search "nginx"')
            self.stormIsInWarn("Search failed: Access denied", msgs)

    async def test_stream(self):
        async with shodanSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(
                "slib.shodan.stream ports --value 443 --value 53 --limit 0 --timeout 5"
            )
            self.stormHasNoErr(msgs)
            assert fake.last()["path"] == "/stream/shodan/ports/443,53"
            assert [m[1][0] for m in msgs if m[0] == "node"] == [("inet:ipv4", 134744072)]
            assert len(await core.nodes("inet:server")) == 2

            msgs = await core.stormlist("slib.shodan.stream ports")
            self.stormIsInWarn("requires at least one value", msgs)


class TestShodanStormDns(s_tests.SynTest):
    async def test_dns_domain(self):
        async with shodanSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(
                "slib.shodan.dns.domain --domain vertex.link --yield --type A --history"
            )
            self.stormHasNoErr(msgs)
            assert fake.last()["query"]["type"] == "A"
            assert fake.last()["query"]["history"] == "true"
            assert {m[1][0][1] for m in msgs if m[0] == "node"} == {
                "www.vertex.link",
                "api.vertex.link",
            }

            assert len(await core.nodes("inet:dns:a=(vertex.link, 1.2.3.4)")) == 1
            assert len(await core.nodes("inet:dns:cname=(www.vertex.link, vertex.link)")) == 1
            assert len(await core.nodes("inet:dns:mx=(vertex.link, mx.vertex.link)")) == 1
            assert len(await core.nodes("inet:dns:ns=(vertex.link, ns1.vertex.link)")) == 1
            assert len(await core.nodes("inet:dns:txt=(vertex.link, 'v=spf1 -all')")) == 1
            assert len(await core.nodes("inet:dns:aaaa=(api.vertex.link, '2001:db8::1')")) == 1
            assert "rep.shodan.ipv6" in (await core.nodes("inet:fqdn=vertex.link"))[0].tags

            # Inbound nodes pass through without --yield.
            msgs = await core.stormlist("inet:fqdn=vertex.link | slib.shodan.dns.domain")
            assert [m[1][0] for m in msgs if m[0] == "node"] == [("inet:fqdn", "vertex.link")]

    async def test_dns_domain_unsupported_node(self):
        # An unsupported inbound node only warns: it isn't sent to Shodan and doesn't stop the others.
        async with shodanSvc(self) as (core, svc, fake):
            await core.nodes("[ inet:ipv4=8.8.8.8 inet:fqdn=vertex.link ]")
            msgs = await core.stormlist(
                "inet:ipv4=8.8.8.8 inet:fqdn=vertex.link | slib.shodan.dns.domain --yield"
            )
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("inet:ipv4 is not supported", msgs)
            paths = [r["path"] for r in fake.requests]
            assert not [p for p in paths if "8.8.8.8" in p]
            assert "/api/dns/domain/vertex.link" in paths
            assert {m[1][0][1] for m in msgs if m[0] == "node"} == {
                "www.vertex.link",
                "api.vertex.link",
            }

            # Without --yield, the unsupported node still passes through.
            msgs = await core.stormlist("inet:ipv4=8.8.8.8 | slib.shodan.dns.domain")
            self.stormHasNoErr(msgs)
            assert [m[1][0] for m in msgs if m[0] == "node"] == [("inet:ipv4", 134744072)]

    async def test_dns_lookup(self):
        async with shodanSvc(self) as (core, svc, fake):
            await core.nodes("[ inet:fqdn=vertex.link inet:ipv4=8.8.8.8 ]")

            msgs = await core.stormlist(
                "inet:fqdn=vertex.link inet:ipv4=8.8.8.8 | slib.shodan.dns.lookup --yield"
            )
            self.stormHasNoErr(msgs)
            assert {m[1][0] for m in msgs if m[0] == "node"} == {
                ("inet:ipv4", 16909060),
                ("inet:fqdn", "dns.google"),
            }
            assert len(await core.nodes("inet:dns:a=(vertex.link, 1.2.3.4)")) == 1
            assert len(await core.nodes("inet:dns:a=(dns.google, 8.8.8.8)")) == 1
            assert (await core.nodes("inet:ipv4=8.8.8.8"))[0].get("dns:rev") == "dns.google"


class TestShodanStormVulns(s_tests.SynTest):
    async def test_cve(self):
        async with shodanSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.shodan.cve --cve cve-2021-44228 --yield --cpes")
            self.stormHasNoErr(msgs)
            nodes = [m for m in msgs if m[0] == "node"]
            assert len(nodes) == 1

            vuln = (await core.nodes("risk:vuln:cve=cve-2021-44228"))[0]
            assert vuln.get("cvss:v3_1:score") == 10.0
            assert vuln.get("cvss:v2_0:score") == 9.3
            assert vuln.get("cve:desc").startswith("Apache Log4j2")
            assert vuln.get("cve:references") == (
                "https://logging.apache.org/log4j/2.x/security.html",
            )
            assert vuln.get("timeline:published") is not None
            assert "rep.shodan.kev" in vuln.tags

            assert len(await core.nodes("it:sec:cve=cve-2021-44228")) == 1

            nodes = await core.nodes("it:prod:softver:cpe")
            assert len(nodes) == 1
            assert nodes[0].get("cves") == ("cve-2021-44228",)

    async def test_cve_inbound_and_search(self):
        async with shodanSvc(self) as (core, svc, fake):
            await core.nodes(
                "[ it:sec:cve=cve-2021-44228 it:sec:cpe='cpe:2.3:a:apache:log4j:2.0:-:*:*:*:*:*:*' ]"
            )

            msgs = await core.stormlist("it:sec:cve | slib.shodan.cve")
            self.stormHasNoErr(msgs)
            assert len(await core.nodes("risk:vuln:cve=cve-2021-44228")) == 1

            msgs = await core.stormlist("it:sec:cpe | slib.shodan.cve --kev --epss --yield")
            self.stormHasNoErr(msgs)
            query = fake.last("/cvedb/cves")["query"]
            assert query["cpe23"] == "cpe:2.3:a:apache:log4j:2.0:-:*:*:*:*:*:*"
            assert query["is_kev"] == "true"
            assert query["sort_by_epss"] == "true"
            assert [m[1][0][0] for m in msgs if m[0] == "node"] == ["risk:vuln"]

            msgs = await core.stormlist("slib.shodan.cve --product log4j --start 2021-01-01")
            self.stormIsInPrint("Found 1 CVEs", msgs)
            assert fake.last("/cvedb/cves")["query"]["start_date"] == "2021-01-01"

    async def test_cpe(self):
        async with shodanSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.shodan.cpe nginx --yield")
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("cpe:2.3:a:f5:nginx:1.25.3", msgs)
            nodes = [m[1][0] for m in msgs if m[0] == "node"]
            assert nodes == [("it:sec:cpe", "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*")]

            fake.routes[("GET", "/cvedb/cpes")] = (200, {"total": 42})
            msgs = await core.stormlist("slib.shodan.cpe nginx --count")
            self.stormIsInPrint("Total CPEs: 42", msgs)

    async def test_cve_advisories(self):
        async with shodanSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(
                "slib.shodan.cve --cve ghsa-jfh8-c2jp-5v3q --cve EUVD-2099-0001 --yield"
            )
            self.stormHasNoErr(msgs)
            assert len([m for m in msgs if m[0] == "node"]) == 2

            # The GHSA resolves to its CVE, with the advisory IDs and CWEs added.
            vuln = (await core.nodes("risk:vuln:cve=cve-2021-44228"))[0]
            assert vuln.get("names") == ("euvd-2021-34768", "ghsa-jfh8-c2jp-5v3q")
            assert vuln.get("cwes") == ("CWE-20", "CWE-502")
            assert "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" in vuln.get("cve:references")

            # An advisory without a CVE is deconflicted by its ID.
            nodes = await core.nodes("risk:vuln:id=EUVD-2099-0001")
            assert len(nodes) == 1
            assert nodes[0].get("desc") == "A made up advisory without a CVE."
            assert nodes[0].get("cvss:v3_1:score") == 7.5

            await core.nodes("slib.shodan.cve --cve EUVD-2099-0001")
            assert len(await core.nodes("risk:vuln:id=EUVD-2099-0001")) == 1

    async def test_cve_count(self):
        async with shodanSvc(self) as (core, svc, fake):
            fake.routes[("GET", "/cvedb/cves")] = (200, {"total": 20})
            msgs = await core.stormlist("slib.shodan.cve --product log4j --kev --count")
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("20 matching CVEs", msgs)
            assert fake.last()["query"]["count"] == "true"
            assert not await core.nodes("risk:vuln")

    async def test_enrich(self):
        async with shodanSvc(self) as (core, svc, fake):
            await core.nodes("""[
                inet:ipv4=8.8.8.8 inet:fqdn=vertex.link it:sec:cve=cve-2021-44228
                (risk:vuln=* :cve=cve-2021-44228) inet:email=visi@vertex.link
            ]""")
            msgs = await core.stormlist("""
                inet:ipv4=8.8.8.8 inet:fqdn=vertex.link it:sec:cve risk:vuln inet:email | slib.shodan.enrich --yield
            """)
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("inet:email is not supported", msgs)
            assert not [r for r in fake.requests if "visi@vertex.link" in r["path"]]
            forms = {m[1][0][0] for m in msgs if m[0] == "node"}
            assert forms == {"inet:ipv4", "inet:fqdn", "risk:vuln"}
            assert len(await core.nodes("inet:ipv4=8.8.8.8 -> inet:server")) == 2
            assert len(await core.nodes("inet:dns:a=(vertex.link, 1.2.3.4)")) == 1


class TestShodanStormPrinting(s_tests.SynTest):
    """Commands that only print Shodan data."""

    async def test_print_cmds(self):
        async with shodanSvc(self) as (core, svc, fake):
            cases = (
                (
                    "slib.shodan.info",
                    ("Name: visi", "API plan: dev", "slib.shodan service IP: 5.6.7.8"),
                ),
                (
                    "slib.shodan.trends product:openssh --facets version",
                    ("Total results: 10", "2026-09", "9.6"),
                ),
                ("slib.shodan.trends --filters", ("Filters: product", "Facets: version")),
                ("slib.shodan.queries", ("Total saved queries: 1", "Webcams")),
                ("slib.shodan.queries --search webcam", ("Webcams",)),
                ("slib.shodan.queries --tags", ("webcam",)),
                ("slib.shodan.ref ports", ("22, 80, 443",)),
                ("slib.shodan.ref protocols", ("HTTPS banner grabber",)),
                ("slib.shodan.ref services", ("SSH",)),
                ("slib.shodan.ref filters", ("port, product",)),
                ("slib.shodan.ref facets", ("country, port",)),
                ("slib.shodan.ref triggers", ("new_service",)),
                ("slib.shodan.ref providers", ("webhook_url",)),
                ("slib.shodan.ref httpheaders", ("User-Agent: test",)),
            )
            for query, prints in cases:
                msgs = await core.stormlist(query)
                self.stormHasNoErr(msgs)
                for text in prints:
                    self.stormIsInPrint(text, msgs)

            assert fake.last("/api/shodan/query/search")["query"]["query"] == "webcam"


class TestShodanStormScanAlerts(s_tests.SynTest):
    async def test_scan(self):
        async with shodanSvc(self) as (core, svc, fake):
            await core.nodes("[ inet:ipv4=8.8.8.8 inet:cidr4=1.2.3.0/24 ]")

            msgs = await core.stormlist(
                "inet:ipv4=8.8.8.8 inet:cidr4 | slib.shodan.scan --ip 9.9.9.9 --wait 30"
            )
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("Submitted scan SCAN1 for 1 IPs, 97 scan credits left", msgs)
            self.stormIsInPrint("Scan SCAN1 is done", msgs)
            self.stormIsInWarn("Not ingesting netblock 1.2.3.0/24", msgs)

            scans = [r for r in fake.requests if r["path"] == "/api/shodan/scan"]
            assert len(scans) == 1
            # Shodan ignores query params on POST /shodan/scan, the IPs must be in a form body.
            assert set(scans[0]["form"]["ips"].split(",")) == {"9.9.9.9", "8.8.8.8", "1.2.3.0/24"}
            assert len(await core.nodes("inet:ipv4=8.8.8.8 -> inet:server")) == 2

            msgs = await core.stormlist("slib.shodan.scan.status")
            self.stormIsInPrint("Total scans: 1", msgs)
            msgs = await core.stormlist("slib.shodan.scan.status SCAN1")
            self.stormIsInPrint("Scan SCAN1: DONE (1 IPs", msgs)
            msgs = await core.stormlist("slib.shodan.scan.internet 8443 https")
            self.stormIsInPrint("Submitted scan ISCAN1", msgs)

            msgs = await core.stormlist("slib.shodan.scan")
            self.stormIsInWarn("Nothing to scan", msgs)

    async def test_alerts(self):
        async with shodanSvc(self) as (core, svc, fake):
            await core.nodes("[ inet:cidr4=1.2.3.0/24 inet:ipv4=5.6.7.8 ]")

            msgs = await core.stormlist(
                "inet:cidr4 inet:ipv4=5.6.7.8 | slib.shodan.alert.add corp --expires 60 --trigger new_service --notifier default"
            )
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("Created alert ALERT1 monitoring 2 IPs/netblocks", msgs)
            self.stormIsInPrint("Enabled trigger new_service", msgs)
            self.stormIsInPrint("Added notifier default", msgs)
            body = fake.last("/api/shodan/alert", "POST")["json"]
            assert body["name"] == "corp"
            assert body["expires"] == 60
            assert sorted(body["filters"]["ip"]) == ["1.2.3.0/24", "5.6.7.8"]

            msgs = await core.stormlist("slib.shodan.alert.list")
            self.stormIsInPrint("Alert ALERT1 - corp", msgs)
            self.stormIsInPrint("Triggers: new_service", msgs)
            assert fake.last()["query"]["include_expired"] == "true"
            msgs = await core.stormlist("slib.shodan.alert.list --active")
            assert fake.last()["query"]["include_expired"] == "false"
            msgs = await core.stormlist("slib.shodan.alert.list --id ALERT1")
            self.stormIsInPrint("IPs: 1.2.3.0/24", msgs)

            msgs = await core.stormlist("""
                slib.shodan.alert.edit ALERT1 --ip 9.9.9.0/24 --append
                    --enable malware --disable new_service
                    --ignore open_database/1.2.3.4:9200 --unignore open_database/1.2.3.4:9200
                    --notifier default --rm-notifier default --ignore bad
            """)
            self.stormIsInPrint("Alert ALERT1 now monitors 2 IPs/netblocks", msgs)
            self.stormIsInPrint("Enabled trigger malware", msgs)
            self.stormIsInPrint("Disabled trigger new_service", msgs)
            self.stormIsInPrint("Ignoring open_database/1.2.3.4:9200", msgs)
            self.stormIsInPrint("No longer ignoring open_database/1.2.3.4:9200", msgs)
            self.stormIsInPrint("Removed notifier default", msgs)
            self.stormIsInWarn("bad is not in the format", msgs)
            body = fake.last("/api/shodan/alert/ALERT1", "POST")["json"]
            assert sorted(body["filters"]["ip"]) == ["1.2.3.0/24", "9.9.9.0/24"]

            msgs = await core.stormlist("slib.shodan.alert.del ALERT1")
            self.stormIsInPrint("Deleted alert ALERT1", msgs)

            msgs = await core.stormlist("slib.shodan.alert.edit NOPE --enable x")
            self.stormIsInWarn("Enabling trigger x failed", msgs)

    async def test_notifiers(self):
        async with shodanSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.shodan.notifier.list")
            self.stormIsInPrint("Total notifiers: 1", msgs)
            msgs = await core.stormlist("slib.shodan.notifier.list --id NOTIF1")
            self.stormIsInPrint('"provider": "slack"', msgs)

            msgs = await core.stormlist(
                'slib.shodan.notifier.add slack --desc soc --arg "webhook_url=https://x?a=b"'
            )
            self.stormIsInPrint("Created notifier NOTIF1", msgs)
            # Shodan only reads POST /notifier's arguments from a form body.
            form = fake.last("/api/notifier", "POST")["form"]
            assert form["webhook_url"] == "https://x?a=b"
            assert form["description"] == "soc"
            assert form["provider"] == "slack"

            msgs = await core.stormlist("slib.shodan.notifier.add slack --arg nope")
            self.stormIsInWarn("nope is not in the format", msgs)

            msgs = await core.stormlist("slib.shodan.notifier.edit NOTIF1 --arg to=a@b.c")
            self.stormIsInPrint("Updated notifier NOTIF1", msgs)
            msgs = await core.stormlist("slib.shodan.notifier.del NOTIF1")
            self.stormIsInPrint("Deleted notifier NOTIF1", msgs)


class TestShodanStormAdmin(s_tests.SynTest):
    async def test_admin(self):
        async with shodanSvc(self, apikey=None) as (core, svc, fake):
            msgs = await core.stormlist("slib.shodan.admin.apikey")
            self.stormIsInPrint("No service-wide API key is set", msgs)

            msgs = await core.stormlist("slib.shodan.admin.apikey adminkey")
            self.stormIsInPrint("Set the slib.shodan API key", msgs)
            msgs = await core.stormlist("slib.shodan.admin.apikey")
            self.stormIsInPrint("A service-wide API key is set", msgs)

            msgs = await core.stormlist("slib.shodan.admin.org")
            self.stormIsInPrint("Organization: Vertex (ORG1)", msgs)
            assert fake.last()["query"]["key"] == "adminkey"
            msgs = await core.stormlist("slib.shodan.admin.org --add visi --notify --remove visi")
            self.stormIsInPrint("Added visi", msgs)
            self.stormIsInPrint("Removed visi", msgs)
            assert fake.last("/api/org/member/visi", "PUT")["query"]["notify"] == "true"

            msgs = await core.stormlist("slib.shodan.admin.data")
            self.stormIsInPrint("raw-daily", msgs)
            msgs = await core.stormlist("slib.shodan.admin.data raw-daily")
            self.stormIsInPrint("2026-10-01.json.gz", msgs)

            msgs = await core.stormlist(
                'slib.shodan.admin.request /shodan/host/count --params ({"query": "x"})'
            )
            self.stormIsInPrint('"total": 1234', msgs)
            assert fake.last()["query"]["query"] == "x"
            msgs = await core.stormlist(
                "slib.shodan.admin.request /api/v1/search/facets --base trends"
            )
            self.stormIsInPrint("version", msgs)

            msgs = await core.stormlist("slib.shodan.admin.apikey --clear")
            self.stormIsInPrint("Cleared the slib.shodan API key", msgs)
            msgs = await core.stormlist("slib.shodan.admin.org")
            self.stormIsInWarn("No Shodan API key is configured", msgs)

            msgs = await core.stormlist("slib.shodan.admin.tags --enable --disable")
            self.stormIsInErr("not both", msgs)


class TestShodanStormPerms(s_tests.SynTest):
    """The package's perms are enforced, and API keys stay private."""

    async def _addUser(self, core, name, *perms):
        user = await core.auth.addUser(name)
        await user.setPasswd("secret")
        for perm in perms:
            await user.addRule((True, perm))
        return user.iden

    async def test_user_perms(self):
        async with shodanSvc(self) as (core, svc, fake):
            # A user doesn't need service.get, the privileged modules handle that.
            useriden = await self._addUser(core, "user", ("node",), USER_PERM)
            noperms = await self._addUser(core, "noperms", ("node",))

            msgs = await core.stormlist("slib.shodan.host --ip 8.8.8.8", opts={"user": useriden})
            self.stormHasNoErr(msgs)
            assert len(await core.nodes("inet:ipv4=8.8.8.8 -> inet:server")) == 2

            for query in ("slib.shodan.host --ip 8.8.8.8", "slib.shodan.info"):
                msgs = await core.stormlist(query, opts={"user": noperms})
                self.stormIsInErr("requires permission: slib.shodan.user", msgs)

            for query in (
                "slib.shodan.scan --ip 1.2.3.4",
                "slib.shodan.alert.list",
                "slib.shodan.admin.apikey foo",
                "slib.shodan.admin.request /org",
            ):
                msgs = await core.stormlist(query, opts={"user": useriden})
                self.stormIsInErr("requires permission", msgs)

            msgs = await core.stormlist(
                '$lib.service.get("slib.shodan").setApiKey(foo)', opts={"user": useriden}
            )
            self.stormIsInErr("must have permission service.get", msgs)

    async def test_scoped_perms(self):
        async with shodanSvc(self) as (core, svc, fake):
            scanner = await self._addUser(core, "scanner", ("slib", "shodan", "scan"))
            alerter = await self._addUser(core, "alerter", ("slib", "shodan", "alert"))
            admin = await self._addUser(core, "admin", ("slib", "shodan", "admin"))

            msgs = await core.stormlist("slib.shodan.scan --ip 1.2.3.4", opts={"user": scanner})
            self.stormHasNoErr(msgs)
            msgs = await core.stormlist("slib.shodan.alert.list", opts={"user": alerter})
            self.stormHasNoErr(msgs)
            msgs = await core.stormlist("slib.shodan.admin.apikey foo", opts={"user": admin})
            self.stormHasNoErr(msgs)
            assert svc.getApiKey() == "foo"

            msgs = await core.stormlist("slib.shodan.alert.list", opts={"user": scanner})
            self.stormIsInErr("requires permission", msgs)

    async def test_user_apikey(self):
        async with shodanSvc(self) as (core, svc, fake):
            visi = await self._addUser(core, "visi", ("node",), USER_PERM)
            other = await self._addUser(core, "other", ("node",), USER_PERM)

            msgs = await core.stormlist("slib.shodan.apikey", opts={"user": visi})
            self.stormIsInPrint("You don't have a Shodan API key set", msgs)

            msgs = await core.stormlist("slib.shodan.apikey visikey", opts={"user": visi})
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("Saved your Shodan API key in vault shodan:visi", msgs)

            # The user's key is used for their own requests, but never for anyone else's.
            await core.nodes("slib.shodan.host --ip 8.8.8.8", opts={"user": visi})
            assert fake.last()["query"]["key"] == "visikey"
            await core.nodes("slib.shodan.host --ip 8.8.8.8", opts={"user": other})
            assert fake.last()["query"]["key"] == "testkey"

            # Another user can't pull the key out of the privileged module.
            msgs = await core.stormlist(
                "$lib.print($lib.import(slib.shodan.priv.user).userKey())", opts={"user": other}
            )
            self.stormIsInPrint("$lib.null", msgs)

            msgs = await core.stormlist("slib.shodan.apikey visikey2", opts={"user": visi})
            self.stormIsInPrint("Updated your Shodan API key", msgs)
            await core.nodes("slib.shodan.host --ip 8.8.8.8", opts={"user": visi})
            assert fake.last()["query"]["key"] == "visikey2"

            msgs = await core.stormlist("slib.shodan.apikey --clear", opts={"user": visi})
            self.stormIsInPrint("Deleted your Shodan API key", msgs)
            await core.nodes("slib.shodan.host --ip 8.8.8.8", opts={"user": visi})
            assert fake.last()["query"]["key"] == "testkey"

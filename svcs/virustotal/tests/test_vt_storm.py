"""Pytests for the slib.vt Storm package (commands, modules, modeling, and perms)."""

import pathlib
import tomllib

import synapse.tests.utils as s_tests

from vtsvc import __version__
from vtsvc.defs import PKGDEFS, SVC_GUID, SVC_NAME

from . import fakevt as fv

CMDS = tuple(cmd["name"] for cmd in PKGDEFS[0]["commands"])
MODS = tuple(mod["name"] for mod in PKGDEFS[0]["modules"])


async def count(core, query, opts=None):
    return len(await core.nodes(query, opts=opts))


class TestVtStormPkg(s_tests.SynTest):
    def test_versions_match(self):
        # The version lives in pyproject.toml (the image tag), __init__.py, the package yaml,
        # and the service's uv.lock entry.
        root = pathlib.Path(__file__).parent.parent
        with (root / "pyproject.toml").open("rb") as fd:
            assert tomllib.load(fd)["project"]["version"] == __version__
        assert PKGDEFS[0]["version"] == __version__
        with (root / "uv.lock").open("rb") as fd:
            pkgs = tomllib.load(fd)["package"]
        assert [p["version"] for p in pkgs if p["name"] == "vtsvc"] == [__version__]

    async def test_pkg(self):
        async with fv.vtSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("service.list")
            self.stormIsInPrint(f"true (svc) ({SVC_NAME} @ {__version__})", msgs)
            for cmd in CMDS:
                assert cmd in core.stormcmds, cmd
            for cdef in PKGDEFS[0]["commands"]:
                for cmdinput in cdef.get("cmdinputs", ()):
                    assert core.model.form(cmdinput["form"]) is not None, (cdef["name"], cmdinput)
            for mod in MODS:
                msgs = await core.stormlist(f"$mod = $lib.import({mod})")
                self.stormHasNoErr(msgs)

            nodes = await core.nodes(f"meta:source={SVC_GUID}")
            assert len(nodes) == 1
            assert nodes[0].get("name") == "virustotal"
            msgs = await core.stormlist("slib.vt.admin.tags")
            self.stormIsInPrint("enabled=true prefix=rep.vt", msgs)
            assert fake.requests == []

    async def test_enrich_file(self):
        async with fv.vtSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(f"[hash:sha256={fv.WANNACRY}] | slib.vt.enrich")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("68 malicious, 0 suspicious of 75 engines", msgs)
            assert fake.paths() == [f"GET /files/{fv.WANNACRY}"]

            nodes = await core.nodes(f"file:bytes:sha256={fv.WANNACRY}")
            assert len(nodes) == 1
            f = nodes[0]
            assert f.get("md5") == fv.WANNACRY_MD5
            assert f.get("size") == 3723264
            assert f.get("name") == "lhdfrgui.exe"
            assert f.get("mime:pe:imphash") == "9ecee117164e0b870a53dd187cdd7174"
            assert f.get("mime:pe:compiled") == 1290243788000
            assert f.get("ssdeeps")
            assert f.getTag("rep.vt.verdict.malicious") is not None
            assert f.getTag("rep.vt.family.wannacry") is not None
            assert f.getTag("rep.vt.category.ransomware") is not None
            assert f.getTag("rep.vt.tag.cve_2017_0144") is not None

            top = await core.nodes(f"file:bytes:sha256={fv.WANNACRY} -> it:av:scan:result +:scanner:name=virustotal")
            assert len(top) == 1
            assert top[0].get("verdict") == 40
            assert top[0].get("multi:count") == 75
            assert top[0].get("multi:count:malicious") == 68
            assert top[0].get("signame") == "trojan.wannacry/wanna"
            assert top[0].get("categories") == ("ransomware", "trojan", "worm")
            engines = await core.nodes(f"it:av:scan:result:multi:scan={top[0].ndef[1]}")
            assert engines and all(n.get("verdict") >= 30 for n in engines)
            assert "ransom:win32/wannacrypt!pz" in {n.get("signame") for n in engines}

            assert await count(core, "it:av:scan:result:scanner:name=c2ae +:verdict=40") == 1
            assert await count(core, f"file:bytes:sha256={fv.WANNACRY} -> it:app:yara:match") == 2
            assert await count(core, "it:app:yara:rule:name=WannaCry_Ransomware :author -> ps:contact") == 1
            assert await count(core, f"file:bytes:sha256={fv.WANNACRY} <(matches)- it:app:snort:rule") == 2
            assert await count(core, f"file:bytes:sha256={fv.WANNACRY} <(seen)- meta:source={SVC_GUID}") == 1

            # Looking it up again is answered from the cache.
            msgs = await core.stormlist(f"slib.vt.enrich --hash {fv.WANNACRY}")
            self.stormHasNoWarnErr(msgs)
            assert len(fake.requests) == 1
            msgs = await core.stormlist(f"slib.vt.enrich --hash {fv.WANNACRY} --no-cache --engines all --yield")
            assert len(fake.requests) == 2
            assert len(await core.nodes(f"it:av:scan:result:multi:scan={top[0].ndef[1]}")) > len(engines)

    async def test_enrich_behaviour(self):
        async with fv.vtSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(f"slib.vt.enrich --hash {fv.WANNACRY_MD5} --behaviour --engines none")
            self.stormHasNoWarnErr(msgs)
            assert fake.paths() == [f"GET /files/{fv.WANNACRY_MD5}", f"GET /files/{fv.WANNACRY}/behaviour_summary"]
            q = f"file:bytes:sha256={fv.WANNACRY}"
            assert await count(core, f"{q} -(refs)> inet:fqdn +inet:fqdn=www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com") == 1
            assert await count(core, "inet:dns:a:fqdn=www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com") == 9
            assert await count(core, f"{q} -(refs)> inet:server") == 4
            assert await count(core, f"{q} -(refs)> inet:url") >= 1
            assert await count(core, f"{q} -(uses)> it:mitre:attack:technique") == 4
            assert await count(core, f"{q} -(refs)> it:dev:mutex") == 4
            assert await count(core, f"{q} -(refs)> file:bytes") == 3
            nodes = await core.nodes(q)
            assert nodes[0].getTag("rep.vt.behaviour.ransom") is not None
            # --engines none only models the overall result.
            assert await count(core, "it:av:scan:result:multi:scan") == 0

            # No behaviour reports.
            msgs = await core.stormlist(f"slib.vt.enrich --hash {fv.EICAR} --behaviour")
            self.stormIsInPrint("has no behaviour reports", msgs)

    async def test_enrich_network(self):
        async with fv.vtSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(
                f"[inet:fqdn=example.com inet:ipv4=8.8.8.8 inet:url={fv.EICAR_URL}] | slib.vt.enrich"
            )
            self.stormHasNoWarnErr(msgs)
            assert len(fake.requests) == 3

            # Domain: DNS records, whois, cert.
            assert await count(core, "inet:dns:a:fqdn=example.com") == 2
            assert await count(core, "inet:dns:aaaa:fqdn=example.com") == 2
            assert await count(core, "inet:dns:ns:zone=example.com") == 2
            assert await count(core, "inet:dns:txt:fqdn=example.com") == 2
            assert await count(core, "inet:dns:soa:fqdn=example.com") == 1
            assert await count(core, "inet:dns:mx:fqdn=example.com") == 0
            nodes = await core.nodes("inet:whois:rec:fqdn=example.com")
            assert len(nodes) == 1
            assert nodes[0].get("registrar") == "reserved-internet assigned numbers authority"
            assert "domain name: example.com" in nodes[0].get("text")
            nodes = await core.nodes("crypto:x509:cert:sha256=85ca6ab068e9bcce88b6c4aa3c47f7d17228134a457f870d3800e6223a0df07a")
            assert nodes[0].get("identities:fqdns") == ("example.com",)
            assert nodes[0].get("serial") == "0000000000000000000000000000000000001eee6aabb521d5e14fc315fd998569"[-len(nodes[0].get("serial")):]
            fqdn = (await core.nodes("inet:fqdn=example.com"))[0]
            assert fqdn.getTag("rep.vt.verdict.benign") is not None
            assert await count(core, "it:av:scan:result:target:fqdn=example.com +:scanner:name=virustotal +:verdict=10") == 1

            # IP: ASN, country, whois, cert, JARM.
            ip = (await core.nodes("inet:ipv4=8.8.8.8"))[0]
            assert ip.get("asn") == 15169
            assert ip.get("loc") == "us"
            assert ip.getTag("rep.vt.verdict.suspicious") is not None
            assert ip.getTag("rep.vt.tag.suspicious_udp") is not None
            assert (await core.nodes("inet:asn=15169"))[0].get("name") == "google llc"
            nodes = await core.nodes("inet:whois:iprec:asn=15169")
            assert nodes[0].get("net4") == (134744064, 134744319)
            assert await count(core, "inet:tls:servercert:server=tcp://8.8.8.8:443") == 1
            assert await count(core, "inet:ssl:jarmsample:server=tcp://8.8.8.8:443") == 1

            # URL: redirects, final content.
            url = (await core.nodes(f"inet:url={fv.EICAR_URL}"))[0]
            assert url.getTag("rep.vt.verdict.malicious") is not None
            assert url.getTag("rep.vt.family.mal_htmlgen_a") is not None
            assert await count(core, f"inet:urlredir:src={fv.EICAR_URL}") == 1
            assert await count(core, f"inet:urlfile:file=sha256:{fv.EICAR}") == 1
            assert (await core.nodes(f"file:bytes=sha256:{fv.EICAR}"))[0].get("size") == 68

            # Re-enriching with a new verdict replaces the verdict tag.
            fake.objects["ip_addresses"]["8.8.8.8"]["data"]["attributes"]["last_analysis_stats"]["malicious"] = 0
            msgs = await core.stormlist("inet:ipv4=8.8.8.8 | slib.vt.enrich --no-cache")
            ip = (await core.nodes("inet:ipv4=8.8.8.8"))[0]
            assert ip.getTag("rep.vt.verdict.benign") is not None
            assert ip.getTag("rep.vt.verdict.suspicious") is None

            # Values given as options, and --yield.
            nodes = await core.nodes("slib.vt.enrich --fqdn example.com --ip 8.8.8.8 --url http://www.eicar.org/download/eicar.com.txt --yield")
            assert {n.ndef[0] for n in nodes} == {"inet:fqdn", "inet:ipv4", "inet:url"}

    async def test_enrich_errors(self):
        async with fv.vtSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.vt.enrich --hash " + "0" * 64)
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("VirusTotal doesn't have file", msgs)

            msgs = await core.stormlist("[file:bytes=*] | slib.vt.enrich")
            self.stormIsInWarn("it has no hash", msgs)

            fake.status["/domains/example.com"] = 503
            msgs = await core.stormlist("slib.vt.enrich --fqdn example.com")
            self.stormIsInWarn("Fake failure (TransientError, HTTP 503)", msgs)
            # Transient errors are retried twice.
            assert fake.paths().count("GET /domains/example.com") == 3

        async with fv.vtSvc(self, **{"vt:apikey": "wrong"}) as (core, svc, fake):
            msgs = await core.stormlist("slib.vt.enrich --fqdn example.com")
            self.stormIsInWarn("VirusTotal rejected the API key: Wrong API key (WrongCredentialsError, HTTP 401)", msgs)

        async with fv.vtSvc(self, **{"vt:apikey": None}) as (core, svc, fake):
            msgs = await core.stormlist("slib.vt.enrich --fqdn example.com")
            self.stormIsInWarn("No VirusTotal API key is configured", msgs)
            assert fake.requests == []

        async with fv.vtSvc(self, **{"vt:apikey": "429"}) as (core, svc, fake):
            msgs = await core.stormlist("slib.vt.enrich --fqdn example.com")
            self.stormIsInWarn("going over a quota", msgs)
            # Not retried, and the key is cooled down.
            assert len(fake.requests) == 1
            status = await svc.quota(apikey="429")
            assert status["wait"] > 50

    async def test_rate_limits(self):
        conf = {"vt:limit:minute": 2, "vt:limit:day": 3, "vt:limit:maxwait": 5, "vt:cache:ttl": 0}
        async with fv.vtSvc(self, **conf) as (core, svc, fake):
            msgs = await core.stormlist("slib.vt.enrich --fqdn example.com --ip 8.8.8.8")
            self.stormHasNoWarnErr(msgs)
            # The 3rd request would have to wait a minute, longer than vt:limit:maxwait.
            msgs = await core.stormlist("slib.vt.enrich --fqdn example.com")
            self.stormIsInWarn("Timed out waiting for room under the VirusTotal rate limit of 2 requests per minute", msgs)
            assert len(fake.requests) == 2

            msgs = await core.stormlist("slib.vt.quota")
            self.stormIsInPrint("limits are enforced (vt:community)", msgs)
            self.stormIsInPrint("minute", msgs)

            # Move the requests out of the minute window, then use up the daily quota.
            kv = svc.limiter.kv
            for name in list(kv.keys()):
                if name.endswith(":recent"):
                    kv.set(name, [t - 120 for t in kv.get(name)])
            msgs = await core.stormlist("slib.vt.enrich --fqdn example.com")
            self.stormHasNoWarnErr(msgs)
            msgs = await core.stormlist("slib.vt.enrich --fqdn example.com")
            self.stormIsInWarn("daily quota (3 requests) for this API key is used up", msgs)
            assert len(fake.requests) == 3

            # Users with their own key get their own limits.
            await core.callStorm(f"slib.vt.apikey {fv.OTHERKEY}")
            msgs = await core.stormlist("slib.vt.enrich --fqdn example.com")
            self.stormHasNoWarnErr(msgs)
            assert fake.keys[-1] == fv.OTHERKEY

        # With vt:community false, nothing is limited.
        conf["vt:community"] = False
        async with fv.vtSvc(self, **conf) as (core, svc, fake):
            for _ in range(5):
                msgs = await core.stormlist("slib.vt.enrich --fqdn example.com")
                self.stormHasNoWarnErr(msgs)
            assert len(fake.requests) == 5
            msgs = await core.stormlist("slib.vt.quota --remote")
            self.stormIsInPrint("limits are not enforced", msgs)
            self.stormIsInPrint("api_requests_daily", msgs)

    async def test_related(self):
        async with fv.vtSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("[inet:fqdn=example.com] | slib.vt.related --rel resolutions --limit 3")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("example.com resolutions: 3 of 47.", msgs)
            assert await count(core, "inet:dns:a:fqdn=example.com") + await count(core, "inet:dns:aaaa:fqdn=example.com") == 3

            # Paging: 5 results, 2 per page in the fake.
            nodes = await core.nodes("[inet:ipv4=8.8.8.8] | slib.vt.related --rel resolutions --limit 40 --yield")
            assert len(nodes) == 5
            assert all(n.ndef[0] == "inet:dns:a" for n in nodes)

            nodes = await core.nodes(f"[hash:sha256={fv.WANNACRY}] | slib.vt.related --rel contacted_domains --yield")
            assert len(nodes) == 3 and all(n.ndef[0] == "inet:fqdn" for n in nodes)
            assert await count(core, f"file:bytes=sha256:{fv.WANNACRY} -(refs)> inet:fqdn") == 3

            # An md5 is linked through its file:bytes, once the Cortex knows it.
            await core.stormlist(f"slib.vt.enrich --hash {fv.WANNACRY}")
            msgs = await core.stormlist(f"[hash:md5={fv.WANNACRY_MD5}] | slib.vt.comments")
            self.stormHasNoWarnErr(msgs)
            assert await count(core, f"file:bytes=sha256:{fv.WANNACRY} <(about)- meta:note") == 3

            nodes = await core.nodes("inet:fqdn=example.com | slib.vt.related --rel historical_whois --yield")
            assert len(nodes) == 1
            assert nodes[0].get("created") == 808372800000
            assert nodes[0].get("registrar") == "reserved-internet assigned numbers authority"

            msgs = await core.stormlist("inet:fqdn=example.com | slib.vt.related --rel votes")
            self.stormIsInPrint("vote d-example.com-1", msgs)

            # Public API keys can't read premium relationships, and they're not requested.
            before = len(fake.requests)
            msgs = await core.stormlist("inet:fqdn=example.com | slib.vt.related --rel urls")
            self.stormIsInWarn("isn't available to VirusTotal Public API keys", msgs)
            assert len(fake.requests) == before

    async def test_comments(self):
        async with fv.vtSvc(self) as (core, svc, fake):
            nodes = await core.nodes(f"[hash:sha256={fv.WANNACRY}] | slib.vt.comments --limit 2 --yield")
            assert len(nodes) == 2
            assert nodes[0].ndef[0] == "meta:note"
            assert nodes[0].get("type") == "virustotal.comment."
            assert await count(core, f"file:bytes=sha256:{fv.WANNACRY} <(about)- meta:note") == 2

    async def test_search(self):
        async with fv.vtSvc(self) as (core, svc, fake):
            nodes = await core.nodes("slib.vt.search 8.8.8.8")
            assert [n.ndef for n in nodes] == [("inet:ipv4", 134744072)]
            assert fake.requests[0][2] == {"query": "8.8.8.8", "limit": "10"}
            msgs = await core.stormlist("slib.vt.search nothing")
            self.stormIsInPrint("0 results", msgs)

    async def test_submit(self):
        async with fv.vtSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(f"slib.vt.submit --url {fv.EICAR_URL}")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(f"analysis {fv.ANALYSIS_ID}", msgs)
            assert fake.bodies[-1] == {"url": fv.EICAR_URL}

            msgs = await core.stormlist(f"slib.vt.analysis {fv.ANALYSIS_ID}")
            self.stormIsInPrint("is queued", msgs)
            nodes = await core.nodes(f"slib.vt.analysis {fv.ANALYSIS_ID} --yield")
            assert nodes[0].ndef == ("inet:url", fv.EICAR_URL)
            assert await count(core, f"it:av:scan:result:target:url={fv.EICAR_URL!r} +:scanner:name=virustotal") == 1

            # A file from the Axon, waiting for the analysis.
            fake.analysisPolls = 0
            size, sha256 = await core.axon.put(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
            opts = {"vars": {"sha256": sha256.hex()}}
            msgs = await core.stormlist("[file:bytes=$sha256 :sha256=$sha256 :size=68 :name=eicar.com] | slib.vt.submit --wait --interval 0", opts=opts)
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("completed", msgs)
            filename, byts = fake.bodies[-1]["file"]
            assert filename == "eicar.com" and len(byts) == 68

            msgs = await core.stormlist("[file:bytes=*] | slib.vt.submit")
            self.stormIsInWarn("has no :sha256", msgs)
            msgs = await core.stormlist(f"[file:bytes=sha256:{'1' * 64} :sha256={'1' * 64}] | slib.vt.submit")
            self.stormIsInWarn("The Axon doesn't have", msgs)

    async def test_rescan_comment_vote(self):
        async with fv.vtSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(f"[inet:fqdn=example.com hash:sha256={fv.WANNACRY}] | slib.vt.rescan")
            self.stormHasNoWarnErr(msgs)
            assert fake.paths() == ["POST /domains/example.com/analyse", f"POST /files/{fv.WANNACRY}/analyse"]

            msgs = await core.stormlist('inet:fqdn=example.com | slib.vt.comment "Looks fine #benign"')
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("Added comment x-example.com-1", msgs)
            assert fake.bodies[-1] == {"data": {"type": "comment", "attributes": {"text": "Looks fine #benign"}}}

            msgs = await core.stormlist("inet:fqdn=example.com | slib.vt.vote harmless")
            self.stormHasNoWarnErr(msgs)
            msgs = await core.stormlist("inet:fqdn=example.com | slib.vt.vote harmless")
            self.stormIsInWarn("Already voted (AlreadyExistsError, HTTP 409)", msgs)

    async def test_admin(self):
        async with fv.vtSvc(self, **{"vt:apikey": None}) as (core, svc, fake):
            msgs = await core.stormlist("slib.vt.admin.apikey")
            self.stormIsInPrint("No service-wide API key is set.", msgs)
            msgs = await core.stormlist(f"slib.vt.admin.apikey {fv.APIKEY}")
            self.stormIsInPrint("Set the slib.vt API key.", msgs)
            msgs = await core.stormlist("slib.vt.admin.apikey")
            self.stormIsInPrint("A service-wide API key is set.", msgs)

            msgs = await core.stormlist("slib.vt.admin.request /popular_threat_categories")
            self.stormIsInPrint('"ransomware"', msgs)
            msgs = await core.stormlist("slib.vt.admin.request /search --param query=8.8.8.8 --param limit=1")
            self.stormHasNoWarnErr(msgs)
            assert fake.requests[-1][2] == {"query": "8.8.8.8", "limit": "1"}
            msgs = await core.stormlist("slib.vt.admin.request /search --param bad")
            self.stormIsInWarn("Invalid --param", msgs)

            msgs = await core.stormlist("slib.vt.admin.tags --prefix rep.virustotal --disable")
            self.stormIsInPrint("enabled=false prefix=rep.virustotal", msgs)
            await core.stormlist("slib.vt.enrich --fqdn example.com")
            assert not (await core.nodes("inet:fqdn=example.com"))[0].tags
            msgs = await core.stormlist("slib.vt.admin.tags --prefix '..' --enable")
            self.stormIsInWarn("Invalid tag prefix", msgs)
            await core.stormlist("slib.vt.enrich --fqdn example.com --no-cache")
            assert (await core.nodes("inet:fqdn=example.com"))[0].getTag("rep.virustotal.verdict.benign") is not None

            msgs = await core.stormlist(f"slib.vt.admin.apikey --clear")
            self.stormIsInPrint("Cleared the slib.vt API key.", msgs)

    async def test_apikey(self):
        async with fv.vtSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.vt.apikey")
            self.stormIsInPrint("You don't have a VirusTotal API key set.", msgs)
            msgs = await core.stormlist(f"slib.vt.apikey {fv.OTHERKEY}")
            self.stormIsInPrint("Saved your VirusTotal API key in vault virustotal:root.", msgs)
            msgs = await core.stormlist(f"slib.vt.apikey {fv.OTHERKEY}")
            self.stormIsInPrint("Updated your VirusTotal API key.", msgs)
            msgs = await core.stormlist("slib.vt.apikey")
            self.stormIsInPrint("set in vault virustotal:root", msgs)
            await core.stormlist("slib.vt.enrich --fqdn example.com")
            assert fake.keys == [fv.OTHERKEY]
            msgs = await core.stormlist("slib.vt.apikey --clear")
            self.stormIsInPrint("Deleted your VirusTotal API key.", msgs)

    async def test_perms(self):
        async with fv.vtSvc(self) as (core, svc, fake):
            user = await core.auth.addUser("visi")
            opts = {"user": user.iden}

            msgs = await core.stormlist("slib.vt.enrich --fqdn example.com", opts=opts)
            self.stormIsInErr("slib.vt.user", msgs)

            await user.addRule((True, ("slib", "vt", "user")))
            await user.addRule((True, ("node",)))
            msgs = await core.stormlist("slib.vt.enrich --fqdn example.com", opts=opts)
            self.stormHasNoWarnErr(msgs)

            for cmd in ("inet:fqdn=example.com | slib.vt.rescan", f"slib.vt.submit --url {fv.EICAR_URL}",
                        "inet:fqdn=example.com | slib.vt.vote harmless", "slib.vt.admin.apikey",
                        "slib.vt.admin.request /search"):
                msgs = await core.stormlist(cmd, opts=opts)
                self.stormIsInErr("requires permission", msgs)

            # The service's key can't be read through the privileged modules.
            msgs = await core.stormlist("$lib.print($lib.import(slib.vt.priv.user).userKey())", opts=opts)
            assert fv.APIKEY not in str(msgs)

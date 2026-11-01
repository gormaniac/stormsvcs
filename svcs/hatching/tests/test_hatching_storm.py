"""Pytests for the slib.hatching Storm package (commands, modules, modeling, and perms)."""

import hashlib
import json

import synapse.tests.utils as s_tests
from pyhatching import testing as ft

from hatchingsvc import __version__
from hatchingsvc.defs import PKGDEFS, SOURCE_GUID, SVC_NAME

from .helpers import hatchingSvc


CMDS = tuple(cmd["name"] for cmd in PKGDEFS[0]["commands"])
MODS = tuple(mod["name"] for mod in PKGDEFS[0]["modules"])

SAMPLE = f"file:bytes=sha256:{ft.SAMPLE_SHA256}"
SID = ft.SAMPLE_ID


def prints(msgs) -> str:
    return "\n".join(m[1]["mesg"] for m in msgs if m[0] == "print")


def warns(msgs) -> str:
    return "\n".join(m[1]["mesg"] for m in msgs if m[0] == "warn")


def yielded(msgs) -> list:
    return [m[1][0] for m in msgs if m[0] == "node"]


class TestStormPkg(s_tests.SynTest):

    async def test_pkg(self):
        assert len(CMDS) == 35

        async with hatchingSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("service.list")
            self.stormIsInPrint(f"true (svc) ({SVC_NAME} @ {__version__})", msgs)

            for cmd in CMDS:
                assert cmd in core.stormcmds, cmd

            for mod in MODS:
                msgs = await core.stormlist(f"$mod = $lib.import({mod})")
                self.stormHasNoErr(msgs)

            # The service add event creates the meta:source and the tag settings.
            nodes = await core.nodes(f"meta:source={SOURCE_GUID}")
            assert len(nodes) == 1 and nodes[0].get("name") == "hatching triage"
            assert nodes[0].get("type") == "slib.hatching"

            msgs = await core.stormlist("slib.hatching.admin.tags")
            self.stormIsInPrint("enabled=true prefix=rep.hatching", msgs)


class TestStormEnrich(s_tests.SynTest):

    async def test_enrich_sample(self):
        async with hatchingSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(f"slib.hatching.enrich --sample {SID} --yield")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(f"Modeled sample {SID} (score=10 families=cobaltstrike,lockbit", msgs)
            assert yielded(msgs) == [("file:bytes", f"sha256:{ft.SAMPLE_SHA256}")]

            (f,) = await core.nodes(SAMPLE)
            assert f.get("md5") == ft.SAMPLE_MD5 and f.get("sha512") == ft.SAMPLE_SHA512
            assert f.get("name") == "invoice.exe" and f.get("mime") == "application/x-dosexec"
            assert f.get("size") == len(ft.SAMPLE_BYTES)
            for tag in ("cobaltstrike", "lockbit", "backdoor", "trojan", "persistence", "upx"):
                assert f"rep.hatching.{tag}" in f.tags, tag
            assert f.tags["rep.hatching.cobaltstrike"] == (1793448000000, 1793448300000)

            # The verdict.
            (scan,) = await core.nodes(f"{SAMPLE} -> it:av:scan:result:target:file -:multi:scan")
            assert scan.get("scanner:name") == "hatching triage" and scan.get("verdict") == 40
            assert scan.get("signame") == "cobaltstrike"
            assert f.get("ssdeeps") == (ft.SAMPLE_SSDEEP,)

            # Each signature is a result under the verdict.
            sigs = await core.nodes(f"it:av:scan:result={scan.ndef[1]} -> it:av:scan:result:multi:scan")
            assert {(s.get("signame"), s.get("verdict")) for s in sigs} == {
                ("cobaltstrike", 40), ("adds run key to start application", 30),
                ("suspicious use of setwindowshookex", 10),
            }
            (sig,) = await core.nodes("it:av:scan:result:signame='adds run key to start application'")
            assert sig.get("categories") == ("persistence",) and sig.get("target:file") == f"sha256:{ft.SAMPLE_SHA256}"
            assert await core.count(f"it:av:scan:result={sig.ndef[1]} -(uses)> it:mitre:attack:technique=T1547.001") == 1

            # Credentials from the config.
            (cred,) = await core.nodes(f"{SAMPLE} -(refs)> auth:creds")
            assert cred.get("user") == "bot@example.com" and cred.get("passwd") == "hunter2"
            assert cred.get("email") == "bot@example.com" and cred.get("website") == "smtp://mail.example.com:587"
            assert await core.count("it:sec:c2:config -(refs)> auth:creds") == 1

            # Families, techniques, and IOCs.
            nodes = await core.nodes("risk:tool:software:tag=rep.hatching.cobaltstrike")
            assert len(nodes) == 1 and nodes[0].get("reporter:name") == "hatching triage"
            ttps = {n.ndef[1] for n in await core.nodes(f"{SAMPLE} -(uses)> it:mitre:attack:technique")}
            assert ttps == {"T1547.001", "T1056.001"}
            refs = {n.ndef for n in await core.nodes(f"{SAMPLE} -(refs)> *")}
            assert ("inet:fqdn", "evil.example.com") in refs
            assert ("inet:url", "http://203.0.113.9/a.ps1") in refs
            assert ("inet:email", "pay@example.org") in refs
            assert ("it:dev:mutex", "Global\\cs-mutex") in refs

            # The malware config.
            (config,) = await core.nodes(f"it:sec:c2:config:file=sha256:{ft.SAMPLE_SHA256}")
            assert config.get("family") == "cobaltstrike" and config.get("mutex") == "Global\\cs-mutex"
            assert config.get("raw")["botnet"] == "1359593325"
            nodes = await core.nodes("#rep.hatching.c2")
            assert {n.ndef for n in nodes} == {
                ("inet:url", "http://198.51.100.7:443/jquery-3.3.1.min.js"),
                ("inet:url", "tcp://evil.example.com:8080"),
                ("inet:ipv4", 0xC6336407),
                ("inet:fqdn", "evil.example.com"),
            }
            assert await core.count("#rep.hatching.dropper") == 1
            assert await core.count("#rep.hatching.ransom") == 2

            # Everything is linked to the meta:source, without the task nodes.
            assert await core.count(f"meta:source={SOURCE_GUID} -(seen)> file:bytes") == 1
            for form in ("it:av:scan:result", "risk:tool:software", "it:mitre:attack:technique",
                         "auth:creds", "it:sec:c2:config"):
                assert await core.count(f"{form} +{{ <(seen)- meta:source={SOURCE_GUID} }}") == await core.count(form), form
            assert await core.count("it:exec:proc") == 0

            # Modeling again updates the same nodes.
            before = await core.count(".created")
            await core.stormlist(f"slib.hatching.enrich --sample {SID}")
            assert await core.count(".created") == before

    async def test_enrich_tasks(self):
        async with hatchingSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(f"[ hash:sha256={ft.SAMPLE_SHA256} ] | slib.hatching.enrich --tasks")
            self.stormHasNoWarnErr(msgs)
            assert yielded(msgs) == [("hash:sha256", ft.SAMPLE_SHA256)]

            procs = await core.nodes(f"it:exec:proc:sandbox:file=sha256:{ft.SAMPLE_SHA256}")
            assert {p.get("pid") for p in procs} == {2044, 3120}
            (child,) = await core.nodes("it:exec:proc:pid=3120")
            assert child.get("cmd") == "C:\\Windows\\System32\\cmd.exe /c whoami"
            assert await core.count("it:exec:proc:pid=3120 :src:proc -> it:exec:proc +:pid=2044") == 1
            assert await core.count(f"it:exec:proc:pid=2044 +:exe=sha256:{ft.SAMPLE_SHA256}") == 1

            (flow,) = await core.nodes("inet:flow:dst=tcp://198.51.100.7:443")
            assert flow.get("dst:port") == 443 and flow.get("dst:txbytes") == 1024
            assert flow.get("src") == "tcp://10.127.0.5:49712"
            assert await core.count("inet:flow:dst=tcp://198.51.100.7:443 :src:proc -> it:exec:proc") == 1
            assert await core.count("inet:flow:dst=tcp://198.51.100.7:443 -(refs)> inet:fqdn=evil.example.com") == 1
            assert await core.count("inet:tls:ja3:sample=(tcp://10.127.0.5:49712, a0e9f5d64349fb13191bc781f81f42e1)") == 1
            assert await core.count("inet:tls:ja3s:sample=(tcp://198.51.100.7:443, 15af977ce25de452b96affa2addb1036)") == 1

            # Triage's ASN and country of the IPs.
            (ip,) = await core.nodes("inet:ipv4=198.51.100.7")
            assert ip.get("asn") == 64500 and ip.get("loc") == "us"

            (dns,) = await core.nodes("inet:dns:request")
            assert dns.get("query:name") == "evil.example.com" and dns.get("query:type") == 1
            assert dns.get("server") == "udp://8.8.8.8:53"
            assert await core.count("inet:dns:a=(evil.example.com, 198.51.100.7)") == 1

            (http,) = await core.nodes("inet:http:request")
            assert http.get("url") == "http://evil.example.com/jquery-3.3.1.min.js"
            assert http.get("response:code") == 200 and http.get("response:reason") == "OK"
            assert http.get("server") == "tcp://198.51.100.7:443"
            assert http.get("headers") == (("host", "evil.example.com"), ("user-agent", "Mozilla/5.0 (fake)"))
            assert http.get("response:headers") == (("server", "nginx"),)
            assert await core.count("inet:http:request :flow -> inet:flow") == 1

            (fadd,) = await core.nodes("it:exec:file:add")
            assert fadd.get("file") == f"sha256:{ft.DROPPED_SHA256}"
            assert fadd.get("path") == "c:/users/admin/appdata/roaming/upd.exe"
            assert await core.count(f"{SAMPLE} -(refs)> file:bytes=sha256:{ft.DROPPED_SHA256} +:name=upd.exe") == 1

            # The task nodes are linked to the meta:source too.
            for form in ("it:exec:proc", "inet:flow", "inet:dns:request", "inet:http:request",
                         "it:exec:file:add", "inet:tls:ja3:sample"):
                assert await core.count(f"{form} +{{ <(seen)- meta:source={SOURCE_GUID} }}") == await core.count(form), form

            # An existing ASN isn't overwritten.
            await core.nodes("inet:ipv4=198.51.100.7 [ :asn=1 ]")
            await core.stormlist(f"slib.hatching.enrich --sample {SID} --tasks")
            assert (await core.nodes("inet:ipv4=198.51.100.7"))[0].get("asn") == 1

    async def test_enrich_archive(self):
        async with hatchingSvc(self) as (core, svc, fake):
            # An archive whose member was the analyzed file.
            member = {"tasks": ["behavioral1"], "target": "invoice.exe", "sha256": ft.SAMPLE_SHA256,
                      "md5": ft.SAMPLE_MD5, "size": len(ft.SAMPLE_BYTES),
                      "tags": ["family:cobaltstrike"], "family": ["cobaltstrike"]}
            zipsha = "ab" * 32
            overview = json.loads(json.dumps(ft.OVERVIEW))
            overview["sample"].update({"target": "invoice.zip", "sha256": zipsha, "md5": None,
                                       "sha1": None, "sha512": None, "ssdeep": None})
            overview["targets"] = [member]
            fake.overviews[SID] = overview
            del fake.statics[SID]
            fake.samples[SID]["filename"] = "invoice.zip"

            msgs = await core.stormlist(f"slib.hatching.enrich --sample {SID} --tasks")
            self.stormHasNoWarnErr(msgs)
            (sub,) = await core.nodes(f"file:subfile:parent=sha256:{zipsha}")
            assert sub.get("child") == f"sha256:{ft.SAMPLE_SHA256}" and sub.get("path") == "invoice.exe"
            (exe,) = await core.nodes(SAMPLE)
            assert "rep.hatching.cobaltstrike" in exe.tags
            # The analyzed process ran the member, in the archive's sandbox.
            (proc,) = await core.nodes("it:exec:proc:pid=2044")
            assert proc.get("exe") == f"sha256:{ft.SAMPLE_SHA256}" and proc.get("sandbox:file") == f"sha256:{zipsha}"

    async def test_enrich_nodes(self):
        async with hatchingSvc(self) as (core, svc, fake):
            # By file:bytes, hash, and URL.
            msgs = await core.stormlist(f"[ file:bytes=sha256:{ft.SAMPLE_SHA256} ] | slib.hatching.enrich --yield")
            assert yielded(msgs) == [("file:bytes", f"sha256:{ft.SAMPLE_SHA256}")]
            assert fake.last("get", "/search")["query"]["query"] == f"sha256:{ft.SAMPLE_SHA256}"

            msgs = await core.stormlist(f"[ hash:md5={ft.SAMPLE_MD5} ] | slib.hatching.enrich --yield")
            assert yielded(msgs) == [("file:bytes", f"sha256:{ft.SAMPLE_SHA256}")]

            url = "https://example.com/login"
            fake.samples["261031-url"] = {"id": "261031-url", "status": "reported", "kind": "url",
                                          "url": url, "submitted": ft.SUBMITTED}
            fake.overviews["261031-url"] = {"sample": {"target": url},
                                            "analysis": {"score": 7, "tags": ["phishing"]}}
            msgs = await core.stormlist(f"[ inet:url={url} ] | slib.hatching.enrich --yield")
            self.stormHasNoWarnErr(msgs)
            assert yielded(msgs) == [("inet:url", url)]
            assert fake.last("get", "/search")["query"]["query"] == f'url:"{url}"'
            (node,) = await core.nodes(f"inet:url={url}")
            assert fake.last("get", "/search")["query"]["limit"] == "50"
            assert "rep.hatching.phishing" in node.tags
            assert await core.count(f"inet:url={url} -> it:av:scan:result:target:url +:verdict=30") == 1

            # Triage's url: search also matches malware whose config has the URL, that's not a URL analysis.
            c2url = "http://c2.example.com/gate.php"
            fake.samples["261031-c2"] = dict(ft.SAMPLE, id="261031-c2", url=c2url)
            msgs = await core.stormlist(f"[ inet:url={c2url} ] | slib.hatching.enrich")
            self.stormIsInWarn("has no reported sample", msgs)

            # Not found, unsupported, no hash, and not reported.
            msgs = await core.stormlist(f"[ hash:sha256={'a' * 64} ] | slib.hatching.enrich")
            self.stormIsInWarn("has no reported sample", msgs)
            msgs = await core.stormlist("[ inet:fqdn=vertex.link ] | slib.hatching.enrich")
            self.stormIsInWarn("The node form inet:fqdn is not supported", msgs)
            msgs = await core.stormlist("[ file:bytes=* ] | slib.hatching.enrich")
            self.stormIsInWarn("has no hash or URL", msgs)

            fake.samples[SID]["status"] = "running"
            msgs = await core.stormlist(f"slib.hatching.enrich --sample {SID}")
            self.stormIsInWarn("isn't reported yet", msgs)
            msgs = await core.stormlist(f"[ hash:sha256={ft.SAMPLE_SHA256} ] | slib.hatching.enrich")
            self.stormIsInWarn("has no reported sample", msgs)

    async def test_tags(self):
        async with hatchingSvc(self) as (core, svc, fake):
            await core.stormlist("slib.hatching.admin.tags --prefix rep.triage")
            await core.stormlist(f"slib.hatching.enrich --sample {SID}")
            (f,) = await core.nodes(SAMPLE)
            assert "rep.triage.cobaltstrike" in f.tags and "rep.hatching" not in f.tags
            nodes = await core.nodes("risk:tool:software:tag=rep.triage.cobaltstrike")
            assert len(nodes) == 1

            msgs = await core.stormlist("slib.hatching.admin.tags --disable")
            self.stormIsInPrint("enabled=false prefix=rep.triage", msgs)
            await core.stormlist(f"{SAMPLE} | [ -#rep ] | slib.hatching.enrich")
            (f,) = await core.nodes(SAMPLE)
            assert not f.tags

            msgs = await core.stormlist("slib.hatching.admin.tags --enable --disable")
            self.stormIsInErr("Use --enable or --disable, not both.", msgs)
            msgs = await core.stormlist("slib.hatching.admin.tags --enable")
            self.stormIsInPrint("enabled=true", msgs)


class TestStormSamples(s_tests.SynTest):

    async def test_search(self):
        async with hatchingSvc(self) as (core, svc, fake):
            msgs = await core.stormlist('slib.hatching.search "family:cobaltstrike" --limit 5')
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("1 samples matched family:cobaltstrike", msgs)
            self.stormIsInPrint(SID, msgs)
            self.stormIsInPrint("invoice.exe", msgs)
            assert fake.last()["query"] == {"query": "family:cobaltstrike", "limit": "5"}

            fake.samples["261031-pending"] = dict(ft.SAMPLE, id="261031-pending", status="pending")
            msgs = await core.stormlist('slib.hatching.search "" --yield')
            assert yielded(msgs) == [("file:bytes", f"sha256:{ft.SAMPLE_SHA256}")]
            self.stormIsInPrint("Skipping sample 261031-pending, it's pending.", msgs)

            msgs = await core.stormlist('slib.hatching.search "family:cobaltstrike" --model --tasks')
            assert not yielded(msgs) and await core.count("inet:flow") == 2

    async def test_samples_and_info(self):
        async with hatchingSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.hatching.samples --subset org --limit 3")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(SID, msgs)
            assert fake.last()["query"] == {"subset": "org", "limit": "3"}

            msgs = await core.stormlist("slib.hatching.samples --subset bad")
            self.stormIsInErr("Invalid choice for argument --subset", msgs)

            msgs = await core.stormlist(f"slib.hatching.sample.info {SID}")
            assert json.loads(prints(msgs))["filename"] == "invoice.exe"
            msgs = await core.stormlist(f"slib.hatching.sample.info {ft.SAMPLE_SHA256} --summary")
            assert json.loads(prints(msgs))["score"] == 10
            msgs = await core.stormlist("slib.hatching.sample.info nope")
            self.stormIsInWarn("Getting sample nope failed", msgs)

    async def test_report_kernel_events(self):
        async with hatchingSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(f"slib.hatching.report {SID}")
            assert json.loads(prints(msgs))["analysis"]["score"] == 10
            msgs = await core.stormlist(f"slib.hatching.report {SID} --static")
            assert json.loads(prints(msgs))["files"][0]["mime"] == "application/x-dosexec"
            msgs = await core.stormlist(f"slib.hatching.report {SID} --task behavioral1")
            assert json.loads(prints(msgs))["task"]["id"] == "behavioral1"
            msgs = await core.stormlist(f"slib.hatching.report {SID} --task behavioral9")
            self.stormIsInWarn("REPORT_NOT_AVAILABLE", msgs)

            msgs = await core.stormlist(f"slib.hatching.kernel {SID} behavioral1")
            assert [json.loads(line) for line in prints(msgs).splitlines()] == ft.KERNEL_EVENTS
            msgs = await core.stormlist(f"slib.hatching.kernel {SID} behavioral1 --log stahp")
            self.stormIsInWarn("Reading the kernel log", msgs)

            msgs = await core.stormlist(f"slib.hatching.events --sample {SID}")
            for status in ft.EVENTS:
                self.stormIsInPrint(f"{SID} {status}", msgs)
            msgs = await core.stormlist("slib.hatching.events --limit 2")
            assert len(prints(msgs).splitlines()) == 2

            msgs = await core.stormlist(f"slib.hatching.sample.wait {SID} --timeout 5 --yield")
            self.stormIsInPrint(f"Sample {SID} is reported.", msgs)
            assert yielded(msgs) == [("file:bytes", f"sha256:{ft.SAMPLE_SHA256}")]

    async def test_download(self):
        async with hatchingSvc(self) as (core, svc, fake):
            axon = core.axon

            msgs = await core.stormlist(f"[ hash:md5={ft.SAMPLE_MD5} ] | slib.hatching.download --yield")
            self.stormHasNoWarnErr(msgs)
            assert yielded(msgs) == [("file:bytes", f"sha256:{ft.SAMPLE_SHA256}")]
            assert await axon.has(bytes.fromhex(ft.SAMPLE_SHA256))
            (f,) = await core.nodes(SAMPLE)
            assert f.get("name") == "invoice.exe" and f.get("size") == len(ft.SAMPLE_BYTES)
            assert await core.count(f"meta:source={SOURCE_GUID} -(seen)> {SAMPLE}") == 1

            msgs = await core.stormlist(f"slib.hatching.download --sample {SID} --pcap --pcapng --dumped --yield")
            self.stormHasNoWarnErr(msgs)
            import hashlib
            pcap = hashlib.sha256(ft.PCAP_BYTES).hexdigest()
            assert yielded(msgs) == [("file:bytes", f"sha256:{pcap}")] * 2 + [
                ("file:bytes", f"sha256:{ft.DROPPED_SHA256}")]
            (dropped,) = await core.nodes(f"file:bytes=sha256:{ft.DROPPED_SHA256}")
            assert dropped.get("name") == "upd.exe"
            assert fake.last("get", "/dump.pcapng") is not None

            msgs = await core.stormlist(
                f"slib.hatching.download --sample {SID} --task behavioral1 --file files/0x0003000000022c2b-1.dat --yield")
            assert yielded(msgs) == [("file:bytes", f"sha256:{ft.DROPPED_SHA256}")]

            msgs = await core.stormlist(f"slib.hatching.download --sample {SID} --archive zip --yield")
            (node,) = await core.nodes(f"file:bytes={yielded(msgs)[0][1]}")
            assert node.get("name") == f"{SID}.zip"

            # Errors.
            msgs = await core.stormlist(f"slib.hatching.download --sample {SID} --file x")
            self.stormIsInErr("--file requires --task", msgs)
            msgs = await core.stormlist(f"slib.hatching.download --sample {SID} --task behavioral1 --file nope")
            self.stormIsInWarn("NOT_FOUND", msgs)
            msgs = await core.stormlist(f"[ hash:sha256={'a' * 64} ] | slib.hatching.download")
            self.stormIsInWarn("has no sample", msgs)
            msgs = await core.stormlist("[ file:bytes=* ] | slib.hatching.download")
            self.stormIsInWarn("has no hash", msgs)

            fake.samples["261031-url"] = {"id": "261031-url", "status": "reported", "kind": "url",
                                          "url": "http://a.com", "submitted": ft.SUBMITTED}
            msgs = await core.stormlist("slib.hatching.download --sample 261031-url")
            self.stormIsInWarn("is a URL, there is no file to download", msgs)

        async with hatchingSvc(self, conf={"hatching:maxsize": 4}) as (core, svc, fake):
            msgs = await core.stormlist(f"slib.hatching.download --sample {SID}")
            self.stormIsInWarn("larger than the max", msgs)


class TestStormSubmit(s_tests.SynTest):

    async def test_submit_file(self):
        async with hatchingSvc(self) as (core, svc, fake):
            (size, sha256) = await core.axon.put(b"MZ submitted file")
            sha256 = sha256.hex()
            q = (f"[ file:bytes=sha256:{sha256} :size={size} :name=payload.exe ] | slib.hatching.submit "
                 "--profile win10-internet --profile w7:payload.exe --tag case.1 --network drop --timeout 120 "
                 "--password infected")
            msgs = await core.stormlist(q)
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(f"Submitted {sha256} as sample 261031-new000001 (pending).", msgs)

            req = fake.last("post", "/samples")
            assert req["files"]["file"] == ("payload.exe", b"MZ submitted file")
            assert json.loads(req["form"]["_json"]) == {
                "kind": "file", "target": "payload.exe", "password": "infected",
                "profiles": [{"profile": "win10-internet"}, {"profile": "w7", "pick": "payload.exe"}],
                "user_tags": ["case.1"], "defaults": {"timeout": 120, "network": "drop"},
            }

            # Not in the Axon, no SHA256, and unsupported forms.
            msgs = await core.stormlist(f"[ file:bytes=sha256:{'b' * 64} :size=10 ] | slib.hatching.submit")
            self.stormIsInWarn("The Axon doesn't have", msgs)
            msgs = await core.stormlist("[ file:bytes=* ] | slib.hatching.submit")
            self.stormIsInWarn("has no SHA256", msgs)
            msgs = await core.stormlist("[ inet:fqdn=vertex.link ] | slib.hatching.submit")
            self.stormIsInWarn("The node form inet:fqdn is not supported", msgs)
            msgs = await core.stormlist(f"file:bytes=sha256:{sha256} [ -:size ] | slib.hatching.submit")
            self.stormIsInWarn("size is unknown", msgs)

        async with hatchingSvc(self, conf={"hatching:maxsize": 4}) as (core, svc, fake):
            (size, sha256) = await core.axon.put(b"too big")
            msgs = await core.stormlist(f"[ file:bytes=sha256:{sha256.hex()} :size={size} ] | slib.hatching.submit")
            self.stormIsInWarn("larger than the max of 4", msgs)

    async def test_submit_wait(self):
        async with hatchingSvc(self) as (core, svc, fake):
            # The fake server reports a sample once its events are read. Give the sample that
            # will be submitted the seeded sample's overview report.
            fake.overviews["261031-new000001"] = fake.overviews[SID]
            (size, sha256) = await core.axon.put(b"MZ waited")

            q = f"[ file:bytes=sha256:{sha256.hex()} :size={size} ] | slib.hatching.submit --wait 10 --tasks --yield"
            msgs = await core.stormlist(q)
            self.stormIsInPrint("Modeled sample 261031-new000001", msgs)
            # The new sample has no task reports, so only its overview is modeled.
            self.stormIsInWarn("The behavioral1 report of 261031-new000001 is unavailable", msgs)
            assert yielded(msgs) == [("file:bytes", f"sha256:{ft.SAMPLE_SHA256}")]
            assert fake.samples["261031-new000001"]["status"] == "reported"

            # Waiting on a running sample.
            fake.samples[SID]["status"] = "running"
            msgs = await core.stormlist(f"slib.hatching.sample.wait {SID} --timeout 5 --yield")
            self.stormIsInPrint(f"Sample {SID} is reported.", msgs)

            # A failed analysis isn't modeled.
            fake.overviews.pop("261031-new000001")
            fake.samples["261031-new000001"]["status"] = "failed"
            msgs = await core.stormlist("slib.hatching.enrich --sample 261031-new000001")
            self.stormIsInWarn("isn't reported yet (its status is failed)", msgs)

    async def test_submit_url(self):
        async with hatchingSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.hatching.submit --url https://example.com/login --tag phish")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("Submitted https://example.com/login as sample 261031-new000001", msgs)
            assert fake.last("post", "/samples")["json"] == {
                "kind": "url", "url": "https://example.com/login", "user_tags": ["phish"]}

            msgs = await core.stormlist("[ inet:url=https://example.com/a.exe ] | slib.hatching.submit --fetch --interactive --wait 5")
            self.stormIsInWarn("Not waiting on interactive sample 261031-new000002", msgs)
            assert fake.last("post", "/samples")["json"] == {
                "kind": "fetch", "url": "https://example.com/a.exe", "interactive": True}

            # Pick its profiles, then delete it.
            msgs = await core.stormlist("slib.hatching.sample.profile 261031-new000002 --profile win10-internet")
            self.stormIsInPrint("Set the profiles of sample 261031-new000002", msgs)
            assert fake.last()["json"] == {"auto": False, "profiles": [{"profile": "win10-internet"}]}
            msgs = await core.stormlist("slib.hatching.sample.profile 261031-new000002 --auto --pick a.exe")
            self.stormIsInWarn("PROFILE_NOT_SETTABLE", msgs)
            msgs = await core.stormlist("slib.hatching.sample.profile 261031-new000002")
            self.stormIsInWarn("Use --profile or --pick at least once, or --auto.", msgs)
            # Picking files without profiles lets the sandbox pick their profiles.
            fake.samples["261031-new000002"]["status"] = "static_analysis"
            msgs = await core.stormlist("slib.hatching.sample.profile 261031-new000002 --pick a.exe")
            assert fake.last("post", "/profile")["json"] == {"auto": True, "pick": ["a.exe"]}

            msgs = await core.stormlist("slib.hatching.sample.delete 261031-new000002 261031-new000001")
            self.stormIsInPrint("Deleted sample 261031-new000002.", msgs)
            self.stormIsInPrint("Deleted sample 261031-new000001.", msgs)
            assert "261031-new000002" not in fake.samples
            msgs = await core.stormlist("slib.hatching.sample.delete 261031-new000002")
            self.stormIsInWarn("NOT_FOUND", msgs)

            msgs = await core.stormlist("slib.hatching.submit --url ''")
            self.stormIsInWarn("Submitting", msgs)

            # VPN analyses, and the timeout and profile limits.
            msgs = await core.stormlist("slib.hatching.submit --url https://a.com/ --network vpn --geolocation us --timeout 300")
            self.stormHasNoWarnErr(msgs)
            assert fake.last("post", "/samples")["json"]["defaults"] == {
                "timeout": 300, "network": "vpn", "geolocation": "us"}
            msgs = await core.stormlist("slib.hatching.submit --url https://a.com/ --geolocation us")
            self.stormIsInWarn("A geolocation requires the vpn network", msgs)
            msgs = await core.stormlist("slib.hatching.submit --url https://a.com/ --timeout 4000")
            self.stormIsInWarn("between 1 and 3600", msgs)
            msgs = await core.stormlist("slib.hatching.submit --url https://a.com/ --network bad")
            self.stormIsInErr("Invalid choice for argument --network", msgs)
            msgs = await core.stormlist("slib.hatching.submit --url https://a.com/ --interactive --profile w10")
            self.stormIsInWarn("Profiles can't be picked for an interactive submission", msgs)

            # Importing public samples.
            msgs = await core.stormlist("slib.hatching.sample.import https://tria.ge/261031-public1")
            self.stormIsInPrint("Imported https://tria.ge/261031-public1 as", msgs)
            assert fake.last("post", "/samples")["json"] == {"kind": "import",
                                                             "url": "https://tria.ge/261031-public1"}


class TestStormManage(s_tests.SynTest):

    async def test_profiles(self):
        async with hatchingSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.hatching.profile.list")
            self.stormIsInPrint("win10-internet", msgs)
            self.stormIsInPrint("windows10", msgs)

            msgs = await core.stormlist("slib.hatching.profile.add win7-drop --tag windows7 --network drop --timeout 300")
            self.stormIsInPrint("Added profile win7-drop", msgs)
            msgs = await core.stormlist("slib.hatching.profile.add win7-drop")
            self.stormIsInWarn("PROFILE_ALREADY_EXISTS", msgs)

            msgs = await core.stormlist("slib.hatching.profile.edit win7-drop --timeout 600 --name win7")
            self.stormIsInPrint("Updated profile win7: network=drop timeout=600 tags=windows7", msgs)
            msgs = await core.stormlist("slib.hatching.profile.edit win7 --tag a --tag b")
            self.stormIsInPrint("tags=a,b", msgs)

            msgs = await core.stormlist("slib.hatching.profile.add win7-vpn --tag windows7 --network vpn --geolocation de")
            self.stormHasNoWarnErr(msgs)
            msgs = await core.stormlist("slib.hatching.profile.list")
            self.stormIsInPrint("win7-vpn", msgs)
            self.stormIsInPrint(" de ", msgs)
            msgs = await core.stormlist("slib.hatching.profile.edit win7-vpn --timeout 60")
            self.stormIsInPrint("network=vpn (de) timeout=60", msgs)
            msgs = await core.stormlist("slib.hatching.profile.edit win7-vpn --timeout 4000")
            self.stormIsInWarn("between 1 and 3600", msgs)

            msgs = await core.stormlist("slib.hatching.profile.del win7 nope")
            self.stormIsInPrint("Deleted profile win7.", msgs)
            self.stormIsInWarn("Deleting profile nope failed", msgs)

    async def test_yara(self):
        async with hatchingSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.hatching.yara.list")
            self.stormIsInPrint("fake_rule.yara", msgs)

            msgs = await core.stormlist("slib.hatching.yara.get fake_rule.yara")
            self.stormIsInPrint("rule fake_rule", msgs)
            msgs = await core.stormlist("slib.hatching.yara.get fake_rule.yara --yield")
            (node,) = [m[1] for m in msgs if m[0] == "node"]
            assert node[0][0] == "it:app:yara:rule" and node[1]["props"]["name"] == "fake_rule.yara"
            msgs = await core.stormlist("slib.hatching.yara.get nope")
            self.stormIsInWarn("NOT_FOUND", msgs)

            q = '[ it:app:yara:rule=* :name=hunt :text="rule hunt { condition: true }" ] | slib.hatching.yara.add'
            msgs = await core.stormlist(q)
            self.stormIsInPrint("Added Yara rule hunt.yara.", msgs)
            assert fake.rules["hunt.yara"]["rule"] == "rule hunt { condition: true }"

            msgs = await core.stormlist('slib.hatching.yara.add --name hunt.yara --text "rule hunt { condition: false }" --update')
            self.stormIsInPrint("Updated Yara rule hunt.yara.", msgs)
            assert fake.rules["hunt.yara"]["rule"] == "rule hunt { condition: false }"

            msgs = await core.stormlist("slib.hatching.yara.add --name hunt2.yara --rename hunt.yara")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("Renamed Yara rule hunt.yara to hunt2.yara.", msgs)
            assert fake.last("put")["json"] == {"name": "hunt2.yara", "rule": "rule hunt { condition: false }"}

            msgs = await core.stormlist('slib.hatching.yara.add --name bad.yara --text "rule bad {"')
            self.stormIsInWarn("COMPILE_ERROR", msgs)
            msgs = await core.stormlist("[ it:app:yara:rule=* ] | slib.hatching.yara.add")
            self.stormIsInWarn("A rule needs a name and text.", msgs)
            msgs = await core.stormlist("[ inet:fqdn=vertex.link ] | slib.hatching.yara.add")
            self.stormIsInWarn("The node form inet:fqdn is not supported", msgs)

            msgs = await core.stormlist("slib.hatching.yara.del hunt.yara")
            self.stormIsInPrint("Deleted Yara rule hunt.yara.", msgs)
            assert "hunt.yara" not in fake.rules


class TestStormAdmin(s_tests.SynTest):

    async def test_apikeys(self):
        async with hatchingSvc(self, apikey=None) as (core, svc, fake):
            msgs = await core.stormlist(f"slib.hatching.enrich --sample {SID}")
            self.stormIsInWarn("No Hatching Triage API key is available", msgs)

            msgs = await core.stormlist("slib.hatching.admin.apikey")
            self.stormIsInPrint("No service-wide API key is set.", msgs)
            msgs = await core.stormlist(f"slib.hatching.admin.apikey {ft.APIKEY}")
            self.stormIsInPrint("Set the slib.hatching API key.", msgs)
            msgs = await core.stormlist("slib.hatching.admin.apikey")
            self.stormIsInPrint("A service-wide API key is set.", msgs)
            msgs = await core.stormlist(f"slib.hatching.enrich --sample {SID}")
            self.stormHasNoWarnErr(msgs)

            # A user's own key takes precedence.
            msgs = await core.stormlist("slib.hatching.apikey")
            self.stormIsInPrint("You don't have a Hatching Triage API key set.", msgs)
            msgs = await core.stormlist("slib.hatching.apikey badkey")
            self.stormIsInPrint("Saved your Hatching Triage API key in vault hatching:root.", msgs)
            msgs = await core.stormlist("slib.hatching.apikey")
            self.stormIsInPrint("is set in vault hatching:root", msgs)
            msgs = await core.stormlist(f"slib.hatching.enrich --sample {SID}")
            self.stormIsInWarn("UNAUTHORIZED", msgs)
            assert fake.requests[-1]["headers"]["Authorization"] == "Bearer badkey"

            msgs = await core.stormlist(f"slib.hatching.apikey {ft.APIKEY}")
            self.stormIsInPrint("Updated your Hatching Triage API key.", msgs)
            msgs = await core.stormlist("slib.hatching.apikey --clear")
            self.stormIsInPrint("Deleted your Hatching Triage API key.", msgs)
            msgs = await core.stormlist("slib.hatching.apikey --clear")
            self.stormIsInPrint("You don't have a Hatching Triage API key set.", msgs)

            msgs = await core.stormlist("slib.hatching.admin.apikey --clear")
            self.stormIsInPrint("Cleared the slib.hatching API key.", msgs)

    async def test_request(self):
        async with hatchingSvc(self) as (core, svc, fake):
            msgs = await core.stormlist('slib.hatching.admin.request /v0/samples --params ({"subset": "org", "limit": 1})')
            assert json.loads(prints(msgs))["data"][0]["id"] == SID
            assert fake.last()["query"] == {"subset": "org", "limit": "1"}

            msgs = await core.stormlist('slib.hatching.admin.request /v0/yara --method post --json ({"name": "r.yara", "rule": "rule r { condition: true }"})')
            self.stormHasNoWarnErr(msgs)
            assert "r.yara" in fake.rules

            msgs = await core.stormlist("slib.hatching.admin.request /v0/nope")
            self.stormIsInWarn("get /v0/nope failed", msgs)

    async def test_users(self):
        async with hatchingSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.hatching.admin.users --limit 10")
            self.stormIsInPrint("analyst@example.com", msgs)
            assert fake.last()["query"]["limit"] == "10"

            msgs = await core.stormlist("slib.hatching.admin.user.add bob --password pw --name 'Bob B' --role org_basic")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("Added user", msgs)
            self.stormIsInPrint("(user-1) with the role org_basic.", msgs)
            assert fake.last()["json"] == {"username": "bob", "password": "pw", "name": "Bob B",
                                           "role": "org_basic"}
            msgs = await core.stormlist("slib.hatching.admin.user.add eve@example.com --confirmed")
            assert fake.last()["json"] == {"email": "eve@example.com", "email_confirmed": True}
            msgs = await core.stormlist("slib.hatching.admin.user.add x --role root")
            self.stormIsInErr("Invalid choice for argument --role", msgs)

            msgs = await core.stormlist("slib.hatching.admin.user.key.add user-1 ci")
            self.stormIsInPrint("Created API key ci for user-1: newkey", msgs)
            msgs = await core.stormlist("slib.hatching.admin.user.keys user-1")
            self.stormIsInPrint("newk...", msgs)
            assert "newkey0000" not in prints(msgs)
            msgs = await core.stormlist("slib.hatching.admin.user.key.del user-1 ci nope")
            self.stormIsInPrint("Deleted API key ci of user-1.", msgs)
            self.stormIsInWarn("Deleting API key nope of user-1 failed", msgs)

            msgs = await core.stormlist("slib.hatching.admin.user.del user-1")
            self.stormIsInPrint("Deleted user user-1.", msgs)
            msgs = await core.stormlist("slib.hatching.admin.user.keys user-1")
            self.stormIsInWarn("NOT_FOUND", msgs)

    async def test_org(self):
        async with hatchingSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.hatching.admin.org")
            assert json.loads(prints(msgs)) == {"magic_link": {"enabled": True}}
            msgs = await core.stormlist("slib.hatching.admin.org --magic off")
            self.stormIsInPrint("Turned magic links off.", msgs)
            assert fake.org_settings == {"magic_link": {"enabled": False}}
            msgs = await core.stormlist("slib.hatching.admin.org --stats")
            assert json.loads(prints(msgs))["samples_submitted"] == len(fake.samples)

            # Magic links are refused while they're off.
            msgs = await core.stormlist(f"slib.hatching.sample.info {SID} --link")
            self.stormIsInWarn("FORBIDDEN", msgs)
            await core.stormlist("slib.hatching.admin.org --magic on")
            msgs = await core.stormlist(f"slib.hatching.sample.info {SID} --link")
            self.stormIsInPrint(f"{fake.url}/{SID}/magic/{ft.MAGIC_TOKEN}", msgs)


class TestStormInfo(s_tests.SynTest):

    async def test_resources_geolocations_stats(self):
        async with hatchingSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.hatching.resources")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("win10v2004-20260901-en", msgs)
            self.stormIsInPrint("os:windows10-2004-x64,locale:en-us", msgs)
            msgs = await core.stormlist("slib.hatching.geolocations")
            self.stormIsInPrint("geo:de", msgs)
            msgs = await core.stormlist("slib.hatching.stats")
            assert json.loads(prints(msgs)) == {"samples_submitted": 1}

    async def test_urlscan(self):
        async with hatchingSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(f"slib.hatching.report {SID} --urlscan")
            assert json.loads(prints(msgs))["effective_url"] == "https://evil.example.com/login"
            msgs = await core.stormlist(f"slib.hatching.download --sample {SID} --screenshot --yield")
            self.stormHasNoWarnErr(msgs)
            assert yielded(msgs) == [("file:bytes", f"sha256:{hashlib.sha256(ft.SCREENSHOT_BYTES).hexdigest()}")]


class TestStormPerms(s_tests.SynTest):

    async def test_perms(self):
        async with hatchingSvc(self) as (core, svc, fake):
            visi = await core.auth.addUser("visi")
            opts = {"user": visi.iden}

            msgs = await core.stormlist(f"slib.hatching.enrich --sample {SID}", opts=opts)
            self.stormIsInErr("slib.hatching.user", msgs)

            await visi.addRule((True, ("slib", "hatching", "user")))
            # Without node permissions, the user can query but not model.
            msgs = await core.stormlist(f"slib.hatching.sample.info {SID}", opts=opts)
            self.stormHasNoWarnErr(msgs)
            msgs = await core.stormlist(f"slib.hatching.enrich --sample {SID}", opts=opts)
            self.stormIsInErr("must have permission node.add", msgs)

            await visi.addRule((True, ("node",)))
            msgs = await core.stormlist(f"slib.hatching.enrich --sample {SID} --yield", opts=opts)
            self.stormHasNoWarnErr(msgs)
            assert yielded(msgs) == [("file:bytes", f"sha256:{ft.SAMPLE_SHA256}")]

            for cmd in ("slib.hatching.submit --url http://a.com", "slib.hatching.sample.delete x",
                        "slib.hatching.profile.add x", "slib.hatching.yara.del x",
                        "slib.hatching.admin.apikey", "slib.hatching.admin.users",
                        "slib.hatching.sample.import x", "slib.hatching.admin.org"):
                msgs = await core.stormlist(cmd, opts=opts)
                self.stormIsInErr("requires permission: slib.hatching", msgs)

            # The service's stored key can't be read from Storm.
            msgs = await core.stormlist('$lib.service.get("slib.hatching")', opts=opts)
            self.stormIsInErr("must have permission service.get", msgs)

            await visi.addRule((True, ("slib", "hatching", "submit")))
            msgs = await core.stormlist("slib.hatching.submit --url http://a.com", opts=opts)
            self.stormHasNoWarnErr(msgs)

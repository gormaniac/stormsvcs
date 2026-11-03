"""Pytests for the slib.anyrun Storm package (commands, modules, modeling, and perms)."""

import copy
import hashlib
import pathlib
import tomllib

import synapse.tests.utils as s_tests

from anyrunsvc import __version__
from anyrunsvc.defs import PKGDEFS, SOURCE_GUID, SVC_NAME

from . import fakeanyrun as fa

CMDS = tuple(cmd["name"] for cmd in PKGDEFS[0]["commands"])
MODS = tuple(mod["name"] for mod in PKGDEFS[0]["modules"])

SAMPLE = f"file:bytes=sha256:{fa.SAMPLE_SHA256}"
IVAL = (1793448000000, 1793448060000)


def prints(msgs) -> str:
    return "\n".join(m[1]["mesg"] for m in msgs if m[0] == "print")


def warns(msgs) -> str:
    return "\n".join(m[1]["mesg"] for m in msgs if m[0] == "warn")


def yielded(msgs) -> list:
    return [m[1][0] for m in msgs if m[0] == "node"]


class TestStormPkg(s_tests.SynTest):
    def test_versions_match(self):
        # The version lives in pyproject.toml (the image tag), __init__.py, the package yaml,
        # and the service's uv.lock entry.
        root = pathlib.Path(__file__).parent.parent
        with (root / "pyproject.toml").open("rb") as fd:
            assert tomllib.load(fd)["project"]["version"] == __version__
        assert PKGDEFS[0]["version"] == __version__
        with (root / "uv.lock").open("rb") as fd:
            pkgs = tomllib.load(fd)["package"]
        assert [p["version"] for p in pkgs if p["name"] == "anyrunsvc"] == [__version__]

    async def test_pkg(self):
        assert len(CMDS) == 20

        async with fa.anyrunSvc(self) as (core, svc, fake):
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

            # The service add event creates the meta:source and the tag settings.
            nodes = await core.nodes(f"meta:source={SOURCE_GUID}")
            assert len(nodes) == 1 and nodes[0].get("name") == "any.run"
            assert nodes[0].get("type") == "slib.anyrun"

            msgs = await core.stormlist("slib.anyrun.admin.tags")
            self.stormIsInPrint("enabled=true prefix=rep.anyrun", msgs)


class TestStormEnrich(s_tests.SynTest):
    async def test_enrich_task(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(f"slib.anyrun.enrich --task {fa.TASK} --yield")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(
                f"Modeled task {fa.TASK} (Malicious activity, families=AgentTesla, processes=2).", msgs
            )
            assert yielded(msgs) == [("file:bytes", f"sha256:{fa.SAMPLE_SHA256}")]

            (f,) = await core.nodes(SAMPLE)
            assert f.get("md5") == fa.SAMPLE_MD5 and f.get("sha1") == fa.SAMPLE_SHA1
            assert f.get("name") == "invoice.exe" and f.get("mime") == "application/x-dosexec"
            assert f.get("ssdeeps") == (fa.SAMPLE_SSDEEP,)
            for tag in ("agenttesla", "stealer", "my_tag"):
                assert f.tags[f"rep.anyrun.{tag}"] == IVAL, tag
            assert await core.count(f"{SAMPLE} <(seen)- meta:source={SOURCE_GUID}") == 1

            # The verdict, families, techniques, and mutexes.
            (scan,) = await core.nodes(f"{SAMPLE} -> it:av:scan:result:target:file")
            assert scan.get("scanner:name") == "any.run" and scan.get("verdict") == 40
            assert scan.get("signame") == "agenttesla" and scan.get("time") == IVAL[0]
            assert scan.get("categories") == ("agenttesla", "my_tag", "stealer")
            (fam,) = await core.nodes("risk:tool:software:reporter:name=any.run")
            assert fam.get("soft:name") == "agenttesla" and fam.get("tag") == "rep.anyrun.agenttesla"
            ttps = {n.repr() for n in await core.nodes(f"{SAMPLE} -(uses)> it:mitre:attack:technique")}
            assert ttps == {"T1555", "T1059.003"}
            mutexes = {n.repr() for n in await core.nodes(f"{SAMPLE} -(refs)> it:dev:mutex")}
            assert mutexes == {"Global\\AgentMutex1"}

            # The malware config, with its C2 servers tagged.
            (conf,) = await core.nodes("it:sec:c2:config")
            assert conf.get("family") == "agenttesla" and conf.get("file") == f"sha256:{fa.SAMPLE_SHA256}"
            assert conf.get("servers") == ("tcp://c2.evil.example.com:587", "tcp://198.51.100.7:8080")
            assert conf.get("raw")["config"]["Options"] == {"Protocol": "smtp"}
            for query in (
                "inet:url=tcp://c2.evil.example.com:587",
                "inet:fqdn=c2.evil.example.com",
                "inet:ipv4=198.51.100.7",
            ):
                (n,) = await core.nodes(query)
                assert n.tags["rep.anyrun.c2"] == IVAL and n.tags["rep.anyrun.agenttesla"] == IVAL

            # Processes.
            procs = await core.nodes(f"it:exec:proc:sandbox:file={SAMPLE.split('=', 1)[1]}")
            assert len(procs) == 2
            (main,) = await core.nodes("it:exec:proc:pid=4321")
            assert main.get("exe") == f"sha256:{fa.SAMPLE_SHA256}" and main.get("time") == 1793448001000
            assert main.get("path") == "c:/users/admin/appdata/local/temp/invoice.exe"
            assert main.get("exitcode") == 0
            (child,) = await core.nodes("it:exec:proc:pid=5555")
            assert child.get("src:proc") == main.ndef[1] and child.get("cmd") == "cmd.exe /c whoami"

            # DNS, HTTP, connections, and Suricata alerts.
            (dns,) = await core.nodes("inet:dns:request")
            assert dns.get("query:name") == "c2.evil.example.com" and dns.get("sandbox:file")
            assert await core.count("inet:dns:a=(c2.evil.example.com, 203.0.113.10)") == 1
            assert await core.count("inet:dns:aaaa=(c2.evil.example.com, 2001:db8::10)") == 1
            (http,) = await core.nodes("inet:http:request")
            assert http.get("url") == "http://c2.evil.example.com/gate.php" and http.get("method") == "POST"
            assert http.get("server") == "tcp://203.0.113.10:80" and http.get("response:code") == 200
            assert http.get("headers") == (("user-agent", "Mozilla/5.0"),) and http.get("proc") == main.ndef[1]
            (flow,) = await core.nodes("inet:flow:dst:port=443")
            assert flow.get("dst") == "tcp://203.0.113.10:443" and flow.get("dst:ipv4") == 0xCB00710A
            assert flow.get("src:proc") == main.ndef[1] and flow.get("sandbox:file")
            (ip,) = await core.nodes("inet:ipv4=203.0.113.10")
            assert ip.get("asn") == 64500 and ip.get("loc") == "us"
            (match,) = await core.nodes("it:app:suricata:matched")
            (rule,) = await core.nodes("it:app:suricata:rule")
            assert rule.get("id") == "2030171" and rule.get("name") == "ET MALWARE AgentTesla Exfil Via HTTP"
            (aflow,) = await core.nodes("it:app:suricata:matched -> inet:flow")
            assert match.get("rule") == rule.ndef[1] and match.get("target") == aflow.ndef[1]
            assert aflow.get("src") == "tcp://10.0.2.15:49712" and aflow.get("dst:port") == 80

            # Created files, tagged with ANY.RUN's threat level for them.
            (add,) = await core.nodes(f"it:exec:file:add:file=sha256:{fa.DROPPED_SHA256}")
            assert add.get("proc") == main.ndef[1] and add.get("sandbox:file")
            assert add.get("path") == "c:/users/admin/appdata/roaming/payload.dll"
            assert add.tags["rep.anyrun.threat_lvl.high"] == IVAL
            assert await core.count(f"{SAMPLE} -(refs)> file:bytes:sha256={fa.DROPPED_SHA256}") == 1
            # A file without a SHA256 is modeled by path, with its MD5.
            (add,) = await core.nodes("it:exec:file:add:path=c:/users/admin/notes.txt")
            assert add.get("file") is None and "rep.anyrun.threat_lvl.unknown" in add.tags
            assert await core.count("it:exec:file:add:path=c:/users/admin/notes.txt -(refs)> hash:md5") == 1

            # File operations from the incidents.
            (write,) = await core.nodes("it:exec:file:write")
            assert write.get("path") == "c:/users/admin/notes.txt" and write.get("proc") == main.ndef[1]
            assert "rep.anyrun.threat_lvl.unknown" in write.tags
            dels = {n.get("path") for n in await core.nodes("it:exec:file:del")}
            assert dels == {"c:/users/admin/appdata/local/temp/invoice.exe", "c:/users/admin/a.tmp"}
            assert await core.count("it:exec:file:add:path=c:/users/admin/b.exe") == 1
            (drop,) = await core.nodes("it:exec:file:add:path=c:/users/admin/second.bin")
            assert drop.get("file") == f"sha256:{fa.DROP2_SHA256}" and not drop.tags
            assert await core.count(f"{SAMPLE} -(refs)> file:bytes:sha256={fa.DROP2_SHA256}") == 1
            assert await core.count("it:exec:file:add") == 4
            assert await core.count("it:exec:file:read") == 0

            # Registry operations.
            run = f"{fa.RUNKEY}\\Updater"
            (rset,) = await core.nodes("it:exec:reg:set:reg::key=$key", opts={"vars": {"key": run}})
            assert rset.get("proc") == main.ndef[1] and rset.get("time") == 1793448011000
            assert rset.get("sandbox:file") == f"sha256:{fa.SAMPLE_SHA256}"
            (rval,) = await core.nodes("it:exec:reg:set:reg::key=$key -> it:dev:regval", opts={"vars": {"key": run}})
            assert rval.get("str") == "C:\\Users\\admin\\AppData\\Roaming\\payload.dll"
            assert await core.count("it:dev:regkey=$key", opts={"vars": {"key": run}}) == 1
            (count,) = await core.nodes("it:dev:regval:key=HKEY_CURRENT_USER\\SOFTWARE\\Agent\\Count")
            assert count.get("int") == 16
            assert await core.count("it:exec:reg:set") == 3
            assert await core.count("it:exec:reg:del") == 2
            (rdel,) = await core.nodes("it:exec:reg:del:reg::key=HKEY_CURRENT_USER\\SOFTWARE\\Old")
            assert rdel.get("proc") == child.ndef[1]
            assert await core.count("it:exec:reg:get") == 0

            # Modeling again updates the same nodes.
            count = await core.count(".created")
            msgs = await core.stormlist(f"slib.anyrun.enrich --task https://app.any.run/tasks/{fa.TASK}")
            self.stormHasNoWarnErr(msgs)
            assert await core.count(".created") == count

            # Reads only with --reads.
            msgs = await core.stormlist(f"slib.anyrun.enrich --task {fa.TASK} --reads")
            self.stormHasNoWarnErr(msgs)
            (read,) = await core.nodes("it:exec:file:read")
            assert read.get("path") == "c:/windows/win.ini"
            (get,) = await core.nodes("it:exec:reg:get -> it:dev:regval")
            assert get.get("key") == "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid"

    async def test_regval_shared(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            # The same value set by two tasks is one it:dev:regval.
            report = fa.fileReport(fake.url)
            report["analysis"]["uuid"] = fa.NEWTASK
            fake.state["reports"][fa.NEWTASK] = report
            for task in (fa.TASK, fa.NEWTASK):
                msgs = await core.stormlist(f"slib.anyrun.enrich --task {task}")
                self.stormHasNoWarnErr(msgs)
            run = f"{fa.RUNKEY}\\Updater"
            assert await core.count("it:exec:reg:set:reg::key=$key", opts={"vars": {"key": run}}) == 2
            assert await core.count("it:dev:regval:key=$key", opts={"vars": {"key": run}}) == 1

            # Turning tags off drops the threat level tags too.
            await core.callStorm("slib.anyrun.admin.tags --disable")
            await core.nodes("it:exec:file:add | [ -#rep ]")
            msgs = await core.stormlist(f"slib.anyrun.enrich --task {fa.TASK}")
            self.stormHasNoWarnErr(msgs)
            assert await core.count("it:exec:file:add#rep.anyrun.threat_lvl") == 0

    async def test_enrich_nodes(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            # Files and URLs are found in the task history.
            msgs = await core.stormlist(f"[ hash:sha256={fa.SAMPLE_SHA256} ] | slib.anyrun.enrich --yield")
            self.stormHasNoWarnErr(msgs)
            assert yielded(msgs) == [("file:bytes", f"sha256:{fa.SAMPLE_SHA256}")]
            assert "/v1/intelligence/api/search" not in fake.paths()

            msgs = await core.stormlist(f"[ inet:url={fa.URL} ] | slib.anyrun.enrich --yield")
            self.stormHasNoWarnErr(msgs)
            assert yielded(msgs) == [("inet:url", fa.URL)]
            (scan,) = await core.nodes(f"inet:url={fa.URL} -> it:av:scan:result:target:url")
            assert scan.get("verdict") == 30
            (url,) = await core.nodes(f"inet:url={fa.URL}")
            assert "rep.anyrun.phishing" in url.tags

            # Then with TI Lookup.
            fake.state["history"] = []
            msgs = await core.stormlist(f"[ hash:md5={fa.SAMPLE_MD5} ] | slib.anyrun.enrich --yield")
            self.stormHasNoWarnErr(msgs)
            assert yielded(msgs) == [("file:bytes", f"sha256:{fa.SAMPLE_SHA256}")]
            req = [r for r in fake.requests if r["path"] == "/v1/intelligence/api/search"][-1]
            assert req["body"]["query"] == f'md5:"{fa.SAMPLE_MD5}"'

            msgs = await core.stormlist(f"[ hash:md5={fa.SAMPLE_MD5} ] | slib.anyrun.enrich --no-lookup")
            self.stormIsInWarn("ANY.RUN has no task for", msgs)
            msgs = await core.stormlist("[ file:bytes=* ] | slib.anyrun.enrich")
            self.stormIsInWarn("has no hash or URL to look up", msgs)
            msgs = await core.stormlist("[ inet:fqdn=a.com ] | slib.anyrun.enrich")
            self.stormIsInWarn("The node form inet:fqdn is not supported", msgs)
            msgs = await core.stormlist("slib.anyrun.enrich --task 00000000-0000-0000-0000-000000000000")
            self.stormIsInWarn("Task not found", msgs)

            # Inbound nodes are passed through without --yield.
            msgs = await core.stormlist(f"[ hash:sha256={fa.SAMPLE_SHA256} ] | slib.anyrun.enrich")
            assert yielded(msgs) == [("hash:sha256", fa.SAMPLE_SHA256)]

            # Tags can be turned off, or moved.
            await core.callStorm("slib.anyrun.admin.tags --disable")
            msgs = await core.stormlist(f"slib.anyrun.enrich --task {fa.URLTASK}")
            self.stormHasNoWarnErr(msgs)
            await core.callStorm("slib.anyrun.admin.tags --enable --prefix rep.ar")
            msgs = await core.stormlist(f"slib.anyrun.enrich --task {fa.URLTASK}")
            (url,) = await core.nodes(f"inet:url={fa.URL}")
            assert "rep.ar.phishing" in url.tags

    async def test_lookup(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("[ inet:fqdn=c2.evil.example.com ] | slib.anyrun.lookup --related --yield")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("c2.evil.example.com is malicious (threats=agenttesla, tasks=2).", msgs)
            assert yielded(msgs) == [("inet:fqdn", "c2.evil.example.com")]

            (fqdn,) = await core.nodes("inet:fqdn=c2.evil.example.com")
            assert fqdn.tags["rep.anyrun.agenttesla"] == (1793448000000, 1793448000001)
            assert "rep.anyrun.stealer" in fqdn.tags and "rep.anyrun.c2" in fqdn.tags
            (scan,) = await core.nodes("inet:fqdn=c2.evil.example.com -> it:av:scan:result:target:fqdn")
            assert scan.get("verdict") == 40 and scan.get("signame") == "agenttesla"

            # The related observables.
            (ip,) = await core.nodes("inet:ipv4=203.0.113.10")
            assert "rep.anyrun.agenttesla" in ip.tags and "rep.anyrun.c2" in ip.tags
            (url,) = await core.nodes("inet:url=http://c2.evil.example.com/gate.php")
            assert "rep.anyrun.agenttesla" in url.tags and "rep.anyrun.c2" not in url.tags
            assert await core.count(SAMPLE) == 1
            assert await core.count("it:dev:mutex") == 1
            assert await core.count("risk:tool:software") == 1

            # The lookup's verdict is updated in place.
            msgs = await core.stormlist("inet:fqdn=c2.evil.example.com | slib.anyrun.lookup")
            assert await core.count("it:av:scan:result") == 1

            # hash:* nodes are modeled on their file, and --tasks models the source tasks.
            msgs = await core.stormlist(f"[ hash:md5={fa.SAMPLE_MD5} ] | slib.anyrun.lookup --tasks 1 --yield")
            self.stormHasNoWarnErr(msgs)
            assert yielded(msgs) == [("file:bytes", f"sha256:{fa.SAMPLE_SHA256}")]
            self.stormIsInPrint(f"Modeled task {fa.TASK}", msgs)
            assert await core.count(f"{SAMPLE} -> it:av:scan:result:target:file") == 2

            # An IP lookup, with a date range.
            msgs = await core.stormlist("[ inet:ipv4=203.0.113.10 ] | slib.anyrun.lookup --start 2026-01-01 --end 2026-02-01")
            self.stormHasNoWarnErr(msgs)
            assert fake.requests[-1]["body"] == {
                "query": 'destinationIP:"203.0.113.10"',
                "startDate": "2026-01-01",
                "endDate": "2026-02-01",
            }

            msgs = await core.stormlist("[ inet:fqdn=nothing.example.com ] | slib.anyrun.lookup --yield")
            self.stormIsInPrint("ANY.RUN has no intelligence on nothing.example.com.", msgs)
            assert yielded(msgs) == []

            msgs = await core.stormlist("slib.anyrun.lookup --query 'threatName:\"agenttesla\"'")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint('threatName:"agenttesla" is malicious.', msgs)
            self.stormIsInPrint("related: 1 IPs, 1 domains, 1 URLs, 1 files, 2 tasks", msgs)
            self.stormIsInPrint(fa.TASK, msgs)
            msgs = await core.stormlist("slib.anyrun.lookup --query 'threatName:\"agenttesla\"' --json")
            self.stormIsInPrint('"verdict": 40', msgs)

            msgs = await core.stormlist("[ inet:email=a@b.com ] | slib.anyrun.lookup")
            self.stormIsInWarn("The node form inet:email is not supported", msgs)
            msgs = await core.stormlist("[ file:bytes=* ] | slib.anyrun.lookup")
            self.stormIsInWarn("can't be looked up", msgs)

            # The API's errors are warnings.
            fake.state["lookup_429"] = 10
            msgs = await core.stormlist("inet:fqdn=c2.evil.example.com | slib.anyrun.lookup")
            self.stormIsInWarn("Too many requests", msgs)


class TestStormTasks(s_tests.SynTest):
    async def test_history_status_report(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.anyrun.history --limit 5")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("slib.anyrun.history: 2 tasks.", msgs)
            self.stormIsInPrint(fa.URLTASK, msgs)
            assert await core.count("file:bytes") == 0

            msgs = await core.stormlist("slib.anyrun.history --yield")
            self.stormHasNoWarnErr(msgs)
            assert yielded(msgs) == [("file:bytes", f"sha256:{fa.SAMPLE_SHA256}"), ("inet:url", fa.URL)]

            msgs = await core.stormlist(f"slib.anyrun.task.status {fa.TASK}")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(f"{fa.TASK} is completed (100%, 0s left, verdict: Malicious activity)", msgs)

            fake.state["events"][fa.QUEUED] = [
                {"error": False, "message": "Task is queued and awaits execution."},
                fa.statusEvent(fa.TASK, 50),
            ]
            msgs = await core.stormlist(f"slib.anyrun.task.status {fa.QUEUED} --follow --timeout 10")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(f"{fa.QUEUED} is queued", msgs)
            self.stormIsInPrint(f"{fa.TASK} is running (50%", msgs)
            self.stormIsInPrint(f"{fa.TASK} is completed", msgs)

            msgs = await core.stormlist(f"slib.anyrun.task.wait {fa.QUEUED} --yield")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(f"Task {fa.TASK} is completed.", msgs)
            assert yielded(msgs) == [("file:bytes", f"sha256:{fa.SAMPLE_SHA256}")]

            msgs = await core.stormlist("slib.anyrun.task.status 00000000-0000-0000-0000-000000000000")
            self.stormIsInWarn("Task not found", msgs)
            msgs = await core.stormlist("slib.anyrun.task.status 00000000-0000-0000-0000-000000000000 --follow")
            self.stormIsInWarn("Task not found", msgs)

            msgs = await core.stormlist(f"slib.anyrun.report {fa.TASK}")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(f"file: {fa.SAMPLE_SHA256}", msgs)
            self.stormIsInPrint("verdict: Malicious activity (score 100)", msgs)
            self.stormIsInPrint("families: AgentTesla", msgs)
            self.stormIsInPrint("processes: 2, DNS requests: 1, HTTP requests: 1, connections: 1, Suricata alerts: 1", msgs)
            self.stormIsInPrint(
                "created files: 2, file operations: 5, registry operations: 5, screenshots: 2, video: true", msgs
            )

            msgs = await core.stormlist(f"slib.anyrun.report {fa.TASK} --iocs --reputation 2")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("c2.evil.example.com", msgs)
            assert "8.8.8.8" not in prints(msgs)
            msgs = await core.stormlist(f"slib.anyrun.report {fa.TASK} --ai")
            self.stormIsInPrint("An AgentTesla stealer.", msgs)
            msgs = await core.stormlist(f"slib.anyrun.report {fa.TASK} --format stix")
            self.stormIsInPrint('"format": "stix"', msgs)
            msgs = await core.stormlist(f"slib.anyrun.report {fa.TASK} --json")
            self.stormIsInPrint('"threatLevelText": "Malicious activity"', msgs)
            msgs = await core.stormlist("slib.anyrun.report nope")
            self.stormIsInWarn("isn't an ANY.RUN task ID", msgs)

            msgs = await core.stormlist("slib.anyrun.limits")
            self.stormIsInPrint('"month": 250', msgs)
            msgs = await core.stormlist("slib.anyrun.envs")
            self.stormIsInPrint("22.04.2", msgs)
            msgs = await core.stormlist("slib.anyrun.presets")
            self.stormIsInPrint("Default", msgs)
            msgs = await core.stormlist("slib.anyrun.presets --json")
            self.stormIsInPrint("QiRRnjH9JNnbmevtH", msgs)

    async def test_download(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(f"slib.anyrun.download --task {fa.TASK} --sample --pcap --dropped --yield")
            self.stormHasNoWarnErr(msgs)
            pcap = hashlib.sha256(fa.PCAP).hexdigest()
            assert yielded(msgs) == [
                ("file:bytes", f"sha256:{pcap}"),
                ("file:bytes", f"sha256:{fa.DROPPED_SHA256}"),
                ("file:bytes", f"sha256:{fa.SAMPLE_SHA256}"),
            ]
            for byts in (fa.SAMPLE, fa.PCAP, fa.DROPPED):
                assert await core.axon.has(hashlib.sha256(byts).digest())
            (n,) = await core.nodes(f"file:bytes=sha256:{pcap}")
            assert n.get("name") == f"{fa.TASK}.pcap" and n.get("size") == len(fa.PCAP)
            (n,) = await core.nodes(f"file:bytes=sha256:{fa.DROPPED_SHA256}")
            assert n.get("name") == "payload.dll"

            # Inbound nodes' tasks are found like enrich.
            msgs = await core.stormlist(f"[ hash:sha1={fa.SAMPLE_SHA1} ] | slib.anyrun.download --yield")
            self.stormHasNoWarnErr(msgs)
            assert yielded(msgs) == [("file:bytes", f"sha256:{fa.SAMPLE_SHA256}")]

            # The PCAP, video, and screenshots, linked to the task's verdict.
            msgs = await core.stormlist(f"slib.anyrun.download --task {fa.TASK} --pcap --video --screenshots --yield")
            self.stormHasNoWarnErr(msgs)
            video = hashlib.sha256(fa.VIDEO).hexdigest()
            jpeg1, jpeg2 = (hashlib.sha256(b).hexdigest() for b in (fa.JPEG1, fa.JPEG2))
            assert yielded(msgs) == [
                ("file:bytes", f"sha256:{pcap}"),
                ("file:bytes", f"sha256:{video}"),
                ("file:bytes", f"sha256:{jpeg1}"),
                ("file:bytes", f"sha256:{jpeg2}"),
            ]
            assert await core.axon.has(hashlib.sha256(fa.VIDEO).digest())
            scan = f"{SAMPLE} -> it:av:scan:result:target:file"
            refs = {n.ndef for n in await core.nodes(f"{scan} -(refs)> *")}
            assert ("file:bytes", f"sha256:{pcap}") in refs and ("file:bytes", f"sha256:{video}") in refs
            (n,) = await core.nodes(f"file:bytes=sha256:{video}")
            assert n.get("mime") == "video/mp4" and n.get("name") == f"{fa.TASK}.mp4"
            (n,) = await core.nodes(f"file:bytes=sha256:{pcap}")
            assert n.get("mime") == "application/vnd.tcpdump.pcap"

            shots = await core.nodes(f"{scan} -(refs)> it:screenshot")
            assert len(shots) == 2
            (shot,) = await core.nodes(f"it:screenshot:image=sha256:{jpeg2}")
            assert shot.get("sandbox:file") == f"sha256:{fa.SAMPLE_SHA256}" and shot.get("time") == 1793448030000
            assert shot.get("desc") == f"ANY.RUN task {fa.TASK} screenshot at 30s"
            (n,) = await core.nodes(f"file:bytes=sha256:{jpeg1}")
            assert n.get("mime") == "image/jpeg" and n.get("name") == f"{fa.SCREEN1}.jpeg"
            assert await core.count("it:exec:url") == 0

            # Downloading again doesn't duplicate anything.
            count = await core.count(".created")
            msgs = await core.stormlist(f"slib.anyrun.download --task {fa.TASK} --pcap --video --screenshots")
            self.stormHasNoWarnErr(msgs)
            assert await core.count(".created") == count

            # A URL task's screenshots, with its browser visit; it has no video.
            report = fa.urlReport()
            report["analysis"]["content"]["screenshots"] = [{"uuid": fa.SCREEN1, "time": 2}, {"uuid": fa.SCREEN2, "time": 9}]
            fake.state["reports"][fa.URLTASK] = report
            msgs = await core.stormlist(f"slib.anyrun.download --task {fa.URLTASK} --screenshots --video")
            self.stormIsInWarn(f"Task {fa.URLTASK} has no video.", msgs)
            (visit,) = await core.nodes("it:exec:url")
            assert visit.get("url") == fa.URL and visit.get("page:image") == f"sha256:{jpeg2}"
            shots = await core.nodes(f"inet:url={fa.URL} -> it:av:scan:result:target:url -(refs)> it:screenshot")
            assert sorted(n.get("time") for n in shots) == [1793350802000, 1793350809000]
            assert all(n.get("sandbox:file") is None for n in shots)

            fake.state["reports"][fa.URLTASK]["analysis"]["content"]["screenshots"] = []
            msgs = await core.stormlist(f"slib.anyrun.download --task {fa.URLTASK} --screenshots")
            self.stormIsInWarn("has no screenshots", msgs)
            fake.state["reports"] = {}

            msgs = await core.stormlist(f"slib.anyrun.download --task {fa.URLTASK}")
            self.stormIsInWarn("analyzed a URL, it has no sample file", msgs)
            fake.state["history"] = []
            msgs = await core.stormlist("[ hash:md5=00000000000000000000000000000000 ] | slib.anyrun.download --no-lookup")
            self.stormIsInWarn("ANY.RUN has no task for", msgs)
            msgs = await core.stormlist("[ inet:fqdn=a.com ] | slib.anyrun.download")
            self.stormIsInWarn("The node form inet:fqdn is not supported", msgs)

    async def test_submit(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            (size, sha256) = await core.axon.put(b"MZ submitted file")
            sha = sha256.hex()
            q = f"[ file:bytes=sha256:{sha} :size={size} :name=a.exe ] | slib.anyrun.submit --os windows --version 11 --timeout 120 --tag t1 --tag t2 --offline"
            msgs = await core.stormlist(q)
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(f"Submitted {sha} as task {fa.NEWTASK} (https://app.any.run/tasks/{fa.NEWTASK}).", msgs)
            body = fake.requests[-1]["body"]
            assert body["file"] == {"filename": "a.exe", "data": b"MZ submitted file"}
            assert body["env_version"] == "11" and body["opt_timeout"] == "120"
            assert body["user_tags"] == "t1,t2" and body["opt_network_connect"] == "False"

            msgs = await core.stormlist(
                "slib.anyrun.submit --url https://a.example.com --browser 'Google Chrome' --mitm --privacy owner "
                "--download https://b.example.com/x.exe --useragent UA --hide-source --rerun " + fa.TASK
            )
            self.stormIsInWarn("The browser option can't be used with a download submission", msgs)
            msgs = await core.stormlist("slib.anyrun.submit --url https://a.example.com --browser 'Google Chrome' --mitm --privacy owner --tor --tor-geo de")
            self.stormHasNoWarnErr(msgs)
            assert fake.requests[-1]["body"] == {
                "obj_type": "url",
                "obj_url": "https://a.example.com",
                "obj_ext_browser": "Google Chrome",
                "opt_network_mitm": True,
                "opt_privacy_type": "owner",
                "opt_network_tor": True,
                "opt_network_geo": "DE",
            }
            msgs = await core.stormlist("slib.anyrun.submit --download https://b.example.com/x.exe --useragent UA --hide-source --no-interactive")
            self.stormHasNoWarnErr(msgs)
            assert fake.requests[-1]["body"] == {
                "obj_type": "download",
                "obj_url": "https://b.example.com/x.exe",
                "obj_ext_useragent": "UA",
                "opt_privacy_hidesource": True,
                "opt_automated_interactivity": False,
            }
            msgs = await core.stormlist(f"slib.anyrun.submit --rerun {fa.TASK} --fakenet --proxy --proxy-geo br")
            self.stormHasNoWarnErr(msgs)
            assert fake.requests[-1]["body"]["task_rerun_uuid"] == fa.TASK

            # Inbound URLs, and waiting for (and modeling) the task.
            report = fa.fileReport(fake.url)
            report["analysis"]["uuid"] = fa.NEWTASK
            fake.state["reports"][fa.NEWTASK] = report
            fake.state["events"][fa.NEWTASK] = [fa.statusEvent(fa.NEWTASK, 50), fa.statusEvent(fa.NEWTASK, 100)]
            msgs = await core.stormlist(f"[ inet:url={fa.URL} ] | slib.anyrun.submit --wait 30 --yield")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(f"Modeled task {fa.NEWTASK}", msgs)
            assert yielded(msgs) == [("file:bytes", f"sha256:{fa.SAMPLE_SHA256}")]

            # Queued tasks are waited on by their queue ID.
            fake.state["queue"] = True
            fake.state["events"][fa.QUEUED] = [fa.statusEvent(fa.NEWTASK, 100, completed=True)]
            msgs = await core.stormlist("slib.anyrun.submit --url https://a.example.com --wait 30 --yield")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(f"it's queued as {fa.QUEUED}", msgs)
            assert len(yielded(msgs)) == 1

            # A task that's still running.
            fake.state["queue"] = False
            fake.state["events"][fa.NEWTASK] = [fa.statusEvent(fa.NEWTASK, 50)]
            msgs = await core.stormlist("slib.anyrun.submit --url https://a.example.com --wait 1 --yield")
            self.stormIsInWarn(f"Task {fa.NEWTASK} is running after 1s", msgs)
            assert yielded(msgs) == []

            msgs = await core.stormlist("slib.anyrun.submit --url https://a.example.com --privacy public")
            self.stormIsInWarn("cannot create public tasks", msgs)
            msgs = await core.stormlist("[ file:bytes=* ] | slib.anyrun.submit")
            self.stormIsInWarn("has no SHA256", msgs)
            msgs = await core.stormlist(f"[ file:bytes=sha256:{'f' * 64} :size=10 ] | slib.anyrun.submit")
            self.stormIsInWarn("The Axon doesn't have", msgs)
            msgs = await core.stormlist("[ inet:fqdn=a.com ] | slib.anyrun.submit")
            self.stormIsInWarn("The node form inet:fqdn is not supported", msgs)

            msgs = await core.stormlist(f"slib.anyrun.task.addtime {fa.TASK}")
            self.stormIsInPrint("Add time in task successful", msgs)
            msgs = await core.stormlist(f"slib.anyrun.task.stop {fa.TASK}")
            self.stormIsInWarn("has already been completed", msgs)
            msgs = await core.stormlist(f"slib.anyrun.task.delete {fa.TASK}")
            self.stormIsInPrint("Delete task successful", msgs)

        async with fa.anyrunSvc(self, **{"anyrun:maxsize": 4}) as (core, svc, fake):
            (size, sha256) = await core.axon.put(b"too big")
            msgs = await core.stormlist(f"[ file:bytes=sha256:{sha256.hex()} :size={size} ] | slib.anyrun.submit")
            self.stormIsInWarn("larger than the max of 4", msgs)


class TestStormTI(s_tests.SynTest):
    async def test_yara(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            rule = await core.nodes("[ it:app:yara:rule=* :name=grimresources :text=$text ]", opts={"vars": {"text": fa.YARA_RULE}})
            msgs = await core.stormlist("it:app:yara:rule | slib.anyrun.yara --yield")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(f"YARA search {fa.YARA_ID} found 2 files, modeled 1.", msgs)
            assert yielded(msgs) == [("file:bytes", f"sha256:{fa.MATCH_SHA256}")]
            (f,) = await core.nodes(f"file:bytes=sha256:{fa.MATCH_SHA256}")
            assert f.get("name") == "invoice_2026.exe" and f.get("size") == 245760
            assert "rep.anyrun.agenttesla" in f.tags and "rep.anyrun.trojan" in f.tags
            assert await core.count(f"it:app:yara:match=({rule[0].ndef[1]}, sha256:{fa.MATCH_SHA256})") == 1

            # A rule's text, then an earlier search by ID.
            msgs = await core.stormlist("slib.anyrun.yara --rule $text", opts={"vars": {"text": fa.YARA_RULE}})
            self.stormHasNoWarnErr(msgs)
            assert await core.count("it:app:yara:rule") == 2
            assert await core.count("it:app:yara:match") == 2
            msgs = await core.stormlist(f"slib.anyrun.yara --search {fa.YARA_ID} --yield")
            self.stormHasNoWarnErr(msgs)
            assert len(yielded(msgs)) == 1
            assert await core.count("it:app:yara:rule") == 2

            fake.state["yara_polls"] = 1000
            msgs = await core.stormlist("slib.anyrun.yara --rule $text --timeout 0", opts={"vars": {"text": fa.YARA_RULE}})
            self.stormIsInWarn(f"YARA search {fa.YARA_ID} is processing", msgs)

            msgs = await core.stormlist("slib.anyrun.yara --rule nope")
            self.stormIsInWarn("Invalid YARA rule", msgs)
            msgs = await core.stormlist("[ it:app:yara:rule=* ] | slib.anyrun.yara")
            self.stormIsInWarn("The YARA rule has no text", msgs)
            msgs = await core.stormlist("[ inet:fqdn=a.com ] | slib.anyrun.yara")
            self.stormIsInWarn("The node form inet:fqdn is not supported", msgs)

    async def test_feed(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.anyrun.feed --limit 0 --yield")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("Read 4 objects from the full feed.", msgs)
            assert yielded(msgs) == [
                ("inet:ipv4", 0xCB00710A),
                ("inet:fqdn", "c2.evil.example.com"),
                ("inet:url", "http://c2.evil.example.com/gate.php"),
                ("file:bytes", f"sha256:{fa.SAMPLE_SHA256}"),
            ]
            (ip,) = await core.nodes("inet:ipv4=203.0.113.10")
            assert ip.tags["rep.anyrun.feed"] == (1793318400000, 1793404800000)
            assert "rep.anyrun.malicious_activity" in ip.tags
            assert await core.count(f"inet:ipv4=203.0.113.10 <(seen)- meta:source={SOURCE_GUID}") == 1

            msgs = await core.stormlist("slib.anyrun.feed --print --days 1 --limit 2")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("203.0.113.10", msgs)
            req = [r for r in fake.requests if r["path"].endswith("/objects/")][-1]
            assert "added_after" in req["query"]

            msgs = await core.stormlist("slib.anyrun.feed --list")
            self.stormIsInPrint("3dce855a-c044-5d49-9334-533c24678c5a", msgs)
            msgs = await core.stormlist("slib.anyrun.feed --feed url")
            self.stormIsInWarn("could not be found", msgs)


class TestStormAdmin(s_tests.SynTest):
    async def test_apikeys(self):
        async with fa.anyrunSvc(self, apikey=None) as (core, svc, fake):
            msgs = await core.stormlist("slib.anyrun.limits")
            self.stormIsInWarn("No ANY.RUN API key is available", msgs)

            msgs = await core.stormlist("slib.anyrun.apikey")
            self.stormIsInPrint("no service-wide key is set either", msgs)
            msgs = await core.stormlist(f"slib.anyrun.apikey {fa.APIKEY}")
            self.stormIsInPrint("Saved your ANY.RUN API key in vault anyrun:root.", msgs)
            msgs = await core.stormlist("slib.anyrun.limits")
            self.stormHasNoWarnErr(msgs)
            msgs = await core.stormlist("slib.anyrun.apikey wrong")
            self.stormIsInPrint("Updated your ANY.RUN API key.", msgs)
            msgs = await core.stormlist("slib.anyrun.limits")
            self.stormIsInWarn("Wrong authorization data", msgs)
            msgs = await core.stormlist("slib.anyrun.apikey")
            self.stormIsInPrint("Your ANY.RUN API key is set in vault anyrun:root.", msgs)
            msgs = await core.stormlist("slib.anyrun.apikey --clear")
            self.stormIsInPrint("Deleted your ANY.RUN API key.", msgs)

            msgs = await core.stormlist(f"slib.anyrun.admin.apikey {fa.APIKEY}")
            self.stormIsInPrint("Set the slib.anyrun API key.", msgs)
            msgs = await core.stormlist("slib.anyrun.admin.apikey")
            self.stormIsInPrint("A service-wide API key is set.", msgs)
            msgs = await core.stormlist("slib.anyrun.limits")
            self.stormHasNoWarnErr(msgs)
            msgs = await core.stormlist("slib.anyrun.apikey")
            self.stormIsInPrint("so the service-wide key is used", msgs)
            msgs = await core.stormlist("slib.anyrun.admin.apikey --clear")
            self.stormIsInPrint("Cleared the slib.anyrun API key.", msgs)

    async def test_admin(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            msgs = await core.stormlist('slib.anyrun.admin.request /v1/analysis --params ({"limit": 1})')
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(fa.TASK, msgs)
            assert fake.requests[-1]["query"] == {"limit": "1"}
            msgs = await core.stormlist("slib.anyrun.admin.request /v1/nope")
            self.stormIsInWarn("Not found (HTTP 404)", msgs)

            msgs = await core.stormlist("slib.anyrun.admin.tags --enable --disable")
            self.stormIsInErr("Use --enable or --disable, not both", msgs)


class TestStormPerms(s_tests.SynTest):
    async def test_perms(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            visi = await core.auth.addUser("visi")
            opts = {"user": visi.iden}

            msgs = await core.stormlist(f"slib.anyrun.enrich --task {fa.TASK}", opts=opts)
            self.stormIsInErr("slib.anyrun.user", msgs)

            await visi.addRule((True, ("slib", "anyrun", "user")))
            # Without node permissions, the user can query but not model.
            msgs = await core.stormlist(f"slib.anyrun.report {fa.TASK}", opts=opts)
            self.stormHasNoWarnErr(msgs)
            msgs = await core.stormlist(f"slib.anyrun.enrich --task {fa.TASK}", opts=opts)
            self.stormIsInErr("must have permission node.add", msgs)

            await visi.addRule((True, ("node",)))
            msgs = await core.stormlist(f"slib.anyrun.enrich --task {fa.TASK} --yield", opts=opts)
            self.stormHasNoWarnErr(msgs)
            assert yielded(msgs) == [("file:bytes", f"sha256:{fa.SAMPLE_SHA256}")]

            for cmd in (
                "slib.anyrun.submit --url http://a.com",
                f"slib.anyrun.task.delete {fa.TASK}",
                f"slib.anyrun.task.stop {fa.TASK}",
                "slib.anyrun.admin.apikey",
                "slib.anyrun.admin.tags",
                "slib.anyrun.admin.request /v1/user",
            ):
                msgs = await core.stormlist(cmd, opts=opts)
                self.stormIsInErr("requires permission: slib.anyrun", msgs)

            # The service's stored key can't be read from Storm.
            msgs = await core.stormlist('$lib.service.get("slib.anyrun")', opts=opts)
            self.stormIsInErr("must have permission service.get", msgs)

            await visi.addRule((True, ("slib", "anyrun", "submit")))
            msgs = await core.stormlist("slib.anyrun.submit --url http://a.com", opts=opts)
            self.stormHasNoWarnErr(msgs)

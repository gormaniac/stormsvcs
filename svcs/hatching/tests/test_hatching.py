"""Pytests for the slib.hatching service's Python code (HatchingSvc, its Telepath API, and norm)."""

import pathlib
import tomllib

import synapse.tests.utils as s_tests
from pyhatching import testing as ft

from hatchingsvc import __version__, norm
from hatchingsvc.defs import PKGDEFS
from hatchingsvc.errors import HatchingApiError

from .helpers import hatchingSvc


class TestVersions(s_tests.SynTest):

    def test_versions_match(self):
        root = pathlib.Path(__file__).parent.parent
        with (root / "pyproject.toml").open("rb") as fd:
            assert tomllib.load(fd)["project"]["version"] == __version__
        assert PKGDEFS[0]["version"] == __version__
        with (root / "uv.lock").open("rb") as fd:
            pkgs = {p["name"]: p for p in tomllib.load(fd)["package"]}
        assert pkgs["hatchingsvc"]["version"] == __version__


class TestNorm(s_tests.SynTest):

    def test_helpers(self):
        assert norm.tagPart("Cobalt Strike!") == "cobalt_strike"
        assert norm.tagPart("") is None
        assert norm.tagName("family:emotet") == "emotet"
        assert norm.tagName("botnet:12-34") == "botnet.12_34"
        assert norm.tagName("a::b") is None
        assert norm.families(["family:a", "b", "family:"]) == ["a"]
        assert norm.toMsecs("2026-10-31T12:00:00Z") == 1793448000000
        assert norm.toMsecs("nope") is None
        assert norm.verdict(10) == 40 and norm.verdict(7) == 30 and norm.verdict(1) == 10
        assert norm.verdict(0) is None
        assert norm.c2Url("1.2.3.4:443") == "tcp://1.2.3.4:443"
        assert norm.c2Url("[::1]:80") == "tcp://[::1]:80"
        assert norm.c2Url("evil.com") == "tcp://evil.com"
        assert norm.c2Url("https://evil.com/a") == "https://evil.com/a"
        assert norm.c2Url("") is None
        assert norm.splitHostPort("a.com:x") == ("a.com", None)
        assert norm.ipVersion("::1") == "ipv6" and norm.ipVersion("a.com") is None
        assert norm.basename("C:\\a\\b.exe") == "b.exe" and norm.basename(None) is None
        assert norm.cmdLine(["a", "b"]) == "a b" and norm.cmdLine("") is None

    def test_norm_sample(self):
        tasks = {"behavioral1": ft.TASK_REPORT}
        data = norm.normSample(ft.SAMPLE, ft.OVERVIEW, ft.STATIC_REPORT, tasks)

        assert data["id"] == ft.SAMPLE_ID and data["kind"] == "file" and data["url"] is None
        assert data["score"] == 10 and data["verdict"] == 40
        assert data["ival"] == [1793448000000, 1793448300000] and data["time"] == 1793448300000
        assert data["file"] == {
            "sha256": ft.SAMPLE_SHA256, "md5": ft.SAMPLE_MD5, "sha1": ft.SAMPLE_SHA1,
            "sha512": ft.SAMPLE_SHA512, "size": len(ft.SAMPLE_BYTES), "name": "invoice.exe",
            "mime": "application/x-dosexec",
        }
        assert data["families"] == ["cobaltstrike", "lockbit"]
        assert data["tags"] == ["cobaltstrike", "backdoor", "trojan", "persistence", "upx", "lockbit"]
        assert "family:cobaltstrike" not in data["categories"] and "backdoor" in data["categories"]
        assert data["ttps"] == ["T1056.001", "T1547.001"]
        assert data["iocs"] == {"urls": ["http://198.51.100.7/jquery-3.3.1.min.js"],
                                "hosts": ["evil.example.com", "198.51.100.7"]}

        # The overview and the task report hold the same config, it's only included once.
        (config,) = data["configs"]
        assert config["servers"] == ["http://198.51.100.7:443/jquery-3.3.1.min.js", "tcp://evil.example.com:8080"]
        assert config["hosts"] == ["198.51.100.7", "evil.example.com"]
        assert config["mutexes"] == ["Global\\cs-mutex"] and config["family"] == "cobaltstrike"
        assert config["raw"] == ft.CONFIG
        assert data["droppers"] == [{"family": None, "language": "ps1", "urls": ["http://203.0.113.9/a.ps1"]}]
        assert data["ransom"][0]["family"] == "lockbit" and data["ransom"][0]["emails"] == ["pay@example.org"]

        (task,) = data["tasks"]
        assert task["name"] == "behavioral1"
        assert task["procs"][1] == {"procid": 2, "parent": 1, "pid": 3120, "orig": False,
                                    "cmd": "C:\\Windows\\System32\\cmd.exe /c whoami",
                                    "path": "C:\\Windows\\System32\\cmd.exe"}
        # Parents that weren't reported are dropped.
        assert task["procs"][0]["parent"] is None and task["procs"][0]["orig"]
        assert task["flows"][0] == {"id": 1, "server": "tcp://198.51.100.7:443", "proto": "tcp",
                                    "ip": "198.51.100.7", "ipver": "ipv4", "port": 443, "procid": 1,
                                    "txbytes": 512, "rxbytes": 1024, "domain": "evil.example.com"}
        assert task["dns"] == [{"flow": 2, "index": 1, "name": "evil.example.com"}]
        assert task["answers"] == [{"type": "a", "name": "evil.example.com", "value": "198.51.100.7"}]
        assert task["http"] == [{"flow": 1, "index": 3, "method": "GET", "code": 200,
                                 "url": "http://evil.example.com/jquery-3.3.1.min.js"}]
        (dropped,) = task["files"]
        assert dropped["sha256"] == ft.DROPPED_SHA256 and dropped["basename"] == "upd.exe"
        assert dropped["procid"] == 1

        # Without task reports there are no tasks.
        assert norm.normSample(ft.SAMPLE, ft.OVERVIEW)["tasks"] == []

    def test_norm_url_sample(self):
        sample = dict(ft.SAMPLE, kind="url", url="https://example.com/login", filename=None)
        overview = {"sample": {"target": "https://example.com/login"},
                    "analysis": {"score": 6, "tags": ["phishing"]}}
        data = norm.normSample(sample, overview)
        assert data["url"] == "https://example.com/login" and data["file"] is None
        assert data["verdict"] == 30 and data["tags"] == ["phishing"]
        assert data["families"] == [] and data["configs"] == []


class TestHatchingSvc(s_tests.SynTest):

    async def test_apikeys(self):
        async with hatchingSvc(self, apikey=None) as (core, svc, fake):
            assert not await svc.hasApiKey()
            with self.raises(HatchingApiError):
                await svc.getClient()
            assert (await svc.getClient("testkey")).api_key == "testkey"

            await svc.setApiKey("stored")
            assert svc.getApiKey() == "stored"
            assert svc.getApiKey("mine") == "mine"
            await svc.setApiKey(None)
            assert svc.getApiKey() is None

            # The Telepath API.
            async with svc.getLocalProxy() as prox:
                retn = await prox.setApiKey("stored")
                assert retn["status"] and retn["mesg"] == "Set the slib.hatching API key."
                assert (await prox.hasApiKey())["data"] is True
                retn = await prox.setApiKey(None)
                assert retn["mesg"] == "Cleared the slib.hatching API key."

                retn = await prox.search("family:cobaltstrike")
                assert not retn["status"] and "No Hatching Triage API key" in retn["mesg"]

    async def test_client_cache(self):
        async with hatchingSvc(self) as (core, svc, fake):
            first = await svc.getClient("k0")
            assert await svc.getClient("k0") is first
            for idx in range(1, 40):
                await svc.getClient(f"k{idx}")
            assert len(svc.clients) == 32 and "k0" not in svc.clients
            assert first.session.closed

            # A client that's in use when it's evicted stays open until the call finishes.
            async with svc.useClient("busy") as busy:
                for idx in range(40, 80):
                    await svc.getClient(f"k{idx}")
                assert "busy" not in svc.clients and busy in svc.retired
                assert not busy.session.closed
            assert busy.session.closed and busy not in svc.retired and not svc.inuse

    async def test_api(self):
        async with hatchingSvc(self) as (core, svc, fake):
            async with svc.getLocalProxy() as prox:
                retn = await prox.search("family:cobaltstrike")
                assert retn["status"] and retn["data"][0]["id"] == ft.SAMPLE_ID

                retn = await prox.sample(ft.SAMPLE_SHA256)
                assert retn["data"]["filename"] == "invoice.exe"
                assert fake.last("get", "/search")["query"]["query"] == f"sha256:{ft.SAMPLE_SHA256}"

                retn = await prox.sample("a" * 64)
                assert not retn["status"] and "has no sample" in retn["mesg"]

                retn = await prox.sample("nope")
                assert not retn["status"] and "NOT_FOUND" in retn["mesg"]

                retn = await prox.search("x", limit="nope")
                assert not retn["status"] and retn["mesg"].startswith("Invalid input")

                retn = await prox.summary(ft.SAMPLE_ID)
                assert retn["data"]["score"] == 10

                assert (await prox.overview(ft.SAMPLE_ID))["data"]["analysis"]["family"] == ("cobaltstrike",)
                assert (await prox.staticReport(ft.SAMPLE_ID))["data"]["files"][0]["mime"]
                retn = await prox.taskReport(ft.SAMPLE_ID, "behavioral1")
                assert retn["data"]["network"]["flows"][0]["tls_sni"] == "evil.example.com"

                retn = await prox.samples(subset="public", limit=5)
                assert [s["id"] for s in retn["data"]] == [ft.SAMPLE_ID]
                assert fake.last()["query"] == {"subset": "public", "limit": "5"}

                events = [r async for r in prox.kernelReport(ft.SAMPLE_ID, "behavioral1")]
                assert [dict(e["data"]) for e in events] == ft.KERNEL_EVENTS
                events = [r async for r in prox.kernelReport(ft.SAMPLE_ID, "behavioral1", limit=1)]
                assert len(events) == 1
                events = [r async for r in prox.kernelReport(ft.SAMPLE_ID, "behavioral1", log="stahp")]
                assert len(events) == 1 and not events[0]["status"]

                retn = await prox.dumpedFiles(ft.SAMPLE_ID)
                assert [dict(d) for d in retn["data"]] == [{"task": "behavioral1", "name": "files/0x0003000000022c2b-1.dat",
                                         "path": "C:\\Users\\Admin\\AppData\\Roaming\\upd.exe",
                                         "sha256": ft.DROPPED_SHA256, "size": len(ft.DROPPED_BYTES)}]

                retn = await prox.rawRequest("get", "v0/samples", params={"subset": "org", "limit": 1})
                assert retn["data"]["data"][0]["id"] == ft.SAMPLE_ID
                retn = await prox.rawRequest("get", "/v0/samples/nope")
                assert not retn["status"] and "404 NOT_FOUND" in retn["mesg"]

                assert (await prox.maxSize())["data"] == 104857600
                assert (await prox.resolve(ft.SAMPLE_MD5))["data"] == ft.SAMPLE_ID
                assert (await prox.resolve(ft.SAMPLE_ID))["data"] == ft.SAMPLE_ID

                # A hash resolves to its newest reported sample, even when it was resubmitted.
                fake.samples["261031-resubmit"] = dict(ft.SAMPLE, id="261031-resubmit", status="pending")
                fake.overviews["261031-resubmit"] = fake.overviews[ft.SAMPLE_ID]
                assert (await prox.resolve(ft.SAMPLE_SHA256))["data"] == ft.SAMPLE_ID
                fake.samples[ft.SAMPLE_ID]["status"] = "failed"
                assert (await prox.resolve(ft.SAMPLE_SHA256))["data"] == "261031-resubmit"

    async def test_norm_sample(self):
        async with hatchingSvc(self) as (core, svc, fake):
            data = await svc.normSample(ft.SAMPLE_SHA256, tasks=True)
            assert data["id"] == ft.SAMPLE_ID and data["score"] == 10 and data["errors"] == []
            assert [t["name"] for t in data["tasks"]] == ["behavioral1"]

            data = await svc.normSample(ft.SAMPLE_ID)
            assert data["tasks"] == []

            # A missing task report is skipped.
            report = fake.task_reports.pop((ft.SAMPLE_ID, "behavioral1"))
            data = await svc.normSample(ft.SAMPLE_ID, tasks=True)
            assert data["tasks"] == [] and "behavioral1 report" in data["errors"][0]
            fake.task_reports[(ft.SAMPLE_ID, "behavioral1")] = report

            # Without a static report, the MIME type is just missing.
            del fake.statics[ft.SAMPLE_ID]
            assert (await svc.normSample(ft.SAMPLE_ID))["file"]["mime"] is None

            fake.samples[ft.SAMPLE_ID]["status"] = "running"
            with self.raises(HatchingApiError) as cm:
                await svc.normSample(ft.SAMPLE_ID)
            assert "isn't reported yet" in cm.exception.mesg

    async def test_submit(self):
        async with hatchingSvc(self) as (core, svc, fake):
            sample = await svc.submitFile([b"MZ", b" chunks"], "a.exe", password="infected",
                                          profiles=["win10-internet:a.exe", {"profile": "w7"}],
                                          tags=["case:1"], timeout=60, network="drop")
            assert sample["filename"] == "a.exe"
            req = fake.last("post", "/samples")
            assert req["files"]["file"] == ("a.exe", b"MZ chunks")
            assert req["form"]["_json"]
            import json
            assert json.loads(req["form"]["_json"]) == {
                "kind": "file", "target": "a.exe", "password": "infected",
                "profiles": [{"profile": "win10-internet", "pick": "a.exe"}, {"profile": "w7"}],
                "user_tags": ["case:1"], "defaults": {"timeout": 60, "network": "drop"},
            }

            with self.raises(HatchingApiError):
                await svc.submitFile([], "empty")

            sample = await svc.submitUrl("http://example.com/a.exe", fetch=True, interactive=True)
            assert sample["kind"] == "fetch" and sample["status"] == "static_analysis"
            assert fake.last()["json"] == {"kind": "fetch", "url": "http://example.com/a.exe",
                                           "interactive": True}

            assert await svc.setProfile(sample["id"], profiles=["w10"])
            assert fake.last()["json"] == {"auto": False, "profiles": [{"profile": "w10"}]}
            with self.raises(HatchingApiError):
                await svc.setProfile(sample["id"], auto=True)

            assert await svc.deleteSample(sample["id"])
            assert sample["id"] not in fake.samples

            with self.raises(HatchingApiError):
                await svc.submitUrl("", fetch=False)

    async def test_submit_maxsize(self):
        async with hatchingSvc(self, conf={"hatching:maxsize": 4}) as (core, svc, fake):
            with self.raises(HatchingApiError) as cm:
                await svc.submitFile([b"12345"], "big")
            assert "larger than the max" in cm.exception.mesg
            with self.raises(HatchingApiError):
                [c async for c in svc.downloadSample(ft.SAMPLE_ID)]

    async def test_wait_and_events(self):
        async with hatchingSvc(self) as (core, svc, fake):
            sample = await svc.wait(ft.SAMPLE_ID, timeout=10)
            assert sample["status"] == "reported"
            # A finished sample's events aren't followed.
            assert fake.last(path="/events") is None

            fake.samples[ft.SAMPLE_ID]["status"] = "running"
            sample = await svc.wait(ft.SAMPLE_ID, timeout=10)
            assert sample["status"] == "reported" and fake.last(path="/events") is not None

            events = [e async for e in svc.sampleEvents(ft.SAMPLE_ID, limit=3)]
            assert [e["status"] for e in events] == ft.EVENTS[:3]
            events = [e async for e in svc.sampleEvents(limit=0)]
            assert len(events) == len(ft.EVENTS)

            with self.raises(HatchingApiError):
                [e async for e in svc.sampleEvents("nope")]

    async def test_downloads(self):
        async with hatchingSvc(self) as (core, svc, fake):
            assert b"".join([c async for c in svc.downloadSample(ft.SAMPLE_SHA256)]) == ft.SAMPLE_BYTES
            byts = b"".join([c async for c in svc.downloadTaskFile(ft.SAMPLE_ID, "behavioral1", "dump.pcap")])
            assert byts == ft.PCAP_BYTES
            byts = b"".join([c async for c in svc.downloadArchive(ft.SAMPLE_ID, fmt="zip")])
            assert byts[:2] == b"PK"

            async with svc.getLocalProxy() as prox:
                items = [r async for r in prox.downloadTaskFile(ft.SAMPLE_ID, "behavioral1", "nope")]
                assert len(items) == 1 and not items[0]["status"] and "NOT_FOUND" in items[0]["mesg"]

    async def test_profiles_rules_users(self):
        async with hatchingSvc(self) as (core, svc, fake):
            assert [p["name"] for p in await svc.profiles()] == ["win10-internet"]
            new = await svc.addProfile("new", tags=["windows7"], timeout=60, network="drop")
            edited = await svc.editProfile("new", timeout=90)
            assert edited["timeout"] == 90 and edited["tags"] == ["windows7"] and edited["network"] == "drop"
            assert fake.last("put")["json"] == {"name": "new", "tags": ["windows7"], "timeout": 90,
                                                 "network": "drop"}
            assert fake.last("put")["path"].endswith(new["id"])
            assert await svc.delProfile("new")
            with self.raises(HatchingApiError):
                await svc.profile("new")

            assert [r["name"] for r in await svc.rules()] == ["fake_rule.yara"]
            assert await svc.addRule("a.yara", "rule a { condition: true }")
            assert await svc.editRule("a.yara", "rule a { condition: false }")
            assert (await svc.rule("a.yara"))["rule"] == "rule a { condition: false }"
            assert await svc.delRule("a.yara")

            assert (await svc.users())[0]["username"] == "analyst"
            user = await svc.addUser("bob", "bob@example.com", password="pw", first="Bob",
                                     permissions=["admin"])
            assert (await svc.user(user["id"]))["first_name"] == "Bob"
            key = await svc.addUserKey(user["id"], "ci")
            assert [k["name"] for k in await svc.userKeys(user["id"])] == ["ci"] and key["key"]
            assert await svc.delUserKey(user["id"], "ci")
            assert await svc.delUser(user["id"])

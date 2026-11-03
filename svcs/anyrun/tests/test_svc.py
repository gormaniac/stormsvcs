"""Tests for the slib.anyrun service (AnyRunSvc and its Telepath API) against a FakeAnyRun."""

import datetime
import hashlib

import pytest
import synapse.tests.utils as s_tests

from anyrunsvc.client import AnyRunApiError
from anyrunsvc.svc import submitParams

from . import fakeanyrun as fa


async def collect(genr) -> list:
    return [item async for item in genr]


async def download(genr) -> bytes:
    return b"".join(await collect(genr))


def test_submit_params():
    assert submitParams("f", None) == {}
    params = submitParams(
        "f",
        {
            "os": "Windows",
            "version": 11,
            "bitness": "32",
            "timeout": "120",
            "privacy": "owner",
            "geo": "de",
            "tags": ["a,b", "c-d"],
            "cmd": None,
            "startfolder": "",
        },
    )
    assert params == {
        "env_os": "windows",
        "env_version": "11",
        "env_bitness": 32,
        "opt_timeout": 120,
        "opt_privacy_type": "owner",
        "opt_network_geo": "DE",
        "opt_network_tor": True,
        "user_tags": "a,b,c-d",
    }
    assert submitParams("u", {"browser": "Google Chrome", "residential_geo": "br"}) == {
        "obj_ext_browser": "Google Chrome",
        "opt_network_residential_proxy_geo": "BR",
        "opt_network_residential_proxy": True,
    }
    assert submitParams("d", {"useragent": "UA", "hidesource": True}) == {
        "obj_ext_useragent": "UA",
        "opt_privacy_hidesource": True,
    }

    bad = (
        ("f", {"os": "beos"}, "The OS must be"),
        ("f", {"bitness": 16}, "32 or 64"),
        ("f", {"os": "linux", "bitness": 32}, "Only Windows"),
        ("f", {"timeout": 5}, "between 10 and 1200"),
        ("f", {"privacy": "secret"}, "privacy must be"),
        ("f", {"autodelete": "year"}, "auto delete"),
        ("f", {"geo": "ZZ"}, "TOR geo"),
        ("f", {"startfolder": "nope"}, "start folder"),
        ("u", {"browser": "Lynx"}, "browser must be"),
        ("f", {"tor": True, "network": False}, "TOR needs"),
        ("f", {"envtype": "office"}, "environment type"),
        ("u", {"cmd": "x"}, "can't be used with a url"),
        ("f", {"browser": "Safari"}, "can't be used with a file"),
        ("f", {"useragent": "x"}, "can't be used with a file"),
        ("f", {"nope": 1}, "Unknown submission options"),
        ("f", {"tags": ["bad tag"]}, "Invalid tags"),
        ("f", {"tags": [str(i) for i in range(9)]}, "at most 8"),
    )
    for kind, opts, mesg in bad:
        with pytest.raises(AnyRunApiError, match=mesg):
            submitParams(kind, opts)


class TestAnyRunSvc(s_tests.SynTest):
    async def test_apikeys(self):
        async with fa.anyrunSvc(self, apikey=None) as (core, svc, fake):
            assert not await svc.hasApiKey()
            with pytest.raises(AnyRunApiError, match="No ANY.RUN API key"):
                await svc.limits()

            # A bad key is the API's error, not an exception.
            with pytest.raises(AnyRunApiError, match=r"Wrong authorization data \(HTTP 403\)"):
                await svc.limits(apikey="wrong")

            await svc.setApiKey(fa.APIKEY)
            assert await svc.hasApiKey()
            assert (await svc.limits())["api"]["month"] == 250
            req = fake.requests[-1]
            assert req["headers"]["Authorization"] == f"API-Key {fa.APIKEY}"
            assert req["headers"]["x-anyrun-connector"] == "slib.anyrun"
            assert req["headers"]["User-Agent"].startswith("slib.anyrun")

            # The caller's own key wins, and prefixed keys are sent as is.
            assert await svc.limits(apikey=f"API-KEY {fa.APIKEY}")
            assert fake.requests[-1]["headers"]["Authorization"] == f"API-KEY {fa.APIKEY}"

            await svc.setApiKey(None)
            assert not await svc.hasApiKey()

            # The TI APIs' error shape.
            with pytest.raises(AnyRunApiError, match="Invalid API key.*API_KEY_ERROR") as exc:
                await svc.lookup("1.2.3.4", apikey="wrong")
            assert exc.value.code == "API_KEY_ERROR" and exc.value.status == 401

    async def test_account_and_tasks(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            envs = await svc.environments()
            assert [e["os"] for e in envs] == ["windows", "linux"]
            presets = await svc.presets()
            assert presets[0]["name"] == "Default"

            tasks = await svc.history(team=True, skip=0, limit=10)
            assert [t["uuid"] for t in tasks] == [fa.TASK, fa.URLTASK]
            assert fake.requests[-1]["query"] == {"team": "true", "skip": "0", "limit": "10"}
            with pytest.raises(AnyRunApiError, match="between 1 and 100"):
                await svc.history(limit=500)

            report = await svc.report(f"https://app.any.run/tasks/{fa.TASK}")
            assert report["analysis"]["uuid"] == fa.TASK
            data = await svc.normReport(fa.TASK)
            assert data["families"] == ["AgentTesla"]
            with pytest.raises(AnyRunApiError, match=r"Task not found \(HTTP 404\)"):
                await svc.report("00000000-0000-0000-0000-000000000000")
            with pytest.raises(AnyRunApiError, match="isn't an ANY.RUN task ID"):
                await svc.report("nope")

            iocs = await svc.iocs(fa.TASK)
            assert len(iocs) == 3
            iocs = await svc.iocs(fa.TASK, reputation=1)
            assert [i["ioc"] for i in iocs] == [fa.SAMPLE_SHA256, "c2.evil.example.com"]
            assert fake.paths()[-1] == f"/report/{fa.TASK}/ioc/json"

            assert (await svc.aiSummary(fa.TASK))["aiSummary"]["Verdict"].startswith("Malicious")
            assert await svc.summary(fa.TASK, fmt="misp") == {"format": "misp", "task": fa.TASK}
            with pytest.raises(AnyRunApiError, match="format must be"):
                await svc.summary(fa.TASK, fmt="pdf")

            assert await svc.addTime(fa.TASK) == "Add time in task successful"
            assert fake.requests[-1]["method"] == "PATCH"
            assert fake.paths()[-1] == f"/v1/analysis/addtime/{fa.TASK}"
            with pytest.raises(AnyRunApiError, match="has already been completed"):
                await svc.stopTask(fa.TASK)
            assert await svc.deleteTask(fa.TASK) == "Delete task successful"
            assert fake.paths("DELETE") == [f"/v1/analysis/delete/{fa.TASK}"]

            data = await svc.rawRequest("get", "v1/user")
            assert data["data"]["limits"]["parallels"]["total"] == 1

    async def test_status(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            status = await svc.status(fa.TASK)
            assert status["state"] == "completed" and status["uuid"] == fa.TASK
            assert fake.requests[-1]["headers"]["Accept"] == "text/event-stream"

            # A queued task's events switch to its real task once it starts, and a stream that
            # closes before the task finishes is reopened.
            fake.state["events"][fa.QUEUED] = [
                {"error": False, "message": "Task is queued and awaits execution."},
                {"error": False, "message": "Task will be launched soon."},
                fa.statusEvent(fa.NEWTASK, 30),
            ]
            fake.state["events"][fa.NEWTASK] = [fa.statusEvent(fa.NEWTASK, 100, completed=True)]
            items = await collect(svc.monitor(fa.QUEUED, timeout=10))
            assert [(i["uuid"], i["state"]) for i in items] == [
                (fa.QUEUED, "queued"),
                (fa.QUEUED, "preparing"),
                (fa.NEWTASK, "running"),
                (fa.NEWTASK, "completed"),
            ]
            assert fake.paths().count(f"/v1/analysis/monitor/{fa.NEWTASK}") == 1

            status = await svc.wait(fa.QUEUED, timeout=10)
            assert status["uuid"] == fa.NEWTASK and status["state"] == "completed"

            # The limit, and a task that never finishes stops at the timeout.
            assert len(await collect(svc.monitor(fa.QUEUED, limit=2))) == 2
            fake.state["events"][fa.NEWTASK] = [fa.statusEvent(fa.NEWTASK, 50)]
            status = await svc.wait(fa.NEWTASK, timeout=0.3)
            assert status["state"] == "running"

            # A failed task ends the wait.
            fake.state["events"][fa.NEWTASK] = [{"error": True, "message": "Pre-launch error occurred."}]
            assert (await svc.wait(fa.NEWTASK, timeout=10))["state"] == "failed"

            with pytest.raises(AnyRunApiError, match="Task not found"):
                await svc.status("00000000-0000-0000-0000-000000000000")
            fake.state["events"][fa.NEWTASK] = []
            with pytest.raises(AnyRunApiError, match="sent no status"):
                await svc.status(fa.NEWTASK)
            with pytest.raises(AnyRunApiError, match="sent no status"):
                await svc.wait(fa.NEWTASK, timeout=0.1)

    async def test_submit(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            sub = await svc.submitFile(
                [b"MZ", b"abc"], "a.exe", opts={"os": "windows", "timeout": 120, "network": False, "tags": ["x"]}
            )
            assert sub == {
                "task": fa.NEWTASK,
                "queue": None,
                "queued": False,
                "link": f"https://app.any.run/tasks/{fa.NEWTASK}",
                "message": "",
            }
            body = fake.requests[-1]["body"]
            assert body["obj_type"] == "file"
            assert body["file"] == {"filename": "a.exe", "data": b"MZabc"}
            # Multipart values are sent like ANY.RUN's SDK sends them.
            assert body["env_os"] == "windows" and body["opt_timeout"] == "120"
            assert body["opt_network_connect"] == "False" and body["user_tags"] == "x"

            sub = await svc.submitUrl("https://example.com/", opts={"browser": "Google Chrome", "mitm": True})
            assert sub["task"] == fa.NEWTASK
            assert fake.requests[-1]["body"] == {
                "obj_type": "url",
                "obj_url": "https://example.com/",
                "obj_ext_browser": "Google Chrome",
                "opt_network_mitm": True,
            }
            await svc.submitDownload("http://example.com/a.exe", opts={"useragent": "UA"})
            assert fake.requests[-1]["body"]["obj_type"] == "download"
            await svc.rerun(f"https://app.any.run/tasks/{fa.TASK}", opts={"timeout": 30})
            assert fake.requests[-1]["body"] == {"obj_type": "rerun", "task_rerun_uuid": fa.TASK, "opt_timeout": 30}

            # Queued submissions (202, with the docs' "error": "false," typo).
            fake.state["queue"] = True
            sub = await svc.submitUrl("https://example.com/")
            assert sub["queued"] and sub["task"] is None and sub["queue"] == fa.QUEUED
            assert sub["message"].startswith("Task is queued")
            fake.state["queue"] = False

            with pytest.raises(AnyRunApiError, match="cannot create public tasks"):
                await svc.submitUrl("https://example.com/", opts={"privacy": "public"})
            with pytest.raises(AnyRunApiError, match="isn't an http"):
                await svc.submitUrl("ftp://example.com/")
            with pytest.raises(AnyRunApiError, match="The file is empty"):
                await svc.submitFile([], "a.exe")
            count = len(fake.requests)
            with pytest.raises(AnyRunApiError, match="TOR geo"):
                await svc.submitFile([b"MZ"], "a.exe", opts={"geo": "XX"})
            assert len(fake.requests) == count

        async with fa.anyrunSvc(self, **{"anyrun:maxsize": 4}) as (core, svc, fake):
            with pytest.raises(AnyRunApiError, match="larger than the max of 4"):
                await svc.submitFile([b"MZabc"], "a.exe")
            with pytest.raises(AnyRunApiError, match="larger than the max of 4"):
                await download(svc.downloadPcap(fa.TASK))

    async def test_downloads(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            # Samples are unzipped and checked against the task's SHA256.
            assert await download(svc.downloadSample(fa.TASK)) == fa.SAMPLE
            assert fake.paths()[-1] == f"/tasks/{fa.TASK}/download/files/{fa.PROC_MAIN}/ab12"
            assert fake.requests[-1]["headers"]["Authorization"] == f"API-Key {fa.APIKEY}"

            assert await download(svc.downloadPcap(fa.TASK)) == fa.PCAP

            files = await svc.droppedFiles(fa.TASK)
            assert [f["sha256"] for f in files] == [fa.DROPPED_SHA256]
            assert await download(svc.downloadDropped(fa.TASK, fa.DROPPED_SHA256.upper())) == fa.DROPPED
            with pytest.raises(AnyRunApiError, match="no downloadable file"):
                await download(svc.downloadDropped(fa.TASK, "0" * 64))

            with pytest.raises(AnyRunApiError, match="analyzed a URL"):
                await download(svc.downloadSample(fa.URLTASK))
            with pytest.raises(AnyRunApiError, match="HTTP 404"):
                await download(svc.downloadPcap("00000000-0000-0000-0000-000000000000"))

            # The unpacking rules.
            assert svc._unpack(b"raw", None, "x") == b"raw"
            zipped = fa.zipped("a", b"inner")
            assert svc._unpack(zipped, None, "x") == b"inner"
            assert svc._unpack(zipped, hashlib.sha256(b"inner").hexdigest(), "x") == b"inner"
            with pytest.raises(AnyRunApiError, match="doesn't contain"):
                svc._unpack(zipped, "0" * 64, "x")
            with pytest.raises(AnyRunApiError, match="doesn't match"):
                svc._unpack(b"raw", "0" * 64, "x")

            # The API key is only ever sent to ANY.RUN's hosts.
            client = svc.client()
            with pytest.raises(AnyRunApiError, match="Refusing to send the API key"):
                await download(client.stream("https://evil.example.com/tasks/x"))

    async def test_lookup(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            resp = await svc.lookup('domainName:"c2.evil.example.com"', days=30, end="2026-10-31")
            assert resp["summary"]["threatLevel"] == 2
            body = fake.requests[-1]["body"]
            start = (datetime.datetime.now(datetime.UTC).date() - datetime.timedelta(days=30)).isoformat()
            assert body == {"query": 'domainName:"c2.evil.example.com"', "startDate": start, "endDate": "2026-10-31"}

            await svc.lookup("x", start="2026-01-01", days=None)
            assert fake.requests[-1]["body"] == {"query": "x", "startDate": "2026-01-01"}
            with pytest.raises(AnyRunApiError, match="isn't a YYYY-MM-DD"):
                await svc.lookup("x", start="nope")
            with pytest.raises(AnyRunApiError, match="query is empty"):
                await svc.lookup(" ")

            data = await svc.lookupIndicator("c2.evil.example.com")
            assert data["query"] == 'domainName:"c2.evil.example.com"' and data["verdict"] == 40
            data = await svc.lookupIndicator(fa.SAMPLE_SHA256)
            assert data["query"] == f'sha256:"{fa.SAMPLE_SHA256}"'
            data = await svc.normLookup("nothing")
            assert data["empty"] and data["query"] == "nothing"
            with pytest.raises(AnyRunApiError, match="Can't tell"):
                await svc.lookupIndicator("not an indicator")

            # A 429 that says when to come back is retried.
            fake.state["lookup_429"] = 1
            count = len(fake.requests)
            assert (await svc.lookup("x"))["summary"]["threatLevel"] == 2
            assert len(fake.requests) == count + 2
            fake.state["lookup_429"] = 5
            with pytest.raises(AnyRunApiError, match="TOO_MANY_REQUESTS"):
                await svc.lookup("x")

    async def test_yara(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            fake.state["yara_polls"] = 2
            res = await svc.yaraRun(fa.YARA_RULE, timeout=10, limit=0)
            assert res["search"] == fa.YARA_ID and res["done"] and res["status"] == "done"
            assert res["rule"] == "grimresources" and res["text"] == fa.YARA_RULE
            assert res["found"] == 2
            # The match without a SHA256 is dropped.
            assert [m["sha256"] for m in res["matches"]] == [fa.MATCH_SHA256]
            assert fake.requests[0]["body"] == {"query": fa.YARA_RULE}
            assert fake.paths().count(f"/v1/intelligence/yara-lookup/search/{fa.YARA_ID}/count") == 3

            # A search that's still running.
            fake.state["yara_polls"] = 1000
            res = await svc.yaraRun(fa.YARA_RULE, timeout=0)
            assert not res["done"] and res["status"] == "processing" and res["matches"] == []

            fake.state["yara_polls"] = 0
            res = await svc.yaraGet(fa.YARA_ID, limit=1)
            assert res["done"] and len(res["matches"]) == 1
            assert fake.requests[-1]["query"] == {"offset": "0", "limit": "1"}

            assert (await svc.yaraStop(fa.YARA_ID))["status"] == "cancelled"
            with pytest.raises(AnyRunApiError, match="Invalid YARA rule"):
                await svc.yaraRun("nope")
            with pytest.raises(AnyRunApiError, match="The YARA rule is empty"):
                await svc.yaraRun("")
            with pytest.raises(AnyRunApiError, match="NOT_FOUND"):
                await svc.yaraGet("00000000-0000-0000-0000-000000000000")
            with pytest.raises(AnyRunApiError, match="sort must be"):
                await svc.yaraResults(fa.YARA_ID, sort="random")

    async def test_feeds(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            assert (await svc.feeds())[0]["title"] == "full"

            items = await collect(svc.feedObjects(added="2026-10-01T00:00:00Z", limit=0))
            assert [i["observables"][0]["value"] for i in items] == [
                "203.0.113.10",
                "c2.evil.example.com",
                "http://c2.evil.example.com/gate.php",
                fa.SAMPLE_SHA256,
            ]
            reqs = [r for r in fake.requests if r["path"].endswith("/objects/")]
            assert len(reqs) == 3
            # Brackets stay literal, and base64 cursors are percent-encoded.
            assert "match[type]=indicator" in reqs[0]["rawquery"]
            assert "added_after=2026-10-01T00%3A00%3A00Z" in reqs[0]["rawquery"]
            assert "next=Mg%3D%3D" in reqs[1]["rawquery"]
            assert reqs[1]["query"]["next"] == "Mg=="

            items = await collect(svc.feedObjects(limit=1))
            assert len(items) == 1

            with pytest.raises(AnyRunApiError, match="Unknown feed"):
                await collect(svc.feedObjects(feed="nope"))
            with pytest.raises(AnyRunApiError, match="could not be found"):
                await collect(svc.feedObjects(feed="ip"))

    async def test_telepath(self):
        async with fa.anyrunSvc(self) as (core, svc, fake):
            async with svc.getLocalProxy() as prox:
                retn = await prox.limits()
                assert retn["status"] and retn["data"]["api"]["month"] == 250
                retn = await prox.report("nope")
                assert not retn["status"] and "isn't an ANY.RUN task ID" in retn["mesg"]
                retn = await prox.history(limit="lots")
                assert not retn["status"] and retn["mesg"].startswith("Invalid input")

                items = [i async for i in prox.downloadPcap(fa.TASK)]
                assert items == [{"status": True, "mesg": "", "data": fa.PCAP}]
                items = [i async for i in prox.downloadSample(fa.URLTASK)]
                assert len(items) == 1 and not items[0]["status"]

                retn = await prox.hasApiKey()
                assert retn["data"] is True
                retn = await prox.setApiKey(None)
                assert retn["mesg"] == "Cleared the slib.anyrun API key."

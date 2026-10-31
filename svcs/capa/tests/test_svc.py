"""Pytests for the slib.capa service (CapaSvc and its Telepath API), outside of Storm."""

import asyncio
import hashlib
import os
import shutil
from unittest import mock
import sys

import synapse.common as s_common
import synapse.tests.utils as s_tests

from capasvc import CapaSvc, svc as s_svc
from capasvc.api import CapaSvcError
from capasvc.rules import ruleGuid

from .capatest import MATCHED, RULES, RULES_VERSION, SAMPLE, SAMPLE_SHA256, svcConf


async def waitProcs(svc) -> None:
    """Wait for the service's subprocesses (ex. building the rules cache) to finish."""

    for _ in range(300):
        if not svc.procs:
            return
        await asyncio.sleep(0.1)
    raise AssertionError("The service's subprocesses didn't finish.")


class TestHelpers:

    def test_fmtAddr(self):
        assert s_svc.fmtAddr({"type": "absolute", "value": 0x401000}) == "0x401000"
        assert s_svc.fmtAddr({"type": "no address"}) is None
        assert s_svc.fmtAddr({"type": "file", "value": 23}) == "file:0x17"
        assert s_svc.fmtAddr({"type": "process", "value": {"pid": 1, "ppid": 0}}) == (
            'process:{"pid": 1, "ppid": 0}'
        )
        assert s_svc.fmtAddr("weird") == "weird"

    def test_stderrMesg(self):
        text = (
            "ERROR    capa:                                                    helpers.py:271\n"
            "         --------------------------------------------------------\n"
            "ERROR    capa:  Input file does not appear to be a supported      helpers.py:272\n"
            "         file.\n"
        )
        assert s_svc.stderrMesg(text) == "Input file does not appear to be a supported file."
        assert s_svc.stderrMesg("") == ""


class TestCapaSvc(s_tests.SynTest):

    async def test_scan(self):
        async with self.getTestAxon() as axon:
            await axon.put(SAMPLE)
            async with self.getTestCell(CapaSvc, svcConf(axon)) as svc:
                res = await svc.scan(SAMPLE_SHA256.upper(), fmt="sc64")

                assert res["sha256"] == SAMPLE_SHA256
                assert res["md5"] and res["sha1"]
                assert res["capa"] == "10.0.0"
                assert res["rules"] == {"version": RULES_VERSION, "sha256": svc.capaRules.sha256}
                assert res["flavor"] == "static"
                assert res["format"] == "sc64"
                assert res["arch"] == "amd64"
                assert res["extractor"] == "VivisectFeatureExtractor"

                # Library rules (contain ret) aren't reported, the rules that use them are.
                assert [m["rule"]["name"] for m in res["matches"]] == MATCHED
                bynames = {m["rule"]["name"]: m for m in res["matches"]}

                xor = bynames["contain xor"]
                assert xor["count"] == 1
                assert xor["addrs"] == ["0x690000"]
                assert xor["rule"] == svc.capaRules.rules["contain xor"]

                # File scope matches have no address.
                marker = bynames["contain slib-capa test marker"]
                assert marker["count"] == 1 and marker["addrs"] == []
                assert marker["rule"]["tag"] == "testing.slib_capa"

                # The file is removed once it's scanned.
                assert os.listdir(svc.workdir) == []

                # The rules cache was built in the service's storage before the scan.
                assert svc.cacheReady.is_set()
                assert any(n.endswith(".cache") for n in os.listdir(svc.cachedir))

    async def test_scan_errors(self):
        async with self.getTestAxon() as axon:
            await axon.put(SAMPLE)
            await axon.put(b"hello world")
            async with self.getTestCell(CapaSvc, svcConf(axon, **{"capa:maxsize": 32})) as svc:

                with self.raises(CapaSvcError) as cm:
                    await svc.scan("newp")
                assert "Invalid SHA256" in cm.exception.mesg

                with self.raises(CapaSvcError) as cm:
                    await svc.scan(SAMPLE_SHA256, fmt="cape")
                assert "Invalid format cape" in cm.exception.mesg

                with self.raises(CapaSvcError) as cm:
                    await svc.scan(SAMPLE_SHA256, osname="android")
                assert "Invalid OS android" in cm.exception.mesg

                with self.raises(CapaSvcError) as cm:
                    await svc.scan("00" * 32)
                assert "is not in the Axon" in cm.exception.mesg

                with self.raises(CapaSvcError) as cm:
                    await svc.scan(SAMPLE_SHA256, fmt="sc64")
                assert "more than the 32 byte max" in cm.exception.mesg

                # capa's own errors.
                hello = hashlib.sha256(b"hello world").hexdigest()
                with self.raises(CapaSvcError) as cm:
                    await svc.scan(hello)
                assert cm.exception.mesg.startswith("The file is not a format capa supports: ")
                assert "does not appear to be a supported file" in cm.exception.mesg
                assert os.listdir(svc.workdir) == []

    async def test_scan_proc_errors(self):
        async with self.getTestAxon() as axon:
            await axon.put(SAMPLE)
            conf = svcConf(axon, **{"capa:timeout": 1})
            async with self.getTestCell(CapaSvc, conf) as svc:
                await waitProcs(svc)

                def cmd(code):
                    return lambda *args: [sys.executable, "-c", code]

                svc._capaCmd = cmd("import time; time.sleep(30)")
                with self.raises(CapaSvcError) as cm:
                    await svc.scan(SAMPLE_SHA256)
                assert "longer than 1 seconds" in cm.exception.mesg
                assert not svc.procs

                svc._capaCmd = cmd("print('newp')")
                with self.raises(CapaSvcError) as cm:
                    await svc.scan(SAMPLE_SHA256)
                assert "invalid JSON" in cm.exception.mesg

                svc._capaCmd = cmd("import sys; sys.exit(99)")
                with self.raises(CapaSvcError) as cm:
                    await svc.scan(SAMPLE_SHA256)
                assert cm.exception.mesg == "capa failed (exit code 99)"

                # Running capa processes are killed with the service.
                svc._capaCmd = cmd("import time; time.sleep(30)")
                task = svc.schedCoro(svc.scan(SAMPLE_SHA256))
                for _ in range(100):
                    if svc.procs:
                        break
                    await asyncio.sleep(0.05)
                proc = list(svc.procs)[0]
                assert proc.returncode is None
                await svc.fini()
                await asyncio.wait_for(proc.wait(), timeout=5)
                assert proc.returncode != 0
                assert task.done()

    async def test_axon_errors(self):
        async with self.getTestCell(CapaSvc, svcConf()) as svc:
            with self.raises(CapaSvcError) as cm:
                await svc.scan(SAMPLE_SHA256)
            assert "no axon:url configured" in cm.exception.mesg

        # The Axon is down, the client keeps trying to connect in the background.
        conf = svcConf(**{"axon:url": "tcp://127.0.0.1:1/axon"})
        async with self.getTestCell(CapaSvc, conf) as svc:
            with mock.patch.object(s_svc, "AXON_TIMEOUT", 0.5):
                with self.raises(CapaSvcError) as cm:
                    await svc.scan(SAMPLE_SHA256)
            assert cm.exception.mesg == "Unable to connect to the Axon within 0.5 seconds."

    async def test_axon_client(self):
        # Every scan uses the service's one Axon client, which reconnects if the link drops.
        async with self.getTestAxon() as axon:
            await axon.put(SAMPLE)
            async with self.getTestCell(CapaSvc, svcConf(axon)) as svc:
                proxy = await svc.axon.proxy()
                await svc._fetch(SAMPLE_SHA256, os.path.join(svc.workdir, "a"))
                assert await svc.axon.proxy() is proxy

                await proxy.fini()
                path = os.path.join(svc.workdir, "b")
                await svc._fetch(SAMPLE_SHA256, path)
                with open(path, "rb") as fd:
                    assert fd.read() == SAMPLE

                # Other Axon errors are reported.
                newproxy = await svc.axon.proxy()
                with mock.patch.object(newproxy, "size", side_effect=OSError("boom")):
                    with self.raises(CapaSvcError) as cm:
                        await svc._fetch(SAMPLE_SHA256, path)
                assert cm.exception.mesg == f"Unable to read {SAMPLE_SHA256} from the Axon: boom"

            # The client is closed with the service.
            assert svc.axon.isfini

    async def test_rules(self):
        async with self.getTestCell(CapaSvc, svcConf()) as svc:
            info = await svc.rulesInfo()
            assert info["capa"] == "10.0.0"
            assert info["rules"] == 6 and info["version"] == RULES_VERSION

            names = [r["name"] async for r in svc.rules()]
            assert names == sorted(svc.capaRules.rules)
            recs = [r async for r in svc.rules(names=["contain xor", "contain xor"])]
            assert [r["guid"] for r in recs] == [ruleGuid("contain xor")]
            with self.raises(CapaSvcError) as cm:
                [r async for r in svc.rules(names=["contain xor", "newp"])]
            assert cm.exception.mesg == "Unknown capa rules: newp"

            tags = await svc.tags()
            assert "testing.ops.xor" in [t["tag"] for t in tags]

            assert (await svc.reload())["sha256"] == info["sha256"]

    async def test_no_rules(self):
        # The service starts without rules, and reports why it can't scan.
        async with self.getTestCell(CapaSvc, {}) as svc:
            assert svc.capaRules is None
            for coro in (svc.rulesInfo(), svc.tags(), svc.scan(SAMPLE_SHA256), svc.reload()):
                with self.raises(CapaSvcError) as cm:
                    await coro
                assert "no capa:rules directory configured" in cm.exception.mesg

        with self.getTestDir() as dirn:
            async with self.getTestCell(CapaSvc, {"capa:rules": dirn}) as svc:
                with self.raises(CapaSvcError) as cm:
                    await svc.rulesInfo()
                assert "has no rules" in cm.exception.mesg

            # An unreadable rule doesn't stop the service from starting either.
            with open(os.path.join(dirn, "rule.yml"), "wb") as fd:
                fd.write(b"\xff\xfe")
            async with self.getTestCell(CapaSvc, {"capa:rules": dirn}) as svc:
                with self.raises(CapaSvcError) as cm:
                    await svc.rulesInfo()
                assert "Unable to read the capa rule rule.yml" in cm.exception.mesg

    async def test_rules_changed(self):
        # Scans refuse to run with rules on disk that aren't the loaded rules.
        with self.getTestDir() as dirn:
            rules = os.path.join(dirn, "rules")
            shutil.copytree(RULES, rules)
            async with self.getTestAxon() as axon:
                await axon.put(SAMPLE)
                async with self.getTestCell(CapaSvc, svcConf(axon, **{"capa:rules": rules})) as svc:
                    extra = os.path.join(rules, "testing", "never.yml")
                    with open(extra, "a") as fd:
                        fd.write("# changed\n")

                    with self.raises(CapaSvcError) as cm:
                        await svc.scan(SAMPLE_SHA256, fmt="sc64")
                    assert "changed since the service loaded them" in cm.exception.mesg

                    os.unlink(extra)
                    with self.raises(CapaSvcError) as cm:
                        await svc.scan(SAMPLE_SHA256, fmt="sc64")
                    assert "changed since the service loaded them" in cm.exception.mesg

                    shutil.rmtree(rules)
                    with self.raises(CapaSvcError) as cm:
                        await svc.scan(SAMPLE_SHA256, fmt="sc64")
                    assert "The capa rules on disk can't be read" in cm.exception.mesg

    async def test_cache_cleanup(self):
        # Reloading the rules deletes capa's caches of other rules, once the new cache is built.
        with self.getTestDir() as dirn:
            rules = os.path.join(dirn, "rules")
            shutil.copytree(RULES, rules)
            async with self.getTestCell(CapaSvc, svcConf(**{"capa:rules": rules})) as svc:
                await asyncio.wait_for(svc.cacheReady.wait(), timeout=60)
                old = svc.capaRules.cacheName(svc.cachedir)
                assert os.listdir(svc.cachedir) == [old]

                other = os.path.join(svc.cachedir, "notacache.txt")
                with open(other, "w") as fd:
                    fd.write("x")

                with open(os.path.join(rules, "testing", "never.yml"), "a") as fd:
                    fd.write("# changed\n")
                await svc.reload()
                await asyncio.wait_for(svc.cacheReady.wait(), timeout=60)

                new = svc.capaRules.cacheName(svc.cachedir)
                assert new != old
                assert sorted(os.listdir(svc.cachedir)) == sorted([new, "notacache.txt"])

                # A failed build (capa rejects a rule that depends on a missing rule) keeps them.
                with open(os.path.join(rules, "testing", "bad.yml"), "w") as fd:
                    fd.write(
                        "rule:\n  meta:\n    name: bad\n    scopes:\n      static: function\n"
                        "      dynamic: unsupported\n  features:\n    - match: newp\n"
                    )
                await svc.reload()
                await asyncio.wait_for(svc.cacheReady.wait(), timeout=60)
                assert new in os.listdir(svc.cachedir)

    async def test_cache_lock(self):
        # Rule cache builds run one at a time, and scans wait for the latest one.
        async with self.getTestCell(CapaSvc, svcConf()) as svc:
            await waitProcs(svc)
            async with svc.cacheLock:
                await svc.reload()
                await asyncio.sleep(0.2)
                assert not svc.cacheReady.is_set()
                assert not svc.procs
            await asyncio.wait_for(svc.cacheReady.wait(), timeout=60)

    async def test_leftovers(self):
        with self.getTestDir() as dirn:
            work = s_common.gendir(dirn, "capa", "work")
            with open(os.path.join(work, "leftover"), "wb") as fd:
                fd.write(b"x")
            async with self.getTestCell(CapaSvc, svcConf(), dirn=dirn):
                assert os.listdir(work) == []

    async def test_summarize_unknown_rule(self):
        # Rules that changed on disk since they were loaded are modeled from capa's results.
        async with self.getTestCell(CapaSvc, svcConf()) as svc:
            doc = {
                "meta": {"sample": {}, "analysis": {}},
                "rules": {
                    "a new rule": {
                        "meta": {"namespace": "new/ns", "description": "New."},
                        "source": "rule: ...",
                        "matches": [[{"type": "absolute", "value": 16}, {}]],
                    },
                },
            }
            res = svc._summarize(svc.capaRules, SAMPLE_SHA256, doc)
            assert res["sha256"] == SAMPLE_SHA256
            rule = res["matches"][0]["rule"]
            assert rule["guid"] == ruleGuid("a new rule")
            assert (rule["tag"], rule["desc"], rule["text"]) == ("new.ns", "New.", "rule: ...")
            assert res["matches"][0]["addrs"] == ["0x10"]


class TestCapaApi(s_tests.SynTest):

    async def test_api(self):
        async with self.getTestAxon() as axon:
            await axon.put(SAMPLE)
            async with self.getTestCell(CapaSvc, svcConf(axon)) as svc:
                async with svc.getLocalProxy() as prox:
                    retn = await prox.scan(SAMPLE_SHA256, fmt="sc64")
                    assert retn["status"] is True and retn["mesg"] == ""
                    assert [m["rule"]["name"] for m in retn["data"]["matches"]] == MATCHED

                    retn = await prox.scan("newp")
                    assert retn["status"] is False and "Invalid SHA256" in retn["mesg"]
                    assert retn["data"] is None

                    retn = await prox.rulesInfo()
                    assert retn["status"] and retn["data"]["path"] == os.path.abspath(RULES)

                    retns = [r async for r in prox.rules()]
                    assert len(retns) == 6 and all(r["status"] for r in retns)

                    retns = [r async for r in prox.rules(names=["newp"])]
                    assert retns == [
                        {"status": False, "mesg": "Unknown capa rules: newp", "data": None},
                    ]

                    assert (await prox.tags())["status"]
                    assert (await prox.reload())["status"]

"""Pytests for the slib.pcap service (PcapSvc) and its Telepath API."""


import gzip
import hashlib
import pathlib
import tomllib

import synapse.tests.utils as s_tests
import yaml

import pcapsvc
from pcapsvc import PcapSvc
from pcapsvc import tshark as p_tshark
from pcapsvc.defs import SVC_NAME

from . import pcapgen as g
from .engines import needs

SVCDIR = pathlib.Path(__file__).parent.parent


async def collect(genr) -> list:
    return [item async for item in genr]


class SvcProx:
    """Calls the service's Telepath API (the test helpers only give a Cortex proxy)."""

    def __init__(self, svc: PcapSvc) -> None:
        self.svc = svc

    async def flows(self, *args, **kwargs):
        async with self.svc.getLocalProxy() as prox:
            async for item in prox.flows(*args, **kwargs):
                yield item

    async def call(self, name, *args, **kwargs):
        async with self.svc.getLocalProxy() as prox:
            return await getattr(prox, name)(*args, **kwargs)

    async def upload(self, byts: bytes, kind: str = "capture", size: int = 7) -> str:
        """Stream a file to the service in small chunks, returning the upload's ID."""

        retn = await self.call("uploadStart", kind=kind)
        assert retn["status"], retn
        for off in range(0, len(byts), size):
            chunk = await self.call("uploadChunk", retn["data"], byts[off:off + size])
            assert chunk["status"], chunk
        return retn["data"]


class TestPcapSvc(s_tests.SynTest):

    def test_versions_match(self):
        pyproj = tomllib.loads((SVCDIR / "pyproject.toml").read_text())
        pkg = yaml.safe_load((SVCDIR / "src/pcapsvc/pkgproto/slib.pcap.yaml").read_text())
        lock = tomllib.loads((SVCDIR / "uv.lock").read_text())
        locked = [p["version"] for p in lock["package"] if p["name"] == "pcapsvc"]

        assert pyproj["project"]["version"] == pcapsvc.__version__
        assert pkg["version"] == pcapsvc.__version__
        assert locked == [pcapsvc.__version__]

    async def test_svc_starts(self):
        async with self.getTestCoreProxSvc(PcapSvc) as (core, _, svc):
            msgs = await core.stormlist("service.list")
            self.stormIsInPrint(f"true (svc) ({SVC_NAME} @ {pcapsvc.__version__})", msgs)

            assert "slib.pcap.flows" in core.stormcmds
            for cmd in ("slib.pcap.status", "slib.pcap.sync", "slib.pcap.rule.add",
                        "slib.pcap.rule.check", "slib.pcap.admin.feed", "slib.pcap.admin.decode"):
                assert cmd in core.stormcmds
            for mod in ("slib.pcap.lib", "slib.pcap.model", "slib.pcap.util",
                        "slib.pcap.priv.user", "slib.pcap.priv.rules", "slib.pcap.priv.sync",
                        "slib.pcap.priv.admin"):
                assert mod in core.stormmods
                self.stormHasNoErr(await core.stormlist(f"$mod = $lib.import({mod})"))

            # The add event creates the service's meta:source and the sync cron job.
            self.len(1, await core.nodes("meta:source:name=slib.pcap"))
            iden = await core.callStorm('return($lib.globals.get("slib:pcap:cron"))')
            assert iden
            crons = await core.callStorm("return($lib.cron.list())")
            assert [c["iden"] for c in crons if c["iden"] == iden] == [iden]

            status = (await SvcProx(svc).call("status"))["data"]
            assert set(status) == {"engines", "sandbox", "axon", "rules"}
            assert set(status["engines"]) == {"suricata", "snort", "tshark"}
            assert status["axon"] is False
            assert (await SvcProx(svc).call("hasAxon"))["data"] is False

    async def test_flows(self):
        async with self.getTestAxon() as axon:
            _, sha = await axon.put(g.pcap(g.session()))
            _, gzsha = await axon.put(gzip.compress(g.pcap(g.session())))
            _, notpcap = await axon.put(b"definitely not a pcap")
            conf = {"axon:url": axon.getLocalUrl()}
            async with self.getTestCoreProxSvc(PcapSvc, ssvc_conf=conf) as (_, _, svc):
                prox = SvcProx(svc)

                retns = await collect(prox.flows(sha.hex()))
                assert all(r["status"] for r in retns)
                summary = retns[0]["data"]["summary"]
                assert summary["sha256"] == sha.hex()
                assert summary["size"] == len(g.pcap(g.session()))
                assert summary["flows"] == 4
                flows = [r["data"]["flow"] for r in retns[1:]]
                assert len(flows) == 4

                # Idens are tied to the capture's SHA-256.
                flows2 = [r["data"]["flow"] for r in (await collect(prox.flows(gzsha.hex())))[1:]]
                assert not {f["iden"] for f in flows} & {f["iden"] for f in flows2}

                # file:bytes style values and upper case are fine.
                retns = await collect(prox.flows(f"sha256:{sha.hex().upper()}"))
                assert retns[0]["status"] and retns[0]["data"]["summary"]["sha256"] == sha.hex()

                # Options.
                retns = await collect(prox.flows(sha.hex(), timeout=0, limit=1, handshake=0))
                assert len(retns) == 2
                assert retns[0]["data"]["summary"]["limited"]
                assert retns[1]["data"]["flow"]["src"]["handshake"] is None

                # The limit is capped by the config.
                svc.conf["pcap:limit"] = 2
                retns = await collect(prox.flows(sha.hex(), limit=100))
                assert len(retns) == 3
                retns = await collect(prox.flows(sha.hex()))
                assert len(retns) == 3
                svc.conf["pcap:limit"] = 100000

                # Errors.
                missing = hashlib.sha256(b"missing").hexdigest()
                for args, kwargs, mesg in (
                    (("nope",), {}, "Invalid SHA-256: nope"),
                    ((missing,), {}, f"file:bytes:sha256={missing} is not in the Axon."),
                    ((notpcap.hex(),), {}, "The file is not a pcap or pcapng file"),
                    ((sha.hex(),), {"timeout": -1}, "Invalid timeout -1"),
                    ((sha.hex(),), {"limit": "x"}, "Invalid limit 'x'"),
                    ((sha.hex(),), {"handshake": True}, "Invalid handshake True"),
                ):
                    retns = await collect(prox.flows(*args, **kwargs))
                    assert len(retns) == 1
                    assert not retns[0]["status"]
                    assert mesg in retns[0]["mesg"], retns[0]["mesg"]

                svc.conf["pcap:maxsize"] = 10
                retns = await collect(prox.flows(sha.hex()))
                assert not retns[0]["status"]
                assert "larger than the max size of 10 bytes" in retns[0]["mesg"]

                # Temp files are cleaned up.
                assert list(pathlib.Path(svc.tmpdir).iterdir()) == []

    async def test_axon_errors(self):
        async with self.getTestCoreProxSvc(PcapSvc) as (_, _, svc):
            prox = SvcProx(svc)
            sha = hashlib.sha256(b"x").hexdigest()
            retns = await collect(prox.flows(sha))
            assert not retns[0]["status"]
            assert retns[0]["mesg"] == \
                "The service has no axon:url, the capture must be uploaded."
            retns = await collect(prox.flows(sha, keylogs=[sha], upload="x"))
            assert retns[0]["mesg"] == "The service has no axon:url, key logs must be uploaded."

            # An Axon that can't be reached.
            svc.axonurl = "tcp://127.0.0.1:1/axon"
            retns = await collect(prox.flows(sha))
            assert len(retns) == 1 and not retns[0]["status"]
            assert retns[0]["mesg"].startswith(f"Unable to read {sha}")

    async def test_axon_file_vanishes(self):
        # A file deleted between the size check and the download.
        async with self.getTestAxon() as axon:
            _, sha = await axon.put(g.pcap(g.session()))
            conf = {"axon:url": axon.getLocalUrl()}
            async with self.getTestCoreProxSvc(PcapSvc, ssvc_conf=conf) as (_, _, svc):
                prox = SvcProx(svc)
                orig = axon.get

                async def get(sha256, *args, **kwargs):
                    await axon.del_(sha256)
                    async for byts in orig(sha256, *args, **kwargs):
                        yield byts

                axon.get = get
                retns = await collect(prox.flows(sha.hex()))
                assert not retns[0]["status"]
                assert "is not in the Axon" in retns[0]["mesg"]


DATA = pathlib.Path(__file__).parent / "data"
needsTshark = needs("tshark")


class TestPcapSvcUploads(s_tests.SynTest):

    async def test_uploads(self):
        # Without an Axon, Storm streams the capture (and key logs) to the service.
        data = g.pcap(g.session())
        sha = hashlib.sha256(data).hexdigest()
        async with self.getTestCoreProxSvc(PcapSvc) as (_, _, svc):
            prox = SvcProx(svc)
            iden = await prox.upload(data)
            retns = await collect(prox.flows(sha, upload=iden))
            assert all(r["status"] for r in retns), retns[0]
            summary = retns[0]["data"]["summary"]
            assert summary["size"] == len(data) and summary["flows"] == 4
            # Uploads are used once.
            assert iden not in svc.uploads
            retns = await collect(prox.flows(sha, upload=iden))
            assert retns[0]["mesg"] == f"Unknown upload: {iden}"

            # The upload's SHA-256 has to match.
            iden = await prox.upload(data)
            other = hashlib.sha256(b"other").hexdigest()
            retns = await collect(prox.flows(other, upload=iden))
            assert retns[0]["mesg"] == \
                f"The uploaded capture has the SHA-256 {sha}, not {other}."
            assert iden not in svc.uploads

            # Key logs are uploads too, and can't be used as captures (or the other way around).
            klog = await prox.upload(b"CLIENT_RANDOM 00 00\n", kind="keylog")
            retns = await collect(prox.flows(sha, upload=klog))
            assert retns[0]["mesg"] == f"Unknown upload: {klog}"
            iden = await prox.upload(data)
            retns = await collect(prox.flows(sha, upload=iden, keyloguploads=[klog], tshark=False))
            assert retns[0]["status"] and retns[0]["data"]["summary"]["keylogs"] == 1

            retn = await prox.call("uploadStart", kind="nope")
            assert not retn["status"] and "Invalid upload kind 'nope'" in retn["mesg"]
            retn = await prox.call("uploadChunk", "nope", b"x")
            assert retn["mesg"] == "Unknown upload: nope"

            # Over the size limit.
            svc.conf["pcap:maxsize"] = 10
            iden = (await prox.call("uploadStart"))["data"]
            retn = await prox.call("uploadChunk", iden, b"x" * 11)
            assert retn["mesg"] == \
                "The capture is larger than the service's max size of 10 bytes."
            assert iden not in svc.uploads
            svc.conf["pcap:maxsize"] = 1 << 30

            # Cancelled and idle uploads are removed (with their files).
            iden = await prox.upload(b"abc")
            path = svc.uploads[iden]["path"]
            assert (await prox.call("uploadCancel", iden))["data"] is True
            assert (await prox.call("uploadCancel", iden))["data"] is False
            assert not pathlib.Path(path).exists()
            iden = await prox.upload(b"abc")
            assert svc._pruneUploads(idle=-1) == [iden]
            assert svc.uploads == {}

            # Files are counted, not saved, without an Axon.
            retns = await collect(prox.flows(sha, upload=await prox.upload(data)))
            files = retns[0]["data"]["summary"]["files"]
            assert files["count"] == 0 and "unsaved" in files

            # Unknown options are refused.
            retns = await collect(prox.flows(sha, nope=1))
            assert retns == [{"status": False, "mesg": "Unknown options: nope", "data": None}]
            assert list(pathlib.Path(svc.tmpdir).iterdir()) == []


DATA = pathlib.Path(__file__).parent / "data"
needsTshark = needs("tshark")
NOENGINES = {"suricata:bin": "/nonexistent/suricata", "snort:bin": "/nonexistent/snort"}


class TestPcapSvcTshark(s_tests.SynTest):

    async def test_no_tshark(self):
        async with self.getTestAxon() as axon:
            _, sha = await axon.put(g.pcap(g.session()))
            conf = {"axon:url": axon.getLocalUrl(), "tshark:path": "/nonexistent/tshark",
                    **NOENGINES}
            async with self.getTestCoreProxSvc(PcapSvc, ssvc_conf=conf) as (_, _, svc):
                prox = SvcProx(svc)
                retns = await collect(prox.flows(sha.hex()))
                summary = retns[0]["data"]["summary"]
                assert summary["engines"]["tshark"] == {"enabled": False,
                                                        "error": "tshark is not installed"}
                assert summary["engines"]["suricata"] == {"enabled": False,
                                                          "error": "Suricata is not installed"}
                # Snort only runs with rules.
                assert summary["engines"]["snort"] == {"enabled": False, "error": None}
                assert summary["files"] == {"count": 0, "skipped": 0, "uploaded": 0}
                assert summary["hits"] == 0
                # Flows still have every key, just empty.
                flow = retns[1]["data"]["flow"]
                assert flow["src"]["txfiles"] == () and flow["hits"] == ()
                assert flow["community_id"].startswith("1:")

                retns = await collect(prox.flows(sha.hex(), tshark=False, suricata=False))
                engines = retns[0]["data"]["summary"]["engines"]
                assert engines["tshark"]["error"] is None
                assert engines["suricata"]["error"] is None

    async def test_tshark_fails(self):
        async with self.getTestAxon() as axon:
            _, sha = await axon.put(g.pcap(g.session()))
            conf = {"axon:url": axon.getLocalUrl(), **NOENGINES}
            async with self.getTestCoreProxSvc(PcapSvc, ssvc_conf=conf) as (_, _, svc):
                async def broken(path, **kwargs):
                    raise p_tshark.TsharkError("boom")
                svc.tshark.path = "/bin/true"
                svc.tshark.frames = broken
                retns = await collect(SvcProx(svc).flows(sha.hex()))
                summary = retns[0]["data"]["summary"]
                tsinfo = summary["engines"]["tshark"]
                assert tsinfo["enabled"] and tsinfo["error"] == "boom"
                assert len(retns) == 5

    @needsTshark
    async def test_files(self):
        async with self.getTestAxon() as axon:
            _, sha = await axon.put((DATA / "http.pcapng").read_bytes())
            conf = {"axon:url": axon.getLocalUrl(), **NOENGINES}
            async with self.getTestCoreProxSvc(PcapSvc, ssvc_conf=conf) as (_, _, svc):
                prox = SvcProx(svc)
                download = hashlib.sha256(bytes(range(256)) * 64).digest()
                assert not await axon.has(download)

                retns = await collect(prox.flows(sha.hex(), files=False))
                assert retns[0]["data"]["summary"]["files"] is None
                assert not await axon.has(download)

                retns = await collect(prox.flows(sha.hex()))
                summary = retns[0]["data"]["summary"]
                tsinfo = summary["engines"]["tshark"]
                assert tsinfo["enabled"] and tsinfo["error"] is None
                assert tsinfo["version"].startswith("TShark")
                assert summary["files"] == {"count": 3, "skipped": 0, "uploaded": 3}
                assert await axon.has(download)
                assert b"".join([b async for b in axon.get(download)]) == bytes(range(256)) * 64

                # Files already in the Axon aren't uploaded again.
                retns = await collect(prox.flows(sha.hex()))
                assert retns[0]["data"]["summary"]["files"]["uploaded"] == 0

                # Only the 6 byte response fits.
                svc.conf["pcap:files:maxsize"] = 100
                retns = await collect(prox.flows(sha.hex()))
                assert retns[0]["data"]["summary"]["files"] == {"count": 1, "skipped": 2,
                                                                "uploaded": 0}

                svc.conf["tshark:enabled"] = False
                retns = await collect(prox.flows(sha.hex()))
                assert not retns[0]["data"]["summary"]["engines"]["tshark"]["enabled"]
                retns = await collect(prox.flows(sha.hex(), tshark=True))
                assert retns[0]["data"]["summary"]["engines"]["tshark"]["enabled"]

    @needsTshark
    async def test_files_unsaved(self):
        # Without an Axon, the files that would have been saved are counted.
        data = (DATA / "http.pcapng").read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        async with self.getTestCoreProxSvc(PcapSvc, ssvc_conf=NOENGINES) as (_, _, svc):
            prox = SvcProx(svc)
            retns = await collect(prox.flows(sha, upload=await prox.upload(data, size=4096)))
            summary = retns[0]["data"]["summary"]
            assert summary["files"] == {"count": 0, "skipped": 0, "unsaved": 3}
            flows = [r["data"]["flow"] for r in retns[1:]]
            assert not any(f["src"]["txfiles"] or f["dst"]["txfiles"] for f in flows)


class TestPcapSvcOptions(s_tests.SynTest):

    async def test_keylogs_decode(self):
        async with self.getTestAxon() as axon:
            _, sha = await axon.put(g.pcap(g.session()))
            _, keylog = await axon.put(b"CLIENT_RANDOM 00 00\n")
            conf = {"axon:url": axon.getLocalUrl(), "tshark:path": "/nonexistent/tshark",
                    **NOENGINES}
            async with self.getTestCoreProxSvc(PcapSvc, ssvc_conf=conf) as (_, _, svc):
                prox = SvcProx(svc)
                missing = hashlib.sha256(b"missing").hexdigest()
                for kwargs, mesg in (
                    ({"keylogs": ["nope"]}, "Invalid SHA-256: nope"),
                    ({"decode": ["-X lua_script:evil.lua"]}, "Invalid Decode As rule"),
                    ({"decode": "tcp.port==1,tls"}, "must be a list"),
                ):
                    retns = await collect(prox.flows(sha.hex(), **kwargs))
                    assert not retns[0]["status"] and mesg in retns[0]["mesg"], retns[0]["mesg"]

                # Without tshark the key logs and rules aren't used, but are still reported.
                retns = await collect(prox.flows(sha.hex(), keylogs=[keylog.hex()],
                                                 decode=["TCP.port==8443,tls"]))
                summary = retns[0]["data"]["summary"]
                assert summary["keylogs"] == 1 and summary["decode"] == ("tcp.port==8443,tls",)
                assert summary["engines"]["tshark"]["error"] == "tshark is not installed"

                # With tshark, key logs have to be in the Axon and under the size limit.
                svc.tshark.path = "/bin/true"
                async def frames(path, keylog=None, decode=(), gaps=False):
                    assert open(keylog, "rb").read() == b"CLIENT_RANDOM 00 00\n\n" * 2
                    assert decode == ["tcp.port==8443,tls"]
                    assert not gaps
                    return {}, {"version": "fake", "error": None}
                svc.tshark.frames = frames
                retns = await collect(prox.flows(sha.hex(), keylogs=[keylog.hex(), keylog.hex()],
                                                 decode=["tcp.port==8443,tls"]))
                assert retns[0]["status"] and retns[0]["data"]["summary"]["keylogs"] == 2

                retns = await collect(prox.flows(sha.hex(), keylogs=[missing]))
                assert retns[0]["mesg"] == \
                    f"The TLS key log file:bytes:sha256={missing} is not in the Axon."
                svc.conf["tshark:keylog:maxsize"] = 5
                retns = await collect(prox.flows(sha.hex(), keylogs=[keylog.hex()]))
                assert "larger than the max size of 5 bytes" in retns[0]["mesg"]

                async with svc.getLocalProxy() as sprox:
                    retn = await sprox.checkDecodeAs(["TCP.port==22,ssh"])
                    assert retn == {"status": True, "mesg": "", "data": ("tcp.port==22,ssh",)}
                    retn = await sprox.checkDecodeAs(["bad"])
                    assert not retn["status"] and "Invalid Decode As rule" in retn["mesg"]

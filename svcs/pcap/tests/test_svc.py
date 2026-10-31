"""Pytests for the slib.pcap service (PcapSvc) and its Telepath API."""


import gzip
import hashlib
import pathlib
import tomllib

import synapse.tests.utils as s_tests
import yaml

import pcapsvc
from pcapsvc import PcapSvc
from pcapsvc.defs import SVC_NAME

from . import pcapgen as g


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
            for mod in ("slib.pcap.lib", "slib.pcap.model", "slib.pcap.priv"):
                assert mod in core.stormmods
                self.stormHasNoErr(await core.stormlist(f"$mod = $lib.import({mod})"))

            # The add event creates the service's meta:source.
            self.len(1, await core.nodes("meta:source:name=slib.pcap"))

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
                assert "larger than the pcap:maxsize of 10 bytes" in retns[0]["mesg"]

                # Temp files are cleaned up.
                assert list(pathlib.Path(svc.tmpdir).iterdir()) == []

    async def test_axon_errors(self):
        async with self.getTestCoreProxSvc(PcapSvc) as (_, _, svc):
            prox = SvcProx(svc)
            sha = hashlib.sha256(b"x").hexdigest()
            retns = await collect(prox.flows(sha))
            assert not retns[0]["status"]
            assert retns[0]["mesg"] == "The slib.pcap service has no axon:url configured."

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

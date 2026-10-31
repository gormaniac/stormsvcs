"""Pytests for the slib.pcap Storm package (the command, modules, modeling, and perms)."""


import contextlib
import hashlib

import synapse.tests.utils as s_tests

from pcapsvc import PcapSvc
from pcapsvc.defs import SVC_GUID

from . import pcapgen as g


@contextlib.asynccontextmanager
async def pcapCore(test: s_tests.SynTest, *blobs: bytes):
    """A Cortex with the slib.pcap service and an Axon holding the given files.

    Yields (core, svc, sha256s) where sha256s are the hex SHA-256s of the files.
    """

    async with test.getTestAxon() as axon:
        shas = [(await axon.put(blob))[1].hex() for blob in blobs]
        conf = {"axon:url": axon.getLocalUrl()}
        async with test.getTestCoreProxSvc(PcapSvc, ssvc_conf=conf) as (core, _, svc):
            yield core, svc, shas


class TestPcapStorm(s_tests.SynTest):

    async def test_flows_cmd(self):
        async with pcapCore(self, g.pcap(g.session())) as (core, _, (sha,)):
            await core.nodes(f"[ file:bytes={sha} ]")

            msgs = await core.stormlist("file:bytes | slib.pcap.flows")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(
                f"slib.pcap: Modeled 4 flows from 16 packets in file:bytes=sha256:{sha}", msgs
            )
            # Without --yield the inbound nodes pass through.
            nodes = [m[1] for m in msgs if m[0] == "node"]
            assert [n[0][0] for n in nodes] == ["file:bytes"]

            flows = await core.nodes("inet:flow")
            self.len(4, flows)

            http = (await core.nodes("inet:flow:dst:port=80"))[0]
            assert http.get("time") == g.BASE * 1000
            assert http.get("duration") == 3
            assert http.get("ip:proto") == 6
            assert http.get("ip:tcp:flags") == 0x1B
            assert http.get("src") == "tcp://10.0.0.1:50000"
            assert http.get("src:ipv4") == 0x0A000001
            assert http.get("src:port") == 50000
            assert http.get("src:proto") == "tcp"
            assert http.get("src:txcount") == 5
            assert http.get("src:txbytes") == 255
            assert http.get("src:handshake").startswith("GET / HTTP/1.1")
            assert http.get("dst") == "tcp://93.184.216.34:80"
            assert http.get("dst:txcount") == 3
            assert http.get("dst:handshake").startswith("HTTP/1.1 200 OK")
            assert http.get("tot:txcount") == 8
            assert http.get("tot:txbytes") == 415
            assert http.get(".seen") == (g.BASE * 1000, g.BASE * 1000 + 3200)
            assert http.get("raw")["tcp:state"] == "closed"
            assert http.get("capture:host") is None

            ssh = (await core.nodes("inet:flow:dst:port=22"))[0]
            assert ssh.get("src:ipv6") == "2001:db8::1"
            assert ssh.get("dst") == "tcp://[2001:db8::2]:22"
            assert ssh.get("src:ipv4") is None
            assert ssh.get("dst:handshake") == "SSH-2.0-OpenSSH_9.6"
            assert ssh.get("src:handshake") is None

            ping = (await core.nodes("inet:flow:ip:proto=1"))[0]
            assert ping.get("src") == "icmp://10.0.0.1"
            assert ping.get("src:port") is None
            assert ping.get("ip:tcp:flags") is None

            # Every flow shares the PCAP's :from, refs edge, and the service's meta:source.
            self.len(1, {n.get("from") for n in flows})
            self.len(4, await core.nodes(f"file:bytes={sha} -(refs)> inet:flow"))
            self.len(4, await core.nodes(f"meta:source={SVC_GUID} -(seen)> inet:flow"))
            self.len(4, await core.nodes(f"inet:flow:from={flows[0].get('from')}"))
            # The endpoints are modeled too.
            self.len(1, await core.nodes("inet:server=tcp://93.184.216.34:80"))
            self.len(1, await core.nodes("inet:ipv4=8.8.8.8"))

            # Running again updates the same nodes.
            msgs = await core.stormlist("file:bytes | slib.pcap.flows --yield")
            self.stormHasNoWarnErr(msgs)
            nodes = [m[1] for m in msgs if m[0] == "node"]
            assert {n[0][0] for n in nodes} == {"inet:flow"}
            self.len(4, nodes)
            self.len(4, await core.nodes("inet:flow"))

    async def test_flows_cmd_sha256s(self):
        blobs = (g.pcap(g.session()), g.pcap(g.session(), nano=True, endian=">"))
        async with pcapCore(self, *blobs) as (core, _, shas):
            await core.nodes("[ it:host=* :name=sensor ]")
            host = (await core.nodes("it:host:name=sensor"))[0].ndef[1]

            msgs = await core.stormlist(
                # Quoted, the Storm parser splits unquoted values like sha256:6010E3... at the "E3".
                f"slib.pcap.flows {shas[0]} 'sha256:{shas[1].upper()}' --tag cno.case.x "
                f"--host '{host}' --timeout 0 --handshake 3"
            )
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(f"file:bytes=sha256:{shas[0]}", msgs)
            self.stormIsInPrint(f"file:bytes=sha256:{shas[1]}", msgs)
            # The SHA-256s are yielded, there are no inbound nodes to pass through.
            nodes = [m[1] for m in msgs if m[0] == "node"]
            assert {n[0][0] for n in nodes} == {"inet:flow"}
            self.len(8, nodes)

            # The file:bytes nodes are created.
            self.len(2, await core.nodes("file:bytes"))
            self.len(8, await core.nodes("inet:flow#cno.case.x"))
            self.len(8, await core.nodes(f"inet:flow:capture:host={host}"))
            self.len(4, await core.nodes(f"file:bytes={shas[1]} -(refs)> inet:flow"))
            nodes = await core.nodes("inet:flow:dst:port=80")
            assert {n.get("src:handshake") for n in nodes} == {"GET"}

            # --limit
            msgs = await core.stormlist(f"slib.pcap.flows {shas[0]} --limit 2")
            self.stormIsInPrint("Modeled 2 flows", msgs)
            self.stormIsInWarn(f"slib.pcap: {shas[0]} has more than 2 flows", msgs)

            # Debug prints the summary.
            msgs = await core.stormlist(f"slib.pcap.flows {shas[0]}", opts={"debug": True})
            self.stormIsInPrint(f"slib.pcap: {shas[0]} summary:", msgs)
            self.stormIsInPrint('"linktypes"', msgs)

    async def test_flows_cmd_problems(self):
        data = g.pcap(g.session())
        async with pcapCore(self, data[:-5], b"not a pcap") as (core, _, (cut, bad)):
            missing = hashlib.sha256(b"missing").hexdigest()

            msgs = await core.stormlist(f"slib.pcap.flows {cut}")
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("Modeled 4 flows from 15 packets", msgs)
            self.stormIsInWarn(f"slib.pcap: {cut} is truncated, read up to the error", msgs)

            for sha, err in ((bad, "The file is not a pcap or pcapng file"),
                             (missing, "is not in the Axon"),
                             ("nope", "Invalid SHA-256: nope")):
                msgs = await core.stormlist(f"slib.pcap.flows {sha}")
                self.stormHasNoErr(msgs)
                self.stormIsInWarn(f"slib.pcap: Unable to analyze {sha}", msgs)
                self.stormIsInWarn(err, msgs)

            # Bad PCAPs don't create file:bytes nodes.
            self.len(1, await core.nodes("file:bytes"))
            self.len(4, await core.nodes("inet:flow"))

            # Unsupported inbound nodes warn and are dropped.
            await core.nodes("[ inet:fqdn=vertex.link file:bytes=* ]")
            msgs = await core.stormlist("inet:fqdn file:bytes:sha256=* | slib.pcap.flows")
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("Unable to analyze inet:fqdn vertex.link", msgs)
            self.stormNotInWarn(f"file:bytes=sha256:{cut}", msgs)

            msgs = await core.stormlist("file:bytes -:sha256 | slib.pcap.flows --yield")
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("it needs to be a file:bytes with a :sha256", msgs)
            self.len(0, [m for m in msgs if m[0] == "node"])

    async def test_lib(self):
        async with pcapCore(self, g.pcap(g.session()), b"nope") as (core, _, (sha, bad)):
            q = "$pcap = $lib.import(slib.pcap.lib) for $n in $pcap.flows($sha) { yield $n }"
            nodes = await core.nodes(q, opts={"vars": {"sha": sha}})
            self.len(4, nodes)
            assert {n.form.name for n in nodes} == {"inet:flow"}

            q = """
                $pcap = $lib.import(slib.pcap.lib)
                $opts = ({"tag": "lib.test"})
                file:bytes
                for $n in $pcap.flows(:sha256, timeout=(0), limit=(1), handshake=(0), file=$node,
                                      opts=$opts) {
                    yield $n
                }
                +inet:flow
            """
            nodes = await core.nodes(q)
            self.len(1, nodes)
            assert nodes[0].get("#lib.test") is not None

            # Module functions raise for application friendly error handling.
            q = "$pcap = $lib.import(slib.pcap.lib) for $n in $pcap.flows($sha) { }"
            with self.raises(Exception) as exc:
                await core.callStorm(q, opts={"vars": {"sha": bad}})
            assert "slib.pcap.Error" in str(exc.exception)
            assert "not a pcap" in str(exc.exception)
            with self.raises(Exception) as exc:
                await core.callStorm(q, opts={"vars": {"sha": "nope"}})
            assert "slib.pcap.Error" in str(exc.exception)
            self.len(1, await core.nodes("file:bytes"))

    async def test_perms(self):
        async with pcapCore(self, g.pcap(g.session())) as (core, _, (sha,)):
            user = await core.auth.addUser("analyst")
            opts = {"user": user.iden}

            msgs = await core.stormlist(f"slib.pcap.flows {sha}", opts=opts)
            self.stormIsInErr("slib.pcap.user", msgs)

            # The user perm lets them use the service, node edits still need their own perms.
            await user.allow(("slib", "pcap", "user"))
            msgs = await core.stormlist(f"slib.pcap.flows {sha}", opts=opts)
            self.stormIsInErr("must have permission node.add", msgs)
            self.len(0, await core.nodes("inet:flow"))

            await user.allow(("node",))
            msgs = await core.stormlist(f"slib.pcap.flows {sha} --yield", opts=opts)
            self.stormHasNoWarnErr(msgs)
            self.len(4, await core.nodes("inet:flow"))

"""The recorded corner case captures in tests/data, through each engine.

- The flow table on its own: midstream TCP, a reused 5-tuple, ICMP unreachable, the same
  5-tuple on two VLANs, and a gzipped pcapng with two link types.
- tshark alone, and Suricata with tshark: the same details come out either way (parity),
  except for the gaps tshark covers for Suricata.
- Invariants between the engines: Suricata's packet counts and Snort's packet numbers are
  frame numbers, Suricata's Community IDs are the flows', and analysis is deterministic.
"""

import hashlib
import io
import json
import os
import pathlib
import tempfile

import pytest
import synapse.tests.utils as s_tests

from pcapsvc import PcapSvc
from pcapsvc import flows as p_flows
from pcapsvc import sandbox as p_sandbox
from pcapsvc import snort as p_snort
from pcapsvc import suricata as p_suricata

from .engines import needs

DATA = pathlib.Path(__file__).parent / "data"
DOWNLOAD = hashlib.sha256(bytes(range(256)) * 64).hexdigest()

# Each fixture and the Decode As rules it needs (SSH and FTP on unusual ports).
FIXTURES = {
    "http.pcapng": [],
    "tls.pcapng": [],
    "ssh.pcapng": [],
    "ssh_pq.pcapng": ["tcp.port==2200,ssh"],
    "ftp.pcapng": [],
    "ftp_active.pcapng": ["tcp.port==2121,ftp"],
    "smtp.pcapng": [],
    "rdp.pcapng": [],
    "sip.pcapng": [],
    "corner.pcapng": [],
    "vlan.pcap": [],
    "multi.pcapng.gz": [],
}


def analyze(name: str) -> tuple[list[dict], dict]:
    with open(DATA / name, "rb") as fd:
        return p_flows.analyze(fd)


def byPort(flows: list[dict]) -> dict:
    return {(f["src"]["port"], f["dst"]["port"], tuple(f["vlans"])): f for f in flows}


class TestFixtureFlows:
    """What the flow table makes of the corner cases, no engines needed."""

    def test_corner(self):
        flows, summary = analyze("corner.pcapng")
        assert summary["flows"] == 5
        tcp = sorted((f for f in flows if f["ipproto"] == 6), key=lambda f: f["time"])
        # Joined midstream: no SYN, the side that sent first is the client.
        mid = tcp[0]
        assert (mid["src"]["port"], mid["dst"]["port"]) == (40100, 8080)
        assert mid["tcp:syn"] is False and mid["tcp:state"] == "closed"
        assert mid["src"]["handshake"].startswith("GET /midstream")
        # The same client port twice is two flows, with the same Community ID.
        first, second = tcp[1:]
        assert first["src"]["port"] == second["src"]["port"] == 40200
        assert first["iden"] != second["iden"]
        assert first["community_id"] == second["community_id"]
        assert first["tcp:state"] == second["tcp:state"] == "reset"
        assert first["src"]["handshake"].startswith("GET /first")
        assert second["src"]["handshake"].startswith("GET /second")
        # The UDP datagram and the ICMP port unreachable it got back.
        udp = [f for f in flows if f["ipproto"] == 17][0]
        assert udp["dst"]["port"] == 9 and udp["src"]["handshake"] == "anyone there?"
        icmp = [f for f in flows if f["ipproto"] == 1][0]
        assert icmp["icmp:types"] == [3]

    def test_vlan(self):
        flows, summary = analyze("vlan.pcap")
        assert summary["flows"] == 4
        assert sorted(tuple(f["vlans"]) for f in flows) == [(10,), (10,), (20,), (20,)]
        # Same 5-tuples, different VLANs: different flows (and idens), same Community IDs.
        ports = byPort(flows)
        a, b = ports[(42288, 80, (10,))], ports[(42288, 80, (20,))]
        assert a["iden"] != b["iden"] and a["community_id"] == b["community_id"]
        assert len({f["iden"] for f in flows}) == 4

    def test_multi(self):
        flows, summary = analyze("multi.pcapng.gz")
        assert summary["compressed"] and summary["format"] == "pcapng"
        assert [lt["type"] for lt in summary["linktypes"]] == [1, 113]
        assert summary["flows"] == 2 and summary["skipped"] == {}
        assert {f["dst"]["port"] for f in flows} == {8081}

    def test_split_linktypes(self, tmp_path):
        parts = p_flows.splitLinktypes(str(DATA / "multi.pcapng.gz"), str(tmp_path))
        assert [os.path.basename(p) for p, _ in parts] == [
            "linktype-1.pcap",
            "linktype-113.pcap",
        ]
        # Every frame is in exactly one part, in order.
        nums = [n for _, ns in parts for n in ns]
        assert sorted(nums) == list(range(1, 25))
        assert all(ns == sorted(ns) for _, ns in parts)
        # Each part is a pcap the flow table (and libpcap) reads, with its frames' packets.
        for path, ns in parts:
            with open(path, "rb") as fd:
                flows, summary = p_flows.analyze(fd)
            assert summary["format"] == "pcap" and summary["packets"] == len(ns)
            assert len(flows) == 1
        assert p_flows.splitLinktypes(str(DATA / "http.pcapng"), str(tmp_path)) is None
        assert p_flows.splitLinktypes(str(DATA / "capture.py"), str(tmp_path)) is None

    def test_deterministic(self):
        # The same capture gives byte identical flows and summaries.
        for name in FIXTURES:
            one = json.dumps(analyze(name), sort_keys=True)
            two = json.dumps(analyze(name), sort_keys=True)
            assert one == two, name


def details(flows: list[dict]) -> dict:
    """The application layer details of each flow (by its iden) that both tshark and
    Suricata find, to compare them."""

    out = {}
    for flow in flows:
        out[flow["iden"]] = {
            side: {
                "softnames": sorted(flow[side]["softnames"]),
                "files": sorted(f["sha256"] for f in flow[side]["txfiles"]),
                "certs": sorted(c["sha256"] for c in flow[side]["ssl:certs"] or ()),
                "sshkey": (flow[side]["ssh:key"] or {}).get("sha256"),
                "rdp": flow[side]["rdp:hostname"],
            }
            for side in ("src", "dst")
        }
    return out


async def run(test, name: str, **opts) -> tuple[list[dict], dict]:
    async with test.getTestAxon() as axon:
        _, sha = await axon.put((DATA / name).read_bytes())
        conf = {"axon:url": axon.getLocalUrl()}
        async with test.getTestCell(PcapSvc, conf=conf) as svc:
            return await svc.analyze(sha.hex(), decode=FIXTURES[name], **opts)


@needs("tshark")
class TestFixtureTshark(s_tests.SynTest):
    """tshark alone (and dpkt), the service without Suricata."""

    async def test_protocols(self):
        flows, _ = await run(self, "sip.pcapng", suricata=False)
        sip = flows[0]
        assert sip["src"]["softnames"] == ["linphone/5.2.5 (belle-sip/5.2.0)"]
        assert sip["dst"]["softnames"] == ["asterisk pbx 20.5.0"]

        flows, _ = await run(self, "ssh_pq.pcapng", suricata=False)
        key = flows[0]["dst"]["ssh:key"]
        assert key["algo"] == "ssh-rsa"
        assert flows[0]["dst"]["softnames"] == ["openssh_9.6p1 ubuntu-3ubuntu13.20"]

        # Active FTP: the server opens the data connection, so it's that flow's client.
        # tshark only follows it when the server connects from port 20 (this one didn't),
        # Suricata does (see TestFixtureServices).
        flows, summary = await run(self, "ftp_active.pcapng", suricata=False)
        data = [f for f in flows if f["dst"]["port"] != 2121][0]
        assert data["src"]["port"] != 2121 and data["dst"]["port"] > 1024
        assert data["src"]["txfiles"] == []

        flows, _ = await run(self, "multi.pcapng.gz", suricata=False)
        assert sorted(f["dst"]["txfiles"][0]["name"] for f in flows) == ["any.bin", "lo.bin"]


# What tshark finds that Suricata doesn't (and the service runs tshark for, see
# tshark.GAP_PREFIXES), checked separately.
GAPS = {"sshkey"}


@needs("tshark", "suricata")
class TestFixtureParity(s_tests.SynTest):
    """Suricata (with tshark for the gaps) finds at least what tshark alone does."""

    async def test_parity(self):
        for name in FIXTURES:
            alone, _ = await run(self, name, suricata=False)
            both, summary = await run(self, name)
            assert summary["engines"]["suricata"]["error"] is None, name
            assert summary["engines"]["tshark"]["gaps"], name
            # The flows are the same whatever engines ran.
            assert [f["iden"] for f in alone] == [f["iden"] for f in both], name
            want, got = details(alone), details(both)
            for iden, sides in want.items():
                for side, items in sides.items():
                    for key, valu in items.items():
                        have = got[iden][side][key]
                        if isinstance(valu, list):
                            missing = set(valu) - set(have)
                            assert not missing, (name, iden, side, key, missing)
                        elif valu is not None:
                            assert have == valu, (name, iden, side, key, have, valu)


@needs("tshark", "suricata", "snort")
class TestCrossEngine(s_tests.SynTest):
    """The engines agree on what a packet is."""

    async def test_suricata_frames(self):
        # Every Suricata event with a packet count is on a packet of a flow with its
        # Community ID: pcap_cnt is the frame number, and Community IDs agree (ICMP too).
        sbx = p_sandbox.Sandbox()
        for name in ("http.pcapng", "tls.pcapng", "corner.pcapng", "vlan.pcap", "sip.pcapng"):
            flows, _ = analyze(name)
            byframe = {}
            with open(DATA / name, "rb") as fd:
                table = p_flows.FlowTable()
                for pkt in p_flows.readPackets(fd):
                    flow = table.add(pkt, None)
                    if flow is not None:
                        byframe[pkt.num] = flow.communityId()
            with tempfile.TemporaryDirectory() as tmp:
                os.chmod(tmp, 0o755)
                suri = p_suricata.Suricata(os.path.join(tmp, "work"), sandbox=sbx)
                out = os.path.join(tmp, "out")
                os.makedirs(out)
                sbx.prepare(tmp)
                res = await suri.run(str(DATA / name), out)
                events = list(p_suricata.iterEve(res["eve"]))
            checked = 0
            for ev in events:
                num, cid = ev.get("pcap_cnt"), ev.get("community_id")
                if not num or not cid or ev.get("event_type") not in (
                    "http", "tls", "sip", "fileinfo", "alert", "anomaly"
                ):
                    continue
                assert byframe.get(num) == cid, (name, ev)
                checked += 1
            assert checked, name
            # Every Community ID Suricata saw is a flow's, including the ICMP flow's.
            assert {e["community_id"] for e in events if e.get("community_id")} <= {
                f["community_id"] for f in flows
            }, name

    async def test_snort_frames(self):
        # Snort's pkt_num is the frame number: the alerted packet is the one with that number.
        with self.getTestDir() as dirn:
            snort = p_snort.Snort(dirn)
            rules = {
                "get": 'alert http any any -> any any ( msg:"get"; http_method; content:"GET"; sid:1; )',
                "icmp": 'alert icmp any any -> any any ( msg:"unreach"; itype:3; sid:2; )',
            }
            path = os.path.join(dirn, "frames.rules")
            assert sorted((await snort.validate(rules, path))[0]) == ["get", "icmp"]
            for name in ("http.pcapng", "corner.pcapng", "vlan.pcap"):
                capture = os.path.join(dirn, "capture.pcap")
                with open(DATA / name, "rb") as ifd, open(capture, "wb") as ofd:
                    ofd.write(ifd.read())
                frames = {}
                with open(capture, "rb") as fd:
                    for pkt in p_flows.readPackets(fd):
                        frames[pkt.num] = pkt
                alerts = []
                await snort.scan(path, capture, alerts.append)
                assert alerts, name
                for alert in alerts:
                    pkt = frames[int(alert["pkt_num"])]
                    ipkt, _ = p_flows.decodePacket(pkt.linktype, pkt.data)
                    assert ipkt is not None, (name, alert)
                    if alert["sid"] == 2:
                        assert ipkt.data.type == 3
                    else:
                        # Stream alerts can be on the packet that flushed the reassembled
                        # data (ex. the server's ACK), always one of the flow's.
                        assert {alert["src_port"], alert["dst_port"]} == {
                            ipkt.data.sport,
                            ipkt.data.dport,
                        }, (name, alert)


@needs("tshark", "suricata")
class TestFixtureServices(s_tests.SynTest):
    """The corner cases through every engine the service runs."""

    async def test_corner(self):
        flows, summary = await run(self, "corner.pcapng", files=True)
        assert summary["events"]["unmatched"] == 0
        assert summary["files"]["skipped"] == 0
        tcp = sorted((f for f in flows if f["ipproto"] == 6), key=lambda f: f["time"])
        # Suricata's details of the reused 5-tuple go to the right connection.
        assert tcp[1]["app_proto"] == ["http"]
        assert tcp[2]["app_proto"] == ["http"]
        assert [f["name"] for f in tcp[2]["dst"]["txfiles"]] == ["second"]
        assert not tcp[1]["dst"]["txfiles"]
        # The capture ended before the response finished, it's incomplete.
        assert tcp[2]["dst"]["txfiles"][0]["complete"] is False

    async def test_vlan(self):
        flows, summary = await run(self, "vlan.pcap")
        assert summary["events"]["unmatched"] == 0
        for flow in flows:
            # Every flow got its own Suricata details, not its twin on the other VLAN's.
            assert flow["app_proto"] == ["http"], flow["vlans"]
            assert flow["src"]["softnames"] == ["curl/8.5.0"]
        downloads = [f for f in flows if f["dst"]["txfiles"] and f["src"]["port"] == 42288]
        assert len(downloads) == 2

    async def test_ftp_active(self):
        flows, _ = await run(self, "ftp_active.pcapng")
        data = [f for f in flows if f["dst"]["port"] != 2121][0]
        assert [(f["sha256"], f["name"]) for f in data["src"]["txfiles"]] == [
            (DOWNLOAD, "sample.bin")
        ]

    async def test_multi(self):
        # Suricata (via libpcap) can't read a pcapng with two link types, so it runs on each.
        flows, summary = await run(self, "multi.pcapng.gz")
        assert summary["engines"]["suricata"]["error"] is None
        assert all(f["app_proto"] == ["http"] for f in flows)
        assert sorted(f["dst"]["txfiles"][0]["name"] for f in flows) == ["any.bin", "lo.bin"]


def test_pcapgen_vlan_split():
    # A capture with one link type and VLANs isn't split.
    from . import pcapgen as g

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "x.pcap")
        with open(path, "wb") as fd:
            fd.write(g.pcap(g.session()))
        assert p_flows.splitLinktypes(path, tmp) is None
        with open(path, "rb") as fd:
            assert p_flows.analyze(io.BytesIO(fd.read()))[1]["flows"] == 4


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_fixture_reads(name):
    flows, summary = analyze(name)
    assert flows and not summary["truncated"] and summary["error"] is None

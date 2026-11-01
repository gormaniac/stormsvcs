"""Pytests for pcapsvc.flows, the capture file readers and flow aggregation."""


import gzip
import io
import struct

import dpkt
import pytest

from pcapsvc import flows as p_flows

from . import pcapgen as g
from .pcapgen import ACK, FIN, PSH, RST, SYN


def analyze(data: bytes, **kwargs):
    return p_flows.analyze(io.BytesIO(data), **kwargs)


def byPort(flows: list[dict], port: int) -> list[dict]:
    return [f for f in flows if port in (f["src"]["port"], f["dst"]["port"])]


class TestReaders:

    def test_pcap_session(self):
        flows, summary = analyze(g.pcap(g.session()), seed="x")

        assert summary["format"] == "pcap"
        assert not summary["compressed"]
        assert summary["linktypes"] == [{"type": 1, "name": "ethernet"}]
        assert summary["packets"] == 16
        assert summary["decoded"] == 15
        assert summary["skipped"] == {"nonip": 1}
        assert summary["flows"] == 4
        assert summary["first"] == g.BASE * 1000
        assert summary["last"] == g.BASE * 1000 + 3200
        assert not summary["truncated"] and summary["error"] is None
        assert not summary["limited"] and summary["dropped"] == 0

        # Ordered by start time.
        assert [f["proto"] for f in flows] == ["tcp", "udp", "icmp", "tcp"]
        assert [f["index"] for f in flows] == [0, 1, 2, 3]

        http = flows[0]
        assert http["version"] == 4 and http["ipproto"] == 6
        assert http["src"]["ip"] == "10.0.0.1" and http["src"]["port"] == 50000
        assert http["src"]["addr"] == "tcp://10.0.0.1:50000"
        assert http["dst"]["addr"] == "tcp://93.184.216.34:80"
        assert http["src"]["pkts"] == 5 and http["dst"]["pkts"] == 3
        assert http["src"]["bytes"] == 40 * 4 + 40 + len(g.HTTP_REQ)
        assert http["dst"]["bytes"] == 40 * 2 + 40 + len(g.HTTP_RESP)
        assert http["pkts"] == 8
        assert http["bytes"] == http["src"]["bytes"] + http["dst"]["bytes"]
        assert http["src"]["payload"] == len(g.HTTP_REQ)
        assert http["src"]["handshake"].startswith("GET / HTTP/1.1\r\nHost: vertex.link")
        assert http["dst"]["handshake"].startswith("HTTP/1.1 200 OK")
        assert http["time"] == g.BASE * 1000
        assert http["last"] == g.BASE * 1000 + 3200
        assert http["duration"] == 3 and http["durationms"] == 3200
        assert http["tcp:flags"] == FIN | SYN | PSH | ACK
        assert http["tcp:flagnames"] == ["fin", "syn", "psh", "ack"]
        assert http["tcp:state"] == "closed"
        assert http["tcp:syn"] is True
        assert http["icmp:types"] is None

        dns = flows[1]
        assert dns["src"]["port"] == 53000 and dns["dst"]["ip"] == "8.8.8.8"
        assert dns["src"]["handshake"] is None  # Binary payloads aren't handshakes.
        assert dns["tcp:flags"] is None and dns["tcp:state"] is None

        ping = flows[2]
        assert ping["src"]["addr"] == "icmp://10.0.0.1" and ping["src"]["port"] is None
        assert ping["icmp:types"] == [0, 8]

        ssh = flows[3]
        assert ssh["version"] == 6
        assert ssh["src"]["addr"] == "tcp://[2001:db8::1]:40000"
        assert ssh["dst"]["handshake"] == "SSH-2.0-OpenSSH_9.6"
        assert ssh["dst"]["bytes"] == 40 + 20 + 21
        assert ssh["tcp:state"] == "reset"

        # Idens are stable for the same capture, and differ between captures.
        again, _ = analyze(g.pcap(g.session()), seed="x")
        assert [f["iden"] for f in again] == [f["iden"] for f in flows]
        other, _ = analyze(g.pcap(g.session()), seed="y")
        assert not {f["iden"] for f in other} & {f["iden"] for f in flows}
        assert all(len(f["iden"]) == 32 for f in flows)

    def test_pcap_variants(self):
        base, _ = analyze(g.pcap(g.session()))
        for data in (
            g.pcap(g.session(), endian=">"),
            g.pcap(g.session(), nano=True),
            g.pcap(g.session(), nano=True, endian=">"),
            gzip.compress(g.pcap(g.session())),
        ):
            flows, summary = analyze(data)
            assert summary["packets"] == 16
            assert [(f["time"], f["last"], f["bytes"]) for f in flows] == \
                [(f["time"], f["last"], f["bytes"]) for f in base]

        _, summary = analyze(gzip.compress(g.pcap(g.session())))
        assert summary["compressed"]

    def test_pcap_nanoseconds(self):
        frame = g.eth(g.udp("10.0.0.1", 5000, "10.0.0.2", 6000))
        flows, _ = analyze(g.pcap([(0.000001, frame), (0.123456789, frame)], nano=True))
        assert flows[0]["time"] == g.BASE * 1000
        assert flows[0]["last"] == g.BASE * 1000 + 123

    def test_pcap_linktype_fcs_bits(self):
        # The upper bits of the link type field are FCS info, not part of the link type.
        frame = g.eth(g.udp("10.0.0.1", 5000, "10.0.0.2", 6000))
        flows, summary = analyze(g.pcap([(0, frame)], linktype=0x10000001))
        assert summary["linktypes"] == [{"type": 1, "name": "ethernet"}]
        assert len(flows) == 1

    def test_pcapng(self):
        ip = g.udp("10.0.0.1", 5000, "10.0.0.2", 6000)
        frame = g.eth(ip)
        data = b"".join((
            g.shb(),
            g.idb(1),  # Ethernet, microseconds.
            g.idb(101, tsresol=9),  # Raw IP, nanoseconds.
            g.idb(1, tsresol=0x80 | 10, tsoffset=10),  # Ethernet, 2^-10 seconds, +10 seconds.
            g.other(),
            g.epb(0, g.usec(0), frame),
            g.epb(1, (g.BASE + 1) * 1_000_000_000 + 500_000_000, bytes(ip)),
            g.epb(2, g.BASE * 1024 + 512, frame),
            g.pb(0, g.usec(3), frame),
            g.spb(frame),
            g.epb(9, g.usec(4), frame),  # No such interface.
        ))
        flows, summary = analyze(data, timeout=0)
        assert summary["format"] == "pcapng"
        assert summary["linktypes"] == [
            {"type": 1, "name": "ethernet"}, {"type": 101, "name": "raw"},
        ]
        assert summary["packets"] == 5
        assert summary["skipped"] == {"badiface": 1}
        assert len(flows) == 1
        assert flows[0]["pkts"] == 5
        assert flows[0]["time"] == g.BASE * 1000
        # The 2^-10 interface is at BASE + 0.5 + its 10 second offset.
        assert flows[0]["last"] == (g.BASE + 10) * 1000 + 500

    def test_pcapng_sections(self):
        # A new section resets the interfaces, and can change the byte order.
        frame = g.eth(g.udp("10.0.0.1", 5000, "10.0.0.2", 6000))
        data = b"".join((
            g.shb(), g.idb(1), g.epb(0, g.usec(0), frame),
            g.shb(">"), g.idb(101, endian=">"),
            g.epb(0, g.usec(1), bytes(g.udp("10.0.0.3", 1, "10.0.0.4", 2)), endian=">"),
        ))
        flows, summary = analyze(data)
        assert summary["packets"] == 2
        assert len(flows) == 2
        assert {f["src"]["ip"] for f in flows} == {"10.0.0.1", "10.0.0.3"}

        # A simple packet block before any interface can't be read.
        _, summary = analyze(g.shb() + g.spb(frame))
        assert summary["packets"] == 0
        assert summary["skipped"] == {"badiface": 1}

    def test_not_a_capture(self):
        for data in (b"", b"nope", b"hello world, not a pcap", gzip.compress(b"not a pcap")):
            with pytest.raises(p_flows.PcapError) as exc:
                analyze(data)
            assert exc.value.mesg == "The file is not a pcap or pcapng file"

        with pytest.raises(p_flows.PcapError, match="compressed more than once"):
            analyze(gzip.compress(gzip.compress(g.pcap(g.session()))))

        bad = bytearray(g.shb())
        bad[8:12] = b"\x00\x00\x00\x00"
        with pytest.raises(p_flows.PcapError, match="byte order magic"):
            analyze(bytes(bad))

    def test_truncated(self):
        data = g.pcap(g.session())
        for cut in (10, 30, len(data) - 5, len(data) - 30):
            flows, summary = analyze(data[:cut])
            assert summary["truncated"]
            assert summary["error"]

        # Everything before the cut is kept.
        flows, summary = analyze(data[:len(data) - 5])
        assert summary["packets"] == 15
        assert len(flows) == 4

        # A record claiming a huge packet is corruption.
        bad = g.pcap([]) + struct.pack("<IIII", 0, 0, 0x7FFFFFFF, 0x7FFFFFFF)
        _, summary = analyze(bad)
        assert summary["truncated"] and "claims" in summary["error"]

        # A truncated gzip stream.
        flows, summary = analyze(gzip.compress(data)[:-20])
        assert summary["compressed"] and summary["truncated"]

        frame = g.eth(g.udp("10.0.0.1", 5000, "10.0.0.2", 6000))
        ng = g.shb() + g.idb(1) + g.epb(0, g.usec(0), frame)
        for cut in (6, 10, 20, len(ng) - 4, len(ng) - 40):
            _, summary = analyze(ng[:cut])
            assert summary["truncated"], cut

        # Invalid block lengths.
        badlen = g.shb() + struct.pack("<II", 1, 13)
        _, summary = analyze(badlen)
        assert summary["truncated"] and "block length" in summary["error"]
        badshb = struct.pack("<III", 0x0A0D0D0A, 8, 0x1A2B3C4D)
        _, summary = analyze(badshb)
        assert summary["truncated"] and "section header length" in summary["error"]


class TestDecode:

    def test_linktypes(self):
        ip4 = bytes(g.udp("10.0.0.1", 5000, "10.0.0.2", 6000))
        ip6 = bytes(g.udp("2001:db8::1", 5000, "2001:db8::2", 6000))
        sll = dpkt.sll.SLL(ethtype=dpkt.ethernet.ETH_TYPE_IP, data=g.udp("10.0.0.1", 5000, "10.0.0.2", 6000))
        sll2 = dpkt.sll2.SLL2(ethtype=dpkt.ethernet.ETH_TYPE_IP6,
                              data=g.udp("2001:db8::1", 5000, "2001:db8::2", 6000))
        ppp = dpkt.ppp.PPP(p=dpkt.ppp.PPP_IP, data=g.udp("10.0.0.1", 5000, "10.0.0.2", 6000))
        vlan = dpkt.ethernet.Ethernet(src=g.MAC_A, dst=g.MAC_B,
                                      vlan_tags=[dpkt.ethernet.VLANtag8021Q(id=7)],
                                      type=dpkt.ethernet.ETH_TYPE_IP,
                                      data=g.udp("10.0.0.1", 5000, "10.0.0.2", 6000))
        qinq = dpkt.ethernet.Ethernet(src=g.MAC_A, dst=g.MAC_B,
                                      vlan_tags=[dpkt.ethernet.VLANtag8021Q(id=7, type=0x8100),
                                                 dpkt.ethernet.VLANtag8021Q(id=8)],
                                      type=dpkt.ethernet.ETH_TYPE_IP6,
                                      data=g.udp("2001:db8::1", 5000, "2001:db8::2", 6000))
        pppoeppp = dpkt.pppoe.PPP(p=dpkt.ppp.PPP_IP,
                                  data=g.udp("10.0.0.1", 5000, "10.0.0.2", 6000))
        pppoe = dpkt.pppoe.PPPoE(code=0, session=1, data=pppoeppp)
        pppoe.len = len(bytes(pppoeppp))
        pppoe = dpkt.ethernet.Ethernet(src=g.MAC_A, dst=g.MAC_B,
                                       type=dpkt.ethernet.ETH_TYPE_PPPoE, data=pppoe)

        cases = (
            (1, bytes(qinq), 6),
            (1, bytes(pppoe), 4),
            (0, b"\x02\x00\x00\x00" + ip4, 4),
            (108, b"\x00\x00\x00\x18" + ip6, 6),
            (101, ip4, 4),
            (12, ip6, 6),
            (14, ip4, 4),
            (228, ip4, 4),
            (229, ip6, 6),
            (113, bytes(sll), 4),
            (276, bytes(sll2), 6),
            (9, bytes(ppp), 4),
            (1, bytes(vlan), 4),
        )
        for linktype, frame, vers in cases:
            flows, summary = analyze(g.pcap([(0, frame)], linktype=linktype))
            assert summary["skipped"] == {}, linktype
            assert len(flows) == 1, linktype
            assert flows[0]["version"] == vers, linktype
            assert flows[0]["src"]["port"] == 5000, linktype

    def test_skipped(self):
        ip4 = bytes(g.udp("10.0.0.1", 5000, "10.0.0.2", 6000))
        pkts = [
            (0, b"\x00" * 30),  # Unsupported link type (802.11).
        ]
        _, summary = analyze(g.pcap(pkts, linktype=105))
        assert summary["skipped"] == {"linktype": 1}
        assert summary["linktypes"] == [{"type": 105, "name": None}]

        # Raw IP that isn't IPv4 or IPv6, and empty packets.
        _, summary = analyze(g.pcap([(0, b"\x50" + ip4[1:]), (0, b"")], linktype=101))
        assert summary["skipped"] == {"nonip": 2}

        # Malformed headers.
        _, summary = analyze(g.pcap([(0, ip4[:10]), (0, b"\x43" + ip4[1:])], linktype=101))
        assert summary["skipped"] == {"malformed": 2}

        # The capture cut off the transport header.
        tcp = bytearray(bytes(g.tcp("10.0.0.1", 1, "10.0.0.2", 2, SYN)))
        _, summary = analyze(g.pcap([(0, bytes(tcp[:26]))], linktype=101))
        assert summary["skipped"] == {"truncated": 1}
        assert summary["decoded"] == 0

    def test_fragments(self):
        first = g.udp("10.0.0.1", 5000, "10.0.0.2", 6000, b"A" * 32)
        first.mf = 1
        later = dpkt.ip.IP(src=first.src, dst=first.dst, p=17, ttl=64, data=b"B" * 16)
        later.offset = 40
        later.len = 36

        frag6 = dpkt.ip6.IP6FragmentHeader(nxt=17, frag_off=5)
        ip6 = dpkt.ip6.IP6(src=b"\x20\x01" + b"\x00" * 13 + b"\x01",
                           dst=b"\x20\x01" + b"\x00" * 13 + b"\x02",
                           nxt=44, hlim=64, data=bytes(frag6) + b"C" * 16)
        ip6.plen = len(ip6.data)

        flows, summary = analyze(g.pcap([(0, bytes(first)), (0.1, bytes(later)),
                                         (0.2, bytes(ip6))], linktype=101))
        assert summary["skipped"] == {"fragment": 2}
        assert len(flows) == 1
        assert flows[0]["src"]["bytes"] == 20 + 8 + 32

    def test_other_protos(self):
        gre = g.ipPkt("10.0.0.1", "10.0.0.2", b"\x00" * 4, 47)
        esp = g.ipPkt("10.0.0.1", "10.0.0.2", b"\x00" * 16, 50)
        unknown = g.ipPkt("10.0.0.1", "10.0.0.2", b"\x00" * 4, 253)
        bareicmp = g.ipPkt("10.0.0.1", "10.0.0.2", b"", 1)
        flows, _ = analyze(g.pcap([(0, bytes(gre)), (1, bytes(esp)), (2, bytes(unknown)),
                                   (3, bytes(bareicmp))], linktype=101))
        assert [f["proto"] for f in flows] == ["gre", "esp", None, "icmp"]
        assert flows[0]["src"]["addr"] == "gre://10.0.0.1"
        assert flows[1]["src"]["addr"] is None
        assert flows[2]["src"]["addr"] is None and flows[2]["ipproto"] == 253
        assert flows[3]["icmp:types"] == []

    def test_tso_lengths(self):
        # IP length fields of 0 (TCP segmentation offload) use the captured length.
        ip4 = g.udp("10.0.0.1", 5000, "10.0.0.2", 6000, b"x" * 10)
        ip4.len = 0
        ip6 = g.udp("2001:db8::1", 5000, "2001:db8::2", 6000, b"x" * 10)
        ip6.plen = 0
        flows, _ = analyze(g.pcap([(0, bytes(ip4)), (1, bytes(ip6))], linktype=101))
        assert flows[0]["bytes"] == 20 + 8 + 10
        assert flows[1]["bytes"] == 40 + 8 + 10


class TestFlowTable:

    def test_direction(self):
        c, s = "10.0.0.1", "10.0.0.2"
        pkts = [
            # A SYN-ACK first, the server sent it.
            (0, g.tcp(s, 443, c, 50001, SYN | ACK)),
            # Mid connection, the lower privileged port is the server.
            (1, g.tcp(s, 443, c, 50002, ACK)),
            (2, g.tcp(c, 50003, s, 22, ACK)),
            # Mid connection with no privileged port, the first sender is the client.
            (3, g.tcp(s, 8080, c, 50004, ACK)),
            # UDP from a privileged port to an unprivileged one is from the server.
            (4, g.udp(s, 53, c, 50005)),
            (5, g.udp(c, 50006, s, 53)),
            (6, g.udp(s, 53, c, 53)),
            # An ICMP reply first is from the server, an unknown type keeps the first sender.
            (7, g.icmp(s, c, 0)),
            (8, g.icmp("2001:db8::2", "2001:db8::1", 129)),
            (9, g.icmp(c, "10.0.0.9", 3)),
            # ICMP flows are by address, so this request is part of the earlier reply's flow.
            (10, g.icmp("2001:db8::1", "2001:db8::2", 128)),
        ]
        flows, _ = analyze(g.pcap([(t, bytes(p)) for t, p in pkts], linktype=101))
        srcs = [(f["src"]["ip"], f["src"]["port"]) for f in flows]
        assert srcs == [
            (c, 50001), (c, 50002), (c, 50003), (s, 8080), (c, 50005), (c, 50006), (s, 53),
            (c, None), ("2001:db8::1", None), (c, None),
        ]
        assert flows[8]["icmp:types"] == [128, 129]
        assert flows[0]["tcp:syn"] is True
        assert flows[1]["tcp:syn"] is False

    def test_timeout(self):
        frame = bytes(g.udp("10.0.0.1", 5000, "10.0.0.2", 6000))
        pkts = [(0, frame), (100, frame), (500, frame), (501, frame)]
        flows, _ = analyze(g.pcap(pkts, linktype=101), timeout=300)
        assert [f["pkts"] for f in flows] == [2, 2]
        assert flows[1]["time"] == (g.BASE + 500) * 1000

        flows, _ = analyze(g.pcap(pkts, linktype=101), timeout=0)
        assert [f["pkts"] for f in flows] == [4]

        flows, _ = analyze(g.pcap(pkts, linktype=101), timeout=50)
        assert [f["pkts"] for f in flows] == [1, 1, 2]

    def test_port_reuse(self):
        c, s = "10.0.0.1", "10.0.0.2"
        pkts = [
            (0, g.tcp(c, 50000, s, 80, SYN)),
            (1, g.tcp(c, 50000, s, 80, FIN | ACK)),
            (2, g.tcp(s, 80, c, 50000, FIN | ACK)),
            (3, g.tcp(c, 50000, s, 80, SYN)),  # A new connection reusing the ports.
            (4, g.tcp(c, 50000, s, 80, RST)),
            (5, g.tcp(c, 50000, s, 80, ACK)),  # Not a SYN, so still the reset connection.
            (6, g.tcp(c, 50000, s, 80, SYN)),
            (7, g.tcp(c, 50000, s, 80, SYN)),  # Retransmitted SYN of an open connection.
            (8, g.tcp(c, 50000, s, 80, FIN | ACK)),  # Only one side closed, still open.
        ]
        flows, _ = analyze(g.pcap([(t, bytes(p)) for t, p in pkts], linktype=101))
        assert [f["pkts"] for f in flows] == [3, 3, 3]
        assert [f["tcp:state"] for f in flows] == ["closed", "reset", "open"]

    def test_out_of_order(self):
        frame = bytes(g.udp("10.0.0.1", 5000, "10.0.0.2", 6000))
        flows, summary = analyze(g.pcap([(5, frame), (2, frame), (9, frame)], linktype=101))
        assert flows[0]["time"] == (g.BASE + 2) * 1000
        assert flows[0]["last"] == (g.BASE + 9) * 1000
        assert summary["first"] == (g.BASE + 2) * 1000

    def test_limit(self):
        pkts = [(i, bytes(g.udp("10.0.0.1", 5000 + i, "10.0.0.2", 53))) for i in range(5)]
        pkts.append((9, bytes(g.udp("10.0.0.1", 5000, "10.0.0.2", 53))))
        flows, summary = analyze(g.pcap(pkts, linktype=101), limit=2)
        assert len(flows) == 2
        assert flows[0]["pkts"] == 2  # Existing flows still count packets.
        assert summary["flows"] == 2
        assert summary["dropped"] == 3
        assert summary["limited"]

    def test_handshake(self):
        c, s = "10.0.0.1", "10.0.0.2"
        long = b"EHLO " + b"x" * 2000
        pkts = [
            (0, bytes(g.tcp(c, 50000, s, 25, PSH | ACK, long))),
            (1, bytes(g.tcp(s, 25, c, 50000, PSH | ACK, b"\x16\x03\x01" + bytes(range(64))))),
            (2, bytes(g.tcp(c, 50000, s, 25, PSH | ACK, b"QUIT\r\n"))),
        ]
        flows, _ = analyze(g.pcap(pkts, linktype=101))
        assert flows[0]["src"]["handshake"] == long[:1024].decode()
        assert flows[0]["dst"]["handshake"] is None
        assert flows[0]["src"]["payload"] == len(long) + 6

        flows, _ = analyze(g.pcap(pkts, linktype=101), handshake=4)
        assert flows[0]["src"]["handshake"] == "EHLO"

        flows, _ = analyze(g.pcap(pkts, linktype=101), handshake=0)
        assert flows[0]["src"]["handshake"] is None


class TestHelpers:

    def test_tsToNs(self):
        assert p_flows.tsToNs(5, (10, 6)) == 5_000
        assert p_flows.tsToNs(5, (10, 9)) == 5
        assert p_flows.tsToNs(5_000, (10, 12)) == 5
        assert p_flows.tsToNs(1024, (2, 10)) == 1_000_000_000

    def test_textPayload(self):
        assert p_flows.textPayload(b"", 10) is None
        assert p_flows.textPayload(b"hello", 0) is None
        assert p_flows.textPayload(b"   \r\n", 10) is None
        assert p_flows.textPayload(b"\x00\x01\x02hello", 10) is None
        assert p_flows.textPayload(b"USER anonymous\r\n", 100) == "USER anonymous"
        # A few unprintable bytes are replaced.
        text = p_flows.textPayload(b"A" * 20 + b"\x01" + b"\xff", 100)
        assert text == "A" * 20 + "��"

    def test_tcpFlagNames(self):
        assert p_flows.tcpFlagNames(0) == []
        assert p_flows.tcpFlagNames(0xFF) == ["fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"]

    def test_addrValu(self):
        assert p_flows.addrValu("tcp", "1.2.3.4", 80) == "tcp://1.2.3.4:80"
        assert p_flows.addrValu("udp", "::1", 53) == "udp://[::1]:53"
        assert p_flows.addrValu("icmp", "::1", None) == "icmp://[::1]"
        assert p_flows.addrValu("gre", "1.2.3.4", None) == "gre://1.2.3.4"
        assert p_flows.addrValu("esp", "1.2.3.4", None) is None
        assert p_flows.addrValu(None, "1.2.3.4", None) is None

    def test_readPackets_state(self):
        # readPackets works without a state dict.
        pkts = list(p_flows.readPackets(io.BytesIO(g.pcap(g.session()))))
        assert len(pkts) == 16
        assert pkts[0].linktype == 1
        assert pkts[0].ts == g.BASE * 1_000_000_000

    def test_unwrap_depth(self):
        # Packets that never reach an IP layer aren't IP.
        assert p_flows._unwrapIp(b"bytes") is None
        arp = dpkt.ethernet.Ethernet(src=g.MAC_A, dst=g.MAC_B, type=dpkt.ethernet.ETH_TYPE_ARP,
                                     data=dpkt.arp.ARP())
        assert p_flows._unwrapIp(arp) is None


class TestIdentity:

    def test_communityId(self):
        from pcapsvc import communityid as p_cid

        def ip(valu):
            import ipaddress
            return ipaddress.ip_address(valu).packed

        # The Community ID spec's example, and its reverse direction.
        assert p_cid.communityId(6, ip("128.232.110.120"), ip("66.35.250.204"), 34855, 80) == \
            "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
        assert p_cid.communityId(6, ip("66.35.250.204"), ip("128.232.110.120"), 80, 34855) == \
            "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
        # Values checked against the reference implementation (pip install communityid).
        assert p_cid.communityId(1, ip("10.0.0.1"), ip("1.1.1.1"), 8, 0) == \
            p_cid.communityId(1, ip("1.1.1.1"), ip("10.0.0.1"), 0, 0)
        assert p_cid.communityId(47, ip("10.0.0.1"), ip("10.0.0.2")) == \
            p_cid.communityId(47, ip("10.0.0.2"), ip("10.0.0.1"))
        # One way ICMP types (ex. unreachable) aren't reordered.
        assert p_cid.communityId(1, ip("10.0.0.1"), ip("10.0.0.9"), 3, 1) != \
            p_cid.communityId(1, ip("10.0.0.9"), ip("10.0.0.1"), 3, 1)

        flows, _ = analyze(g.pcap(g.session()))
        http, dns, ping, ssh = flows
        assert http["community_id"] == p_cid.communityId(
            6, ip("10.0.0.1"), ip("93.184.216.34"), 50000, 80)
        assert ping["community_id"] == p_cid.communityId(1, ip("10.0.0.1"), ip("1.1.1.1"), 8, 0)
        assert all(f["community_id"].startswith("1:") for f in flows)

    def test_vlans(self):
        udp = g.udp("10.0.0.1", 5000, "10.0.0.2", 53)

        def tagged(*ids):
            tags = [dpkt.ethernet.VLANtag8021Q(id=i, type=0x8100) for i in ids]
            if tags:
                tags[-1].type = dpkt.ethernet.ETH_TYPE_IP
            return bytes(dpkt.ethernet.Ethernet(src=g.MAC_A, dst=g.MAC_B, vlan_tags=tags,
                                                type=dpkt.ethernet.ETH_TYPE_IP, data=udp))

        pkts = [(0, tagged(7)), (1, tagged(7)), (2, tagged(8)), (3, tagged()), (4, tagged(7, 9))]
        flows, _ = analyze(g.pcap(pkts))
        assert [(f["vlans"], f["pkts"]) for f in flows] == [([7], 2), ([8], 1), ([], 1), ([7, 9], 1)]
        # The VLAN IDs are part of the iden, the Community ID (endpoints only) isn't.
        assert len({f["iden"] for f in flows}) == 4
        assert len({f["community_id"] for f in flows}) == 1

    def test_iden(self):
        import synapse.common as s_common

        flows, _ = analyze(g.pcap(g.session()), seed="abc")
        http = flows[0]
        assert http["iden"] == s_common.guid((
            "slib.pcap.flow", p_flows.FLOW_IDEN_VERSION, "abc", 6, "10.0.0.1", 50000,
            "93.184.216.34", 80, [], g.BASE * 1_000_000_000))


class TestOwnEvents:
    def test_misplaced(self):
        # Suricata events logged on another flow's packet are re-matched by Community ID.
        mine, other = "1:mine", "1:other"
        rec = {
            "_eve": [{"community_id": mine, "event_type": "dns"},
                     {"community_id": other, "event_type": "fileinfo",
                      "timestamp": "2024-01-01T00:00:00.000000+0000"},
                     {"event_type": "stats"}],
            "_alerts": [("suricata", {"community_id": other}), ("snort", {"gid": 1})],
            "http.host": ["x"],
        }
        misplaced = []
        kept = p_flows._ownEvents(rec, mine, misplaced)
        assert [e["event_type"] for e in kept["_eve"]] == ["dns", "stats"]
        assert kept["_alerts"] == [("snort", {"gid": 1})]
        assert kept["http.host"] == ["x"]
        assert [(m[0], m[2]) for m in misplaced] == [(other, "eve"), (other, "suricata")]
        assert misplaced[0][1] == 1704067200000
        # The original record isn't changed, and records with only their own events are kept.
        assert len(rec["_eve"]) == 3
        assert p_flows._ownEvents(kept, mine, []) is kept



def _pcapRecords(path) -> tuple[tuple, list[tuple]]:
    """A nanosecond pcap's header and its (sec, nsec, incl_len, orig_len, data) records."""

    with open(path, "rb") as fd:
        buf = fd.read()
    header = struct.unpack_from("<IHHiIII", buf, 0)
    recs, offs = [], 24
    while offs < len(buf):
        sec, nsec, incl, orig = struct.unpack_from("<IIII", buf, offs)
        recs.append((sec, nsec, incl, orig, buf[offs + 16 : offs + 16 + incl]))
        offs += 16 + incl
    return header, recs


class TestSplitLinktypes:
    """pcapsvc.flows.splitLinktypes, the per link type pcaps libpcap based engines read."""

    def frame(self, sport: int) -> bytes:
        return g.eth(g.udp("10.0.0.1", sport, "10.0.0.2", 53, b"x"))

    def test_interface_without_packets(self, tmp_path):
        # libpcap rejects a pcapng on an IDB of another link type, even one with no packets.
        path = tmp_path / "x.pcapng"
        path.write_bytes(
            g.shb() + g.idb(1) + g.idb(113)
            + g.epb(0, g.usec(0), self.frame(1000)) + g.epb(0, g.usec(1), self.frame(1001))
        )
        parts = p_flows.splitLinktypes(str(path), str(tmp_path))
        assert parts is not None
        assert [(p.rsplit("/", 1)[-1], nums) for p, nums in parts] == [("linktype-1.pcap", [1, 2])]

    def test_pcap_stops_at_header(self, tmp_path, monkeypatch):
        # A classic pcap has one link type, its packets aren't all read to find that out.
        path = tmp_path / "x.pcap"
        path.write_bytes(g.pcap([(i, self.frame(1000 + i)) for i in range(50)]))
        seen = []
        orig = p_flows.readPackets

        def counting(fd, state=None):
            for pkt in orig(fd, state):
                seen.append(pkt.num)
                yield pkt

        monkeypatch.setattr(p_flows, "readPackets", counting)
        assert p_flows.splitLinktypes(str(path), str(tmp_path)) is None
        assert seen == [1]

    def test_clamps(self, tmp_path):
        # Timestamps a pcap record can't hold, and packets over libpcap's max snaplen.
        big = self.frame(1002) + b"\x00" * (p_flows.SPLIT_SNAPLEN + 100)
        future = (2**33) * 1_000_000  # Microseconds, past 2106.
        path = tmp_path / "x.pcapng"
        path.write_bytes(
            g.shb()
            # Interface 0 is offset back before the epoch.
            + g.idb(1, tsoffset=-2 * g.BASE) + g.idb(113)
            + g.epb(0, g.usec(0), self.frame(1000))
            + g.epb(1, future, b"\x00" * 16 + self.frame(1001)[14:])
            + g.epb(0, g.usec(2), big)
        )
        parts = dict((p.rsplit("/", 1)[-1], (p, nums)) for p, nums in
                     p_flows.splitLinktypes(str(path), str(tmp_path)))
        assert {k: v[1] for k, v in parts.items()} == {"linktype-1.pcap": [1, 3],
                                                       "linktype-113.pcap": [2]}

        header, recs = _pcapRecords(parts["linktype-1.pcap"][0])
        assert header == (0xA1B23C4D, 2, 4, 0, 0, p_flows.SPLIT_SNAPLEN, 1)
        # Before the epoch is the epoch, the big packet is cut at the snaplen (its original
        # length is kept).
        assert recs[0][:2] == (0, 0)
        assert recs[1][2:4] == (p_flows.SPLIT_SNAPLEN, len(big))
        assert recs[1][4] == big[: p_flows.SPLIT_SNAPLEN]
        _, recs = _pcapRecords(parts["linktype-113.pcap"][0])
        assert recs[0][:2] == (2**32 - 1, 999_999_999)

        # The parts are readable captures.
        for path, nums in parts.values():
            with open(path, "rb") as fd:
                _, summary = p_flows.analyze(fd)
            assert summary["packets"] == len(nums) and not summary["truncated"]


class TestMatchLoose:
    """pcapsvc.flows.matchLoose, engine records without a frame number."""

    def flow(self, iden: str, start: int, last: int, vlans=()) -> dict:
        return {"iden": iden, "community_id": "1:x", "time": start, "last": last,
                "vlans": list(vlans)}

    def match(self, flows, tick, rec=None) -> str:
        matched, unmatched = p_flows.matchLoose(flows, [("1:x", tick, "eve", rec or {})])
        assert unmatched == 0
        (iden,) = matched
        return iden

    def test_reused_tuple(self):
        # A reused 5-tuple: the old connection ends at 10s, the new one runs 10.1s to 70s.
        flows = [self.flow("old", 0, 10_000), self.flow("new", 10_100, 70_000)]
        # The new connection's own records (ex. its flow event at its start), even within a
        # second of the old one's end.
        assert self.match(flows, 10_100) == "new"
        assert self.match(flows, 40_000) == "new"
        assert self.match(flows, 5_000) == "old"
        # Between them (neither active), within a second: the closest end.
        assert self.match(flows, 10_050) == "old"
        # After both (ex. logged at the end of the capture): the one that just ended.
        assert self.match(flows, 70_500) == "new"
        # No time: the first.
        assert self.match(flows, None) == "old"

    def test_vlans(self):
        flows = [self.flow("tagged", 0, 1000, [10]), self.flow("untagged", 0, 1000)]
        # Suricata leaves vlan out of EVE records of untagged traffic.
        assert self.match(flows, 500, {"event_type": "flow"}) == "untagged"
        assert self.match(flows, 500, {"event_type": "flow", "vlan": [10]}) == "tagged"
        # Snort's alert_json has a vlan, 0 when untagged.
        assert self.match(flows, 500, {"gid": 1, "vlan": 0}) == "untagged"
        assert self.match(flows, 500, {"gid": 1, "vlan": 10}) == "tagged"
        # A VLAN no flow has doesn't drop the record.
        assert self.match(flows, 500, {"event_type": "flow", "vlan": [99]}) in ("tagged", "untagged")
        assert p_flows._recVlans({"gid": 1}) is None
        assert p_flows._recVlans({"vlan": ["x"]}) is None

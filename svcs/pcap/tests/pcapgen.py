"""Build packets and pcap/pcapng capture files for tests, so no binary fixtures are needed."""


import io
import ipaddress
import struct

import dpkt


BASE = 1_700_000_000
"""The capture start time for test packets, in seconds since the epoch."""

MAC_A = b"\x00\x11\x22\x33\x44\x55"
MAC_B = b"\x66\x77\x88\x99\xaa\xbb"


def _addr(ip: str) -> bytes:
    return ipaddress.ip_address(ip).packed


def ipPkt(src: str, dst: str, l4: dpkt.Packet | bytes, proto: int) -> dpkt.Packet:
    """An IPv4 or IPv6 packet (picked by the address) wrapping a transport packet."""

    if ":" in src:
        pkt = dpkt.ip6.IP6(src=_addr(src), dst=_addr(dst), nxt=proto, hlim=64, data=l4)
        pkt.plen = len(bytes(l4))
        return pkt
    pkt = dpkt.ip.IP(src=_addr(src), dst=_addr(dst), p=proto, ttl=64, data=l4)
    pkt.len = 20 + len(bytes(l4))
    return pkt


def tcp(src: str, sport: int, dst: str, dport: int, flags: int, data: bytes = b"") -> dpkt.Packet:
    """An IP packet with a TCP segment."""

    seg = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=data, off=5)
    return ipPkt(src, dst, seg, 6)


def udp(src: str, sport: int, dst: str, dport: int, data: bytes = b"") -> dpkt.Packet:
    """An IP packet with a UDP datagram."""

    dgram = dpkt.udp.UDP(sport=sport, dport=dport, data=data)
    dgram.ulen = 8 + len(data)
    return ipPkt(src, dst, dgram, 17)


def icmp(src: str, dst: str, type_: int) -> dpkt.Packet:
    """An IP packet with an ICMP (or ICMPv6, for IPv6 addresses) message."""

    if ":" in src:
        return ipPkt(src, dst, dpkt.icmp6.ICMP6(type=type_, code=0, data=b"\x00" * 8), 58)
    return ipPkt(src, dst, dpkt.icmp.ICMP(type=type_, code=0, data=b"\x00" * 8), 1)


def eth(ip: dpkt.Packet) -> bytes:
    """Wrap an IP packet in an Ethernet frame."""

    etype = dpkt.ethernet.ETH_TYPE_IP6 if isinstance(ip, dpkt.ip6.IP6) else dpkt.ethernet.ETH_TYPE_IP
    return bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=etype, data=ip))


def pcap(pkts: list[tuple[float, bytes]], linktype: int = 1, nano: bool = False,
         endian: str = "<") -> bytes:
    """A libpcap file of (seconds offset from BASE, frame) packets."""

    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    buf = io.BytesIO()
    buf.write(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype))
    for offs, frame in pkts:
        scale = 1_000_000_000 if nano else 1_000_000
        units = round(offs * scale)
        sec, frac = BASE + units // scale, units % scale
        buf.write(struct.pack(endian + "IIII", sec, frac, len(frame), len(frame)))
        buf.write(frame)
    return buf.getvalue()


def _block(btype: int, body: bytes, endian: str = "<") -> bytes:
    body += b"\x00" * (-len(body) % 4)
    size = len(body) + 12
    return struct.pack(endian + "II", btype, size) + body + struct.pack(endian + "I", size)


def _opt(code: int, valu: bytes, endian: str = "<") -> bytes:
    return struct.pack(endian + "HH", code, len(valu)) + valu + b"\x00" * (-len(valu) % 4)


def shb(endian: str = "<") -> bytes:
    """A pcapng Section Header Block."""

    return _block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)


def idb(linktype: int = 1, tsresol: int | None = None, tsoffset: int | None = None,
        endian: str = "<") -> bytes:
    """A pcapng Interface Description Block."""

    body = struct.pack(endian + "HHI", linktype, 0, 65535)
    opts = b""
    if tsresol is not None:
        opts += _opt(9, bytes([tsresol]), endian)
    if tsoffset is not None:
        opts += _opt(14, struct.pack(endian + "q", tsoffset), endian)
    if opts:
        body += opts + struct.pack(endian + "HH", 0, 0)
    return _block(1, body, endian)


def epb(ifid: int, units: int, frame: bytes, endian: str = "<") -> bytes:
    """A pcapng Enhanced Packet Block, with a timestamp in the interface's units."""

    body = struct.pack(endian + "IIIII", ifid, units >> 32, units & 0xFFFFFFFF, len(frame),
                       len(frame))
    return _block(6, body + frame, endian)


def spb(frame: bytes, endian: str = "<") -> bytes:
    """A pcapng Simple Packet Block."""

    return _block(3, struct.pack(endian + "I", len(frame)) + frame, endian)


def pb(ifid: int, units: int, frame: bytes, endian: str = "<") -> bytes:
    """An (obsolete) pcapng Packet Block."""

    body = struct.pack(endian + "HHIIII", ifid, 0, units >> 32, units & 0xFFFFFFFF, len(frame),
                       len(frame))
    return _block(2, body + frame, endian)


def other(endian: str = "<") -> bytes:
    """A pcapng block that should be ignored (an Interface Statistics Block)."""

    return _block(5, b"\x00" * 12, endian)


def usec(offs: float) -> int:
    """Seconds offset from BASE as microseconds since the epoch (the default pcapng units)."""

    return BASE * 1_000_000 + round(offs * 1_000_000)


HTTP_REQ = b"GET / HTTP/1.1\r\nHost: vertex.link\r\nUser-Agent: test\r\n\r\n"
HTTP_RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08


def session() -> list[tuple[float, bytes]]:
    """A capture of a few common flows, as (seconds offset, ethernet frame) packets.

    - An HTTP connection 10.0.0.1:50000 -> 93.184.216.34:80, handshake to FIN/ACK close.
    - A DNS query and response 10.0.0.1:53000 -> 8.8.8.8:53.
    - An ICMP ping 10.0.0.1 -> 1.1.1.1 (request and reply).
    - An IPv6 TCP connection [2001:db8::1]:40000 -> [2001:db8::2]:22 that is reset.
    - An ARP packet, which isn't IP.
    """

    c, s = "10.0.0.1", "93.184.216.34"
    pkts = [
        (0.0, eth(tcp(c, 50000, s, 80, SYN))),
        (0.1, eth(tcp(s, 80, c, 50000, SYN | ACK))),
        (0.2, eth(tcp(c, 50000, s, 80, ACK))),
        (0.3, eth(tcp(c, 50000, s, 80, PSH | ACK, HTTP_REQ))),
        (0.4, eth(tcp(s, 80, c, 50000, PSH | ACK, HTTP_RESP))),
        (0.5, eth(udp(c, 53000, "8.8.8.8", 53, b"\x12\x34" + b"\x00" * 10))),
        (0.6, eth(udp("8.8.8.8", 53, c, 53000, b"\x12\x34" + b"\x80" * 10))),
        (1.0, eth(icmp(c, "1.1.1.1", 8))),
        (1.1, eth(icmp("1.1.1.1", c, 0))),
        (2.0, eth(tcp("2001:db8::1", 40000, "2001:db8::2", 22, SYN))),
        (2.1, eth(tcp("2001:db8::2", 22, "2001:db8::1", 40000, SYN | ACK, b"SSH-2.0-OpenSSH_9.6\r\n"))),
        (2.2, eth(tcp("2001:db8::1", 40000, "2001:db8::2", 22, RST))),
        (2.5, bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_ARP,
                                           data=dpkt.arp.ARP()))),
        (3.0, eth(tcp(c, 50000, s, 80, FIN | ACK))),
        (3.1, eth(tcp(s, 80, c, 50000, FIN | ACK))),
        (3.2, eth(tcp(c, 50000, s, 80, ACK))),
    ]
    return pkts

"""Build small PCAPs for tests, without any packet library.

Only what the tests need: Ethernet + IPv4 with complete TCP sessions (handshake, payloads, and
teardown, so Snort's stream reassembly sees an established flow) and single UDP datagrams.
"""

import ipaddress
import struct
from typing import Self

LINKTYPE_ETHERNET = 1


def _csum(byts: bytes) -> int:
    if len(byts) % 2:
        byts += b"\x00"
    total = sum(struct.unpack(f"!{len(byts) // 2}H", byts))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        ident,
        0x4000,
        64,
        proto,
        0,
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    )
    hdr = hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:]
    return hdr + payload


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    return (
        ipaddress.IPv4Address(src).packed
        + ipaddress.IPv4Address(dst).packed
        + struct.pack("!BBH", 0, proto, length)
    )


def _tcp(
    src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, data: bytes
) -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    csum = _csum(_pseudo(src, dst, 6, len(hdr) + len(data)) + hdr + data)
    return hdr[:16] + struct.pack("!H", csum) + hdr[18:] + data


def _udp(src: str, dst: str, sport: int, dport: int, data: bytes) -> bytes:
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(data), 0)
    csum = _csum(_pseudo(src, dst, 17, len(hdr) + len(data)) + hdr + data) or 0xFFFF
    return hdr[:6] + struct.pack("!H", csum) + data


def _eth(payload: bytes) -> bytes:
    return b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + payload


class Pcap:
    """Build a classic (libpcap) capture, one packet at a time."""

    def __init__(self, start: float = 1790856000.0) -> None:
        self.time = start
        self.packets: list[tuple[float, bytes]] = []
        self.ident = 1

    def _add(self, src: str, dst: str, proto: int, l4: bytes) -> None:
        self.packets.append((self.time, _eth(_ipv4(src, dst, proto, l4, self.ident))))
        self.ident += 1
        self.time += 0.001

    def tcp(
        self, client: tuple[str, int], server: tuple[str, int], *exchanges: tuple[str, bytes]
    ) -> Self:
        """Add a complete TCP session. Each exchange is ("c", data) sent by the client or ("s", data)."""

        (cip, cport), (sip, sport) = client, server
        cseq, sseq = 1000, 5000
        self._add(cip, sip, 6, _tcp(cip, sip, cport, sport, cseq, 0, 0x02, b""))
        self._add(sip, cip, 6, _tcp(sip, cip, sport, cport, sseq, cseq + 1, 0x12, b""))
        cseq += 1
        sseq += 1
        self._add(cip, sip, 6, _tcp(cip, sip, cport, sport, cseq, sseq, 0x10, b""))
        for who, data in exchanges:
            if who == "c":
                self._add(cip, sip, 6, _tcp(cip, sip, cport, sport, cseq, sseq, 0x18, data))
                cseq += len(data)
                self._add(sip, cip, 6, _tcp(sip, cip, sport, cport, sseq, cseq, 0x10, b""))
            else:
                self._add(sip, cip, 6, _tcp(sip, cip, sport, cport, sseq, cseq, 0x18, data))
                sseq += len(data)
                self._add(cip, sip, 6, _tcp(cip, sip, cport, sport, cseq, sseq, 0x10, b""))
        self._add(cip, sip, 6, _tcp(cip, sip, cport, sport, cseq, sseq, 0x11, b""))
        self._add(sip, cip, 6, _tcp(sip, cip, sport, cport, sseq, cseq + 1, 0x11, b""))
        self._add(cip, sip, 6, _tcp(cip, sip, cport, sport, cseq + 1, sseq + 1, 0x10, b""))
        return self

    def udp(self, src: tuple[str, int], dst: tuple[str, int], data: bytes) -> Self:
        """Add a single UDP datagram."""

        self._add(src[0], dst[0], 17, _udp(src[0], dst[0], src[1], dst[1], data))
        return self

    def bytes(self) -> bytes:
        """The capture as libpcap file bytes."""

        out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)]
        for ts, pkt in self.packets:
            secs = int(ts)
            usecs = int(round((ts - secs) * 1_000_000))
            out.append(struct.pack("<IIII", secs, usecs, len(pkt), len(pkt)) + pkt)
        return b"".join(out)


HTTP_REQ = (
    b"GET /malware/beacon.php?id=1234 HTTP/1.1\r\nHost: evil.example.com\r\n"
    b"User-Agent: SlibSnortTest/1.0\r\nAccept: */*\r\n\r\n"
)
HTTP_RESP = (
    b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\nslibsnorttest"
)


def samplePcap() -> bytes:
    """A capture with an HTTP session (10.1.1.10:49152 -> 203.0.113.5:80), a second HTTP session
    from another client, and a UDP datagram (10.1.1.10:5353 -> 198.51.100.7:9999)."""

    pcap = Pcap()
    pcap.tcp(("10.1.1.10", 49152), ("203.0.113.5", 80), ("c", HTTP_REQ), ("s", HTTP_RESP))
    pcap.tcp(("10.1.1.11", 49153), ("203.0.113.5", 80), ("c", HTTP_REQ), ("s", HTTP_RESP))
    pcap.udp(("10.1.1.10", 5353), ("198.51.100.7", 9999), b"SLIBSNORT-UDP-PING")
    return pcap.bytes()

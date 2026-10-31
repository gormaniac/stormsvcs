"""Read packets from PCAP files and aggregate them into bidirectional network flows.

This module has no Synapse dependencies, so it can be used on its own.

``readPackets`` streams packets out of a pcap, pcapng, or gzip compressed capture file
(every interface of a pcapng file keeps its own link type and timestamp resolution).
``FlowTable`` decodes each packet's IP and transport headers (with ``dpkt``) and
aggregates them into flows keyed by their protocol and endpoints. ``analyze`` ties the
two together and returns the flows plus a summary of the capture.
"""

import gzip
import ipaddress
import struct
from collections.abc import Iterator
from typing import Any, BinaryIO, NamedTuple

import dpkt
import synapse.common as s_common

from . import communityid as p_communityid
from . import enrich as p_enrich


class PcapError(Exception):
    """Raised when a capture file can't be read at all (ex. it isn't a capture file).

    Problems with individual packets never raise, they are counted in the summary.
    """

    def __init__(self, mesg: str) -> None:
        super().__init__(mesg)
        self.mesg = mesg


class Packet(NamedTuple):
    """A packet read from a capture file."""

    ts: int
    """The packet's capture time, in nanoseconds since the epoch."""
    linktype: int
    """The link-layer header type (a LINKTYPE_* value) of the packet's interface."""
    data: bytes
    """The captured bytes, starting with the link-layer header."""
    num: int = 0
    """The packet's frame number, its position in the capture starting at 1 (like tshark's)."""


def _frame(state: dict) -> int:
    """Count a packet record in the capture and return its frame number."""

    state["frames"] = state.get("frames", 0) + 1
    return state["frames"]


PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000),  # Little endian, microsecond timestamps.
    b"\xa1\xb2\xc3\xd4": (">", 1_000),  # Big endian, microsecond timestamps.
    b"\x4d\x3c\xb2\xa1": ("<", 1),  # Little endian, nanosecond timestamps.
    b"\xa1\xb2\x3c\x4d": (">", 1),  # Big endian, nanosecond timestamps.
}
"""The pcap file magic numbers and the (byte order, nanoseconds per timestamp unit) they mean."""

PCAPNG_SHB = 0x0A0D0D0A
"""The pcapng Section Header Block type, which is also the magic at the start of the file."""
PCAPNG_BOM = 0x1A2B3C4D
"""The pcapng byte order magic, its byte order is the section's byte order."""
GZIP_MAGIC = b"\x1f\x8b"
"""The magic number of gzip compressed files."""

MAX_BLOCK = 256 * 1024 * 1024
"""The largest packet record or pcapng block that will be read, anything bigger is corruption."""

# Link-layer header types (https://www.tcpdump.org/linktypes.html).
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_PPP = 9
LINKTYPE_RAW_BSD = 12
LINKTYPE_RAW_OPENBSD = 14
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

LINKTYPES = {
    LINKTYPE_NULL: "null",
    LINKTYPE_ETHERNET: "ethernet",
    LINKTYPE_PPP: "ppp",
    LINKTYPE_RAW_BSD: "raw",
    LINKTYPE_RAW_OPENBSD: "raw",
    LINKTYPE_RAW: "raw",
    LINKTYPE_LOOP: "loop",
    LINKTYPE_LINUX_SLL: "linux_sll",
    LINKTYPE_IPV4: "ipv4",
    LINKTYPE_IPV6: "ipv6",
    LINKTYPE_LINUX_SLL2: "linux_sll2",
}
"""The link-layer header types that can be decoded, and their names."""

IPPROTOS = {
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "icmp",  # ICMPv6, modeled with the icmp inet:addr protocol.
    89: "ospf",
    132: "sctp",
}
"""IP protocol numbers and the protocol names used for them."""

ADDR_PROTOS = ("tcp", "udp", "icmp", "gre")
"""The protocols that inet:client/inet:server (inet:addr) values can be made for."""
PORT_PROTOS = ("tcp", "udp")
"""The protocols that have ports."""

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80

TCP_FLAGS = (
    (TCP_FIN, "fin"),
    (TCP_SYN, "syn"),
    (TCP_RST, "rst"),
    (TCP_PSH, "psh"),
    (TCP_ACK, "ack"),
    (TCP_URG, "urg"),
    (TCP_ECE, "ece"),
    (TCP_CWR, "cwr"),
)
"""TCP flag bits and their names."""

ICMP_REQUESTS = {(1, 8), (1, 13), (1, 15), (1, 17), (58, 128)}
"""(IP protocol, ICMP type) pairs that are sent by the client (echo, timestamp, info, mask)."""
ICMP_REPLIES = {(1, 0), (1, 14), (1, 16), (1, 18), (58, 129)}
"""(IP protocol, ICMP type) pairs that are sent by the server in reply to ICMP_REQUESTS."""

PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
"""The bytes counted as printable when deciding if a payload is text."""

DEFAULT_TIMEOUT = 300
"""Default seconds a flow can be idle before a packet between its endpoints starts a new flow."""
DEFAULT_HANDSHAKE = 1024
"""The default max number of characters saved from a flow's first text payload in each direction."""


def tsToNs(units: int, resol: tuple[int, int]) -> int:
    """Convert a timestamp in a pcapng interface's units to nanoseconds.

    ``resol`` is ``(base, exp)``, meaning one unit is ``base ** -exp`` seconds.
    """

    base, exp = resol
    if base == 10:
        if exp <= 9:
            return units * 10 ** (9 - exp)
        return units // 10 ** (exp - 9)
    return (units * 1_000_000_000) >> exp


def _readExact(fd: BinaryIO, size: int) -> bytes | None:
    """Read exactly size bytes. None at a clean EOF, raises EOFError for a partial read."""

    buf = fd.read(size)
    if not buf:
        return None
    while len(buf) < size:
        more = fd.read(size - len(buf))
        if not more:
            raise EOFError(f"Expected {size} bytes, got {len(buf)}")
        buf += more
    return buf


def _readPcap(fd: BinaryIO, header: bytes, state: dict) -> Iterator[Packet]:
    """Yield the packets of a classic libpcap file, ``header`` is its first 4 bytes."""

    endian, nsunit = PCAP_MAGICS[header]
    rest = _readExact(fd, 20)
    if rest is None:
        raise EOFError("Truncated pcap header")
    # Only the low 16 bits of the link type are the link type, the rest are FCS info.
    linktype = struct.unpack(endian + "I", rest[16:20])[0] & 0xFFFF
    state["format"] = "pcap"
    state["linktypes"].add(linktype)

    rec = struct.Struct(endian + "IIII")
    while (buf := _readExact(fd, 16)) is not None:
        sec, frac, caplen, _ = rec.unpack(buf)
        if caplen > MAX_BLOCK:
            raise EOFError(f"Packet record claims {caplen} bytes")
        data = _readExact(fd, caplen) if caplen else b""
        if data is None:
            raise EOFError("Truncated packet record")
        yield Packet(sec * 1_000_000_000 + frac * nsunit, linktype, data, _frame(state))


def _pcapngOptions(buf: bytes, endian: str) -> Iterator[tuple[int, bytes]]:
    """Yield the (code, value) options in a pcapng block's options section."""

    offs = 0
    while offs + 4 <= len(buf):
        code, size = struct.unpack_from(endian + "HH", buf, offs)
        if code == 0:
            return
        yield code, buf[offs + 4 : offs + 4 + size]
        offs += 4 + size + (-size % 4)


def _readPcapng(fd: BinaryIO, header: bytes, state: dict) -> Iterator[Packet]:
    """Yield the packets of a pcapng file, ``header`` is its first 4 bytes."""

    state["format"] = "pcapng"
    endian = "<"
    # Each interface is (linktype, (resolution base, exp), offset ns).
    ifaces: list[tuple[int, tuple[int, int], int]] = []
    lastts = 0

    def blockTypes() -> Iterator[bytes]:
        yield header
        while (btype := _readExact(fd, 4)) is not None:
            yield btype

    for btype in blockTypes():
        if btype == b"\x0a\x0d\x0d\x0a":
            # A new section, its byte order magic sets the byte order of everything in it.
            pre = _readExact(fd, 8)
            if pre is None:
                raise EOFError("Truncated section header")
            if struct.unpack("<I", pre[4:8])[0] == PCAPNG_BOM:
                endian = "<"
            elif struct.unpack(">I", pre[4:8])[0] == PCAPNG_BOM:
                endian = ">"
            else:
                raise PcapError("Invalid pcapng byte order magic")
            size = struct.unpack(endian + "I", pre[0:4])[0]
            if size < 28 or size > MAX_BLOCK:
                raise EOFError(f"Invalid pcapng section header length {size}")
            if _readExact(fd, size - 12) is None:
                raise EOFError("Truncated section header")
            ifaces = []
            continue

        sizebuf = _readExact(fd, 4)
        if sizebuf is None:
            raise EOFError("Truncated pcapng block")
        blktype = struct.unpack(endian + "I", btype)[0]
        size = struct.unpack(endian + "I", sizebuf)[0]
        if size < 12 or size > MAX_BLOCK or size % 4:
            raise EOFError(f"Invalid pcapng block length {size}")
        body = _readExact(fd, size - 8)
        if body is None:
            raise EOFError("Truncated pcapng block")
        body = body[:-4]  # Drop the trailing copy of the block length.

        if blktype == 1:  # Interface Description Block
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            resol, offs = (10, 6), 0
            for code, valu in _pcapngOptions(body[8:], endian):
                if code == 9 and valu:  # if_tsresol
                    resol = (2, valu[0] & 0x7F) if valu[0] & 0x80 else (10, valu[0])
                elif code == 14 and len(valu) >= 8:  # if_tsoffset, in seconds
                    offs = struct.unpack(endian + "q", valu[:8])[0] * 1_000_000_000
            ifaces.append((linktype, resol, offs))
            state["linktypes"].add(linktype)

        elif blktype in (6, 2):  # Enhanced Packet Block, (obsolete) Packet Block
            if blktype == 6:
                ifid, tshi, tslo, caplen = struct.unpack_from(endian + "IIII", body, 0)
                data = body[20 : 20 + caplen]
            else:
                ifid, _, tshi, tslo, caplen = struct.unpack_from(endian + "HHIII", body, 0)
                data = body[20 : 20 + caplen]
            num = _frame(state)
            if ifid >= len(ifaces):
                state["skipped"]["badiface"] = state["skipped"].get("badiface", 0) + 1
                continue
            linktype, resol, offs = ifaces[ifid]
            lastts = tsToNs((tshi << 32) | tslo, resol) + offs
            yield Packet(lastts, linktype, data, num)

        elif blktype == 3:  # Simple Packet Block, always interface 0 and has no timestamp.
            num = _frame(state)
            if not ifaces:
                state["skipped"]["badiface"] = state["skipped"].get("badiface", 0) + 1
                continue
            origlen = struct.unpack_from(endian + "I", body, 0)[0]
            yield Packet(lastts, ifaces[0][0], body[4 : 4 + origlen], num)

        # Every other block type (stats, name resolution, custom, etc.) is ignored.


def readPackets(fd: BinaryIO, state: dict | None = None) -> Iterator[Packet]:
    """Yield every packet in a pcap, pcapng, or gzip compressed pcap/pcapng file.

    Parameters
    ----------
    fd : BinaryIO
        The capture file, opened for reading in binary mode.
    state : dict | None
        A dict that is updated with what was learned about the file while reading it:
        ``format`` (pcap or pcapng), ``compressed``, ``linktypes`` (a set), ``truncated``
        (the file ended mid-packet), ``error`` (why reading stopped early), and
        ``skipped`` (counts of packets that couldn't be read, by reason).

    Raises
    ------
    PcapError
        If the file is not a capture file this can read.
    """

    if state is None:
        state = {}
    state.setdefault("linktypes", set())
    state.setdefault("skipped", {})
    state.setdefault("compressed", False)
    state.setdefault("truncated", False)
    state.setdefault("error", None)

    header = fd.read(4)
    if header[:2] == GZIP_MAGIC:
        if state["compressed"]:
            raise PcapError("The file is compressed more than once")
        fd.seek(0)
        state["compressed"] = True
        yield from readPackets(gzip.GzipFile(fileobj=fd, mode="rb"), state)
        return

    if header in PCAP_MAGICS:
        genr = _readPcap(fd, header, state)
    elif len(header) == 4 and struct.unpack("<I", header)[0] == PCAPNG_SHB:
        genr = _readPcapng(fd, header, state)
    else:
        raise PcapError("The file is not a pcap or pcapng file")

    try:
        yield from genr
    except (EOFError, gzip.BadGzipFile, struct.error, OSError, ValueError) as err:
        # Captures are often cut off (ex. a capture that was still being written), so keep
        # everything read until the problem, but report it.
        state["truncated"] = True
        state["error"] = str(err) or err.__class__.__name__


FLOW_IDEN_VERSION = 2
"""The version of the scheme ``Flow.asdict`` builds flow idens with. Changing what goes into an
iden needs a new version, so the idens of the old and new schemes can't collide."""


def _unwrapIp(pkt: Any) -> dpkt.ip.IP | dpkt.ip6.IP6 | None:
    """Find the IP packet inside a decoded link-layer packet (through VLAN, PPPoE, PPP, etc.)."""

    for _ in range(6):
        if isinstance(pkt, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return pkt
        if not isinstance(pkt, dpkt.Packet):
            return None
        pkt = pkt.data
    return None


def vlanIds(pkt: Any) -> tuple[int, ...]:
    """The 802.1Q VLAN IDs (outermost first) an Ethernet frame is tagged with."""

    return tuple(int(tag.id) for tag in getattr(pkt, "vlan_tags", None) or ())


def _rawIp(buf: bytes) -> dpkt.ip.IP | dpkt.ip6.IP6 | None:
    """Decode an IP packet with no link-layer header, by its version."""

    if not buf:
        return None
    vers = buf[0] >> 4
    if vers == 4:
        return dpkt.ip.IP(buf)
    if vers == 6:
        return dpkt.ip6.IP6(buf)
    return None


def decodeIp(linktype: int, buf: bytes) -> dpkt.ip.IP | dpkt.ip6.IP6 | None:
    """Decode the IP packet in a captured packet, or None if it isn't an IP packet.

    See ``decodePacket`` for the packet's VLAN IDs too.

    Raises
    ------
    KeyError
        If the link type isn't supported (see ``LINKTYPES``).
    dpkt.UnpackError
        If the packet's headers can't be decoded.
    """

    if linktype == LINKTYPE_ETHERNET:
        return _unwrapIp(dpkt.ethernet.Ethernet(buf))
    if linktype in (
        LINKTYPE_RAW,
        LINKTYPE_RAW_BSD,
        LINKTYPE_RAW_OPENBSD,
        LINKTYPE_IPV4,
        LINKTYPE_IPV6,
    ):
        return _rawIp(buf)
    if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        # A 4 byte address family, which varies by OS, so go by the IP version instead.
        return _rawIp(buf[4:])
    if linktype == LINKTYPE_LINUX_SLL:
        return _unwrapIp(dpkt.sll.SLL(buf))
    if linktype == LINKTYPE_LINUX_SLL2:
        return _unwrapIp(dpkt.sll2.SLL2(buf))
    if linktype == LINKTYPE_PPP:
        return _unwrapIp(dpkt.ppp.PPP(buf))
    raise KeyError(linktype)


def decodePacket(
    linktype: int, buf: bytes
) -> tuple[dpkt.ip.IP | dpkt.ip6.IP6 | None, tuple[int, ...]]:
    """Decode a captured packet's IP packet (see ``decodeIp``) and its VLAN IDs."""

    if linktype == LINKTYPE_ETHERNET:
        eth = dpkt.ethernet.Ethernet(buf)
        return _unwrapIp(eth), vlanIds(eth)
    return decodeIp(linktype, buf), ()


def textPayload(payload: bytes, size: int) -> str | None:
    """The start of a payload as text, if it's mostly printable ASCII (ex. HTTP, SMTP, SSH).

    Returns None for binary payloads (ex. TLS) and empty payloads.
    """

    if size <= 0 or not payload:
        return None
    head = payload[:size]
    printable = sum(1 for byte in head if byte in PRINTABLE)
    if printable / len(head) < 0.9:
        return None
    text = head.decode("ascii", errors="replace")
    text = "".join(c if c.isprintable() or c in "\t\r\n" else "�" for c in text)
    return text.strip() or None


def tcpFlagNames(flags: int) -> list[str]:
    """The names of the TCP flags set in a flags value."""

    return [name for bit, name in TCP_FLAGS if flags & bit]


def addrValu(proto: str | None, ip: str, port: int | None) -> str | None:
    """An inet:addr (inet:client/inet:server) value for an endpoint, or None if there can't be."""

    if proto not in ADDR_PROTOS:
        return None
    host = f"[{ip}]" if ":" in ip else ip
    if port is not None and proto in PORT_PROTOS:
        return f"{proto}://{host}:{port}"
    return f"{proto}://{host}"


class Side:
    """The traffic sent by one side of a flow."""

    __slots__ = ("bytes", "first", "ip", "payload", "pkts", "port")

    def __init__(self, ip: bytes, port: int | None) -> None:
        self.ip = ip
        self.port = port
        self.pkts = 0
        self.bytes = 0
        self.payload = 0
        self.first: bytes | None = None


class Flow:
    """A bidirectional network flow, the packets sent between a client and a server."""

    __slots__ = (
        "client",
        "fins",
        "flags",
        "frames",
        "icmpfirst",
        "icmptypes",
        "index",
        "ipproto",
        "last",
        "reset",
        "server",
        "start",
        "syn",
        "vers",
        "vlans",
    )

    def __init__(
        self,
        vers: int,
        ipproto: int,
        client: Side,
        server: Side,
        ts: int,
        index: int,
        vlans: tuple[int, ...] = (),
    ) -> None:
        self.vers = vers
        self.ipproto = ipproto
        self.vlans = vlans
        self.client = client
        self.server = server
        self.start = ts
        self.last = ts
        self.flags = 0
        self.fins = 0
        self.reset = False
        self.syn = False
        self.icmptypes: set[int] = set()
        # The (sender is the client, type, code) of the first ICMP packet, for the Community ID.
        self.icmpfirst: tuple[bool, int, int] | None = None
        self.index = index
        self.frames: list[tuple[bool, dict]] = []

    @property
    def closed(self) -> bool:
        """True if the TCP connection was reset or both sides sent a FIN."""

        return self.reset or self.fins == 3

    def side(self, src: bytes, sport: int | None) -> Side:
        """The side of the flow that sent a packet from src:sport."""

        if self.client.ip == src and self.client.port == sport:
            return self.client
        return self.server

    def state(self) -> str | None:
        """How the TCP connection ended: reset, closed, or open (None for other protocols)."""

        if self.ipproto != 6:
            return None
        if self.reset:
            return "reset"
        if self.fins == 3:
            return "closed"
        return "open"

    def communityId(self) -> str:
        """The flow's Community ID (see ``pcapsvc.communityid``), the same one Suricata logs.

        ICMP flows are by address, so their Community ID is the first ICMP packet's.
        """

        if self.ipproto in (1, 58) and self.icmpfirst is not None:
            fromclient, itype, code = self.icmpfirst
            src, dst = (self.client, self.server) if fromclient else (self.server, self.client)
            return p_communityid.communityId(self.ipproto, src.ip, dst.ip, itype, code)
        return p_communityid.communityId(
            self.ipproto, self.client.ip, self.server.ip, self.client.port, self.server.port
        )

    def asdict(self, handshake: int = DEFAULT_HANDSHAKE, seed: Any = None) -> dict:
        """The flow as a dict of primitives that can be sent over Telepath.

        Parameters
        ----------
        handshake : int
            The max number of characters of each side's first text payload to include.
        seed : Any
            A value (ex. the capture's SHA-256) included in the flow's iden, so the same flow
            from the same capture always has the same iden.

        The iden is a Synapse guid of the iden scheme's version (``FLOW_IDEN_VERSION``), the
        seed, the IP protocol, the client's and server's addresses and ports, the VLAN IDs, and
        when the flow started (in nanoseconds).
        """

        proto = IPPROTOS.get(self.ipproto)
        tcp = self.ipproto == 6

        def side(s: Side) -> dict:
            ip = str(ipaddress.ip_address(s.ip))
            return {
                "ip": ip,
                "port": s.port,
                "addr": addrValu(proto, ip, s.port),
                "pkts": s.pkts,
                "bytes": s.bytes,
                "payload": s.payload,
                "handshake": textPayload(s.first, handshake) if s.first else None,
            }

        client, server = side(self.client), side(self.server)
        iden = s_common.guid(
            (
                "slib.pcap.flow",
                FLOW_IDEN_VERSION,
                seed,
                self.ipproto,
                client["ip"],
                client["port"],
                server["ip"],
                server["port"],
                list(self.vlans),
                self.start,
            )
        )

        return {
            "iden": iden,
            "index": self.index,
            "version": self.vers,
            "ipproto": self.ipproto,
            "proto": proto,
            "vlans": list(self.vlans),
            "community_id": self.communityId(),
            "src": client,
            "dst": server,
            "time": self.start // 1_000_000,
            "last": self.last // 1_000_000,
            "duration": round((self.last - self.start) / 1_000_000_000),
            "durationms": (self.last - self.start) // 1_000_000,
            "pkts": self.client.pkts + self.server.pkts,
            "bytes": self.client.bytes + self.server.bytes,
            "tcp:flags": self.flags if tcp else None,
            "tcp:flagnames": tcpFlagNames(self.flags) if tcp else None,
            "tcp:state": self.state(),
            "tcp:syn": self.syn if tcp else None,
            "icmp:types": sorted(self.icmptypes) if self.ipproto in (1, 58) else None,
        }


class FlowTable:
    """Aggregates decoded packets into bidirectional flows.

    Packets are grouped by IP protocol and endpoints (addresses, plus ports for TCP and UDP).
    A packet starts a new flow, instead of being added to the existing one, when the existing
    flow has been idle for ``timeout`` seconds, or when it's a TCP SYN for a closed connection.

    The client (the flow's ``src``) is the side that sent the TCP SYN, the ICMP request, or
    otherwise the first packet. When the first TCP packet isn't part of the handshake, or the
    first UDP packet is from a privileged port (< 1024) to an unprivileged one, the side using
    the privileged port is assumed to be the server.

    Parameters
    ----------
    timeout : int
        Seconds a flow can be idle before the next packet between its endpoints starts a new
        flow. 0 means flows never time out.
    limit : int
        The max number of flows to track, packets for any more are counted as dropped. 0 means
        no limit.
    """

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, limit: int = 0) -> None:
        self.timeout = int(timeout * 1_000_000_000) if timeout else 0
        self.limit = limit
        self.active: dict[tuple, Flow] = {}
        self.done: list[Flow] = []
        self.count = 0
        self.packets = 0
        self.decoded = 0
        self.dropped = 0
        self.skipped: dict[str, int] = {}
        self.first: int | None = None
        self.last: int | None = None
        self.fromClient = False

    def _skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1

    def add(self, pkt: Packet, rec: dict | None = None) -> Flow | None:
        """Add a captured packet to its flow, returning the flow (or None if it was skipped).

        ``rec`` is what tshark found in the packet (see ``pcapsvc.tshark``), it's kept with the
        flow along with which side sent it, see ``Flow.frames``.
        """

        self.packets += 1
        if self.first is None or pkt.ts < self.first:
            self.first = pkt.ts
        if self.last is None or pkt.ts > self.last:
            self.last = pkt.ts

        try:
            ip, vlans = decodePacket(pkt.linktype, pkt.data)
        except KeyError:
            self._skip("linktype")
            return None
        except (dpkt.UnpackError, struct.error, ValueError, IndexError):
            self._skip("malformed")
            return None

        if ip is None:
            self._skip("nonip")
            return None

        flow = self.addIp(pkt.ts, ip, vlans)
        if flow is not None and rec is not None:
            flow.frames.append((self.fromClient, rec))
        return flow

    def addIp(
        self, ts: int, ip: dpkt.ip.IP | dpkt.ip6.IP6, vlans: tuple[int, ...] = ()
    ) -> Flow | None:
        """Add a decoded IP packet, captured at ts (nanoseconds), to its flow.

        Packets on different VLANs are different flows, even between the same endpoints.
        """

        if isinstance(ip, dpkt.ip.IP):
            vers = 4
            wirelen = ip.len or len(ip)
            fragment = ip.offset != 0
        else:
            vers = 6
            wirelen = (40 + ip.plen) if ip.plen else len(ip)
            frag = ip.extension_hdrs.get(dpkt.ip.IP_PROTO_FRAGMENT)
            fragment = frag is not None and frag.frag_off != 0

        if fragment:
            # Only the first fragment has the transport header, so the rest can't be matched
            # to a flow without reassembly.
            self._skip("fragment")
            return None

        ipproto = ip.p
        l4 = ip.data
        sport = dport = None
        flags = 0
        payload = b""
        icmptype = None

        if ipproto in (6, 17):
            if not isinstance(l4, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                # The capture cut the packet off before the end of the transport header.
                self._skip("truncated")
                return None
            sport, dport = l4.sport, l4.dport
            payload = bytes(l4.data)
            if ipproto == 6:
                flags = l4.flags
        icmpcode = 0
        if ipproto in (1, 58):
            if isinstance(l4, dpkt.Packet):
                icmptype, icmpcode = l4.type, l4.code
            elif len(l4):
                icmptype = l4[0]
                icmpcode = l4[1] if len(l4) > 1 else 0

        self.decoded += 1
        src, dst = bytes(ip.src), bytes(ip.dst)
        a, b = (src, sport), (dst, dport)
        key = (ipproto, vlans) + ((a, b) if a <= b else (b, a))

        flow = self.active.get(key)
        if flow is not None and self._expired(flow, ts, flags):
            self.done.append(self.active.pop(key))
            flow = None

        if flow is None:
            if self.limit and self.count >= self.limit:
                self.dropped += 1
                return None
            flow = self._newFlow(vers, ipproto, src, sport, dst, dport, ts, flags, icmptype, vlans)
            self.active[key] = flow

        side = flow.side(src, sport)
        self.fromClient = side is flow.client
        side.pkts += 1
        side.bytes += wirelen
        side.payload += len(payload)
        if payload and side.first is None:
            side.first = payload

        flow.last = max(flow.last, ts)
        flow.start = min(flow.start, ts)

        if ipproto == 6:
            flow.flags |= flags
            if flags & TCP_SYN:
                flow.syn = True
            if flags & TCP_RST:
                flow.reset = True
            if flags & TCP_FIN:
                flow.fins |= 1 if side is flow.client else 2
        elif icmptype is not None:
            flow.icmptypes.add(icmptype)
            if flow.icmpfirst is None:
                flow.icmpfirst = (side is flow.client, icmptype, icmpcode)

        return flow

    def _expired(self, flow: Flow, ts: int, flags: int) -> bool:
        """True if a packet at ts with the given TCP flags should start a new flow."""

        if self.timeout and ts - flow.last > self.timeout:
            return True
        # A new connection reusing the ports of a finished one.
        return flow.closed and bool(flags & TCP_SYN) and not flags & TCP_ACK

    def _newFlow(
        self,
        vers: int,
        ipproto: int,
        src: bytes,
        sport: int | None,
        dst: bytes,
        dport: int | None,
        ts: int,
        flags: int,
        icmptype: int | None,
        vlans: tuple[int, ...] = (),
    ) -> Flow:
        """Create a flow from its first packet, deciding which side is the client."""

        swap = False
        if ipproto == 6 and flags & TCP_SYN:
            # A SYN-ACK is sent by the server.
            swap = bool(flags & TCP_ACK)
        elif icmptype is not None and (ipproto, icmptype) in ICMP_REPLIES:
            swap = True
        elif icmptype is not None and (ipproto, icmptype) in ICMP_REQUESTS:
            swap = False
        elif sport is not None and dport is not None:
            if ipproto == 6:
                # Joined mid-connection, the server is probably the side with the lower port.
                swap = sport < dport and sport < 1024
            else:
                swap = sport < 1024 <= dport

        client, server = Side(src, sport), Side(dst, dport)
        if swap:
            client, server = server, client

        self.count += 1
        return Flow(vers, ipproto, client, server, ts, self.count - 1, vlans)

    def flows(self) -> list[Flow]:
        """Every flow, ordered by when they started."""

        return sorted(self.done + list(self.active.values()), key=lambda f: (f.start, f.index))

    def summary(self) -> dict:
        """A summary of the packets added to this table."""

        return {
            "packets": self.packets,
            "decoded": self.decoded,
            "skipped": dict(self.skipped),
            "flows": self.count,
            "dropped": self.dropped,
            "limited": bool(self.dropped),
            "first": self.first // 1_000_000 if self.first is not None else None,
            "last": self.last // 1_000_000 if self.last is not None else None,
        }


def matchLoose(
    flows: list[dict], loose: list[tuple[str, int | None, str, Any]]
) -> tuple[dict[str, list[tuple[str, Any]]], int]:
    """Match records that have no frame number to flows, by Community ID and time.

    Parameters
    ----------
    flows : list[dict]
        The flows (``Flow.asdict``), with their ``community_id``, ``time``, and ``last``.
    loose : list
        (Community ID, time in epoch millis or None, kind, record) of each record.

    Returns
    -------
    tuple
        ({flow iden: [(kind, record), ...]}, the number of records no flow matched). A record
        goes to the flow with its Community ID that was active at its time (within a second),
        or the closest one.
    """

    bycid: dict[str, list[dict]] = {}
    for flow in flows:
        bycid.setdefault(flow["community_id"], []).append(flow)

    matched: dict[str, list[tuple[str, Any]]] = {}
    unmatched = 0
    for cid, tick, kind, rec in loose:
        cands = bycid.get(cid)
        if not cands:
            unmatched += 1
            continue
        best = cands[0]
        if tick is not None and len(cands) > 1:

            def dist(flow: dict, tick: int = tick) -> int:
                if flow["time"] - 1000 <= tick <= flow["last"] + 1000:
                    return 0
                return min(abs(tick - flow["time"]), abs(tick - flow["last"]))

            best = min(cands, key=dist)
        matched.setdefault(best["iden"], []).append((kind, rec))
    return matched, unmatched


def analyze(
    fd: BinaryIO,
    timeout: int = DEFAULT_TIMEOUT,
    limit: int = 0,
    handshake: int = DEFAULT_HANDSHAKE,
    seed: Any = None,
    frames: dict | None = None,
    files: p_enrich.FileStore | None = None,
    unsaved: bool = False,
    rules: dict | None = None,
    loose: list | None = None,
    filestore: str | None = None,
) -> tuple[list[dict], dict]:
    """Read a capture file and return its flows (see ``Flow.asdict``) and a summary of it.

    Parameters
    ----------
    fd : BinaryIO
        The capture file (pcap, pcapng, or either gzip compressed), opened in binary mode.
    timeout : int
        Seconds a flow can be idle before a new flow starts, 0 to never time out.
    limit : int
        The max number of flows, 0 for no limit.
    handshake : int
        The max number of characters of each side's first text payload to include.
    seed : Any
        A value (ex. the capture's SHA-256) used to make flow idens unique to the capture.
    frames : dict | None
        What the engines found in the capture, by frame number: tshark's fields (see
        ``pcapsvc.tshark``), and ``_eve`` (Suricata events) and ``_alerts`` ((engine, alert)
        pairs) lists. The details are added to the flows the frames belong to (see
        ``pcapsvc.enrich``).
    files : FileStore | None
        Where to write the files found in the flows, None to not extract files.
    unsaved : bool
        Count the files that would have been extracted when ``files`` is None.
    rules : dict | None
        The loaded rules of each engine, to turn alerts into hits.
    loose : list | None
        Records without a frame number, matched to flows by Community ID and time (see
        ``matchLoose``). Each is (Community ID, time, kind, record), kind is ``eve`` or an
        alert's engine.
    filestore : str | None
        The directory of the files Suricata extracted.

    Raises
    ------
    PcapError
        If the file isn't a capture file this can read.
    """

    frames = frames or {}
    state: dict = {}
    table = FlowTable(timeout=timeout, limit=limit)
    matched = 0
    unframed = 0
    for pkt in readPackets(fd, state):
        rec = frames.get(pkt.num)
        flow = table.add(pkt, rec)
        if rec is not None:
            if flow is not None:
                matched += 1
            else:
                unframed += len(rec.get("_eve", ())) + len(rec.get("_alerts", ()))

    summary = table.summary()
    skipped = dict(state["skipped"])
    for reason, count in summary["skipped"].items():
        skipped[reason] = skipped.get(reason, 0) + count
    summary.update(
        {
            "format": state.get("format"),
            "compressed": state["compressed"],
            "linktypes": [
                {"type": lt, "name": LINKTYPES.get(lt)} for lt in sorted(state["linktypes"])
            ],
            "skipped": skipped,
            "truncated": state["truncated"],
            "error": state["error"],
            "tshark": {"frames": len(frames), "matched": matched},
        }
    )

    counts: dict[str, dict[str, int]] = {}
    base = [(flow, flow.asdict(handshake=handshake, seed=seed)) for flow in table.flows()]
    extra, unmatched = matchLoose([d for _, d in base], loose or [])

    flows = []
    unsavedcount = 0
    for flow, fdict in base:
        enricher = p_enrich.Enricher(
            files, unsaved=unsaved, rules=rules, counts=counts, filestore=filestore
        )
        for client, rec in flow.frames:
            enricher.add(client, rec)
        for kind, rec in extra.get(fdict["iden"], ()):
            if kind == "eve":
                enricher.eve.append(rec)
            else:
                enricher.alerts.append((kind, rec))
        flows.append(enricher.apply(fdict))
        unsavedcount += enricher.unsaved

    summary["events"] = {"unmatched": unmatched + unframed, **counts}
    summary["hits"] = sum(len(f["hits"]) for f in flows)
    if files is not None:
        summary["files"] = {"count": len(files.files), "skipped": files.skipped}
    if unsaved:
        summary["files"] = {"count": 0, "skipped": 0, "unsaved": unsavedcount}
    return flows, summary

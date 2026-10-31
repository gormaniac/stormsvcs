"""Community ID flow hashes (version 1), see https://github.com/corelight/community-id-spec.

A Community ID identifies a flow by its endpoints and protocol, the same in both directions.
Suricata logs one on every EVE event (``community-id: yes``), which is how its events are
matched back to the flows ``pcapsvc.flows`` builds when a frame number can't be used.
"""


import base64
import hashlib
import struct

ICMP4_PAIRS = {0: 8, 8: 0, 13: 14, 14: 13, 15: 16, 16: 15, 17: 18, 18: 17, 9: 10, 10: 9}
"""ICMPv4 types and the type of their reply/request counterpart (echo, timestamp, info, mask,
router advertisement/solicitation)."""

ICMP6_PAIRS = {128: 129, 129: 128, 133: 134, 134: 133, 135: 136, 136: 135, 130: 131, 131: 130,
               144: 145, 145: 144, 146: 147, 147: 146}
"""ICMPv6 types and their counterparts."""

PORT_PROTOS = (6, 17, 132)
"""IP protocols with ports (TCP, UDP, SCTP)."""


def _icmpPorts(ipproto: int, itype: int, code: int) -> tuple[int, int, bool]:
    """The (port, port, one way) ICMP types and codes are hashed as."""

    pairs = ICMP4_PAIRS if ipproto == 1 else ICMP6_PAIRS
    if itype in pairs:
        return itype, pairs[itype], False
    return itype, code, True


def communityId(ipproto: int, src: bytes, dst: bytes, sport: int | None = None,
                dport: int | None = None, seed: int = 0) -> str:
    """The Community ID of a flow.

    Parameters
    ----------
    ipproto : int
        The IP protocol number.
    src, dst : bytes
        The packed IPv4 or IPv6 addresses of the flow's (or packet's) source and destination.
    sport, dport : int | None
        The ports for TCP, UDP, and SCTP. For ICMP and ICMPv6 they are the ICMP type and code.
        None for other protocols.
    seed : int
        The Community ID seed (0 by default, the same as Suricata's).
    """

    oneway = False
    if ipproto in (1, 58) and sport is not None:
        sport, dport, oneway = _icmpPorts(ipproto, sport, dport or 0)

    hasports = sport is not None and dport is not None and (
        ipproto in PORT_PROTOS or ipproto in (1, 58))
    if not oneway and ((src, sport if hasports else 0) > (dst, dport if hasports else 0)):
        src, dst = dst, src
        sport, dport = dport, sport

    data = struct.pack(">H", seed) + src + dst + struct.pack(">BB", ipproto, 0)
    if hasports:
        data += struct.pack(">HH", sport, dport)
    return "1:" + base64.b64encode(hashlib.sha1(data).digest()).decode()

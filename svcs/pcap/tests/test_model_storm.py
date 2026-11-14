"""Pytests for slib.pcap.model and slib.pcap.lib with crafted flows (no engine needed)."""


import copy
import hashlib

import synapse.tests.utils as s_tests

from pcapsvc import eve as p_eve

from . import pcapgen as g
from .test_pcap_storm import pcapCore

NOENGINES = {"tshark": False, "suricata": False, "snort": False}


async def baseFlow(svc, sha: str) -> dict:
    """The first flow the service finds in a capture, to craft engine details onto."""

    flows, _ = await svc.analyze(sha, **NOENGINES)
    return copy.deepcopy(flows[0])


class TestModelStorm(s_tests.SynTest):

    async def test_dns_answers(self):
        async with pcapCore(self, g.pcap(g.session())) as (core, svc, (sha,)):
            flow = await baseFlow(svc, sha)

            def ans(name, rrtype, rdata=None, **extra):
                ev = {"rrname": name, "rrtype": rrtype, "ttl": 60, "rdata": rdata, **extra}
                return ev

            events = [
                {"type": "query", "id": 1, "rrname": "4.3.2.1.in-addr.arpa", "rrtype": "PTR"},
                {"type": "answer", "id": 1, "rrname": "4.3.2.1.in-addr.arpa", "rrtype": "PTR",
                 "rcode": "NOERROR",
                 "answers": [ans("4.3.2.1.in-addr.arpa", "PTR", "host.vertex.link")]},
                {"type": "answer", "id": 2, "rrname": "vertex.link", "rrtype": "SOA",
                 "rcode": "NOERROR",
                 "answers": [ans("vertex.link", "SOA",
                                 soa={"mname": "ns1.vertex.link.",
                                      "rname": "hostmaster.vertex.link"})]},
                {"type": "answer", "id": 3, "rrname": "_ldap._tcp.vertex.link", "rrtype": "SRV",
                 "rcode": "NOERROR",
                 "answers": [ans("_ldap._tcp.vertex.link", "SRV", "dc.vertex.link")]},
            ]
            v6name = ".".join(reversed("20010db8000000000000000000000001")) + ".ip6.arpa"
            events.append(
                {"type": "answer", "id": 4, "rrname": v6name, "rrtype": "PTR",
                 "rcode": "NOERROR", "answers": [ans(v6name, "PTR", "v6.vertex.link")]}
            )
            flow["dns"] = p_eve.dnsQueries(events)

            q = "$lib.import(slib.pcap.model).flow($flow, $lib.import(slib.pcap.model).fileNode($sha))"
            msgs = await core.stormlist(q, opts={"vars": {"flow": flow, "sha": sha}})
            self.stormHasNoWarnErr(msgs)

            nodes = await core.nodes("inet:dns:answer:rev")
            self.len(1, nodes)
            assert nodes[0].get("rev") == (0x01020304, "host.vertex.link")
            nodes = await core.nodes("inet:dns:answer:rev6")
            self.len(1, nodes)
            assert nodes[0].get("rev6") == ("2001:db8::1", "v6.vertex.link")

            nodes = await core.nodes("inet:dns:answer:soa -> inet:dns:soa")
            self.len(1, nodes)
            assert nodes[0].get("fqdn") == "vertex.link"
            assert nodes[0].get("ns") == "ns1.vertex.link"
            assert nodes[0].get("email") == "hostmaster@vertex.link"

            # SRV answers have no inet:dns:answer prop, so no empty answer nodes are made.
            self.len(3, await core.nodes("inet:dns:answer"))
            self.len(4, await core.nodes("inet:dns:request"))

    def test_ptr_addr(self):
        assert p_eve.ptrAddr("4.3.2.1.in-addr.arpa.") == {"ipv4": "1.2.3.4"}
        assert p_eve.ptrAddr("3.2.1.in-addr.arpa") is None
        assert p_eve.ptrAddr("x.3.2.1.in-addr.arpa") is None
        assert p_eve.ptrAddr("vertex.link") is None
        assert p_eve.ptrAddr(None) is None
        assert p_eve.ptrAddr("g." * 32 + "ip6.arpa") is None
        assert p_eve.soaInfo({"mname": "ns.x.", "rname": "a\\.b.x"})["email"] is None
        assert p_eve.soaInfo({"rname": "a.x"}) is None

    async def test_rdp_dst_and_cert_file(self):
        async with pcapCore(self, g.pcap(g.session())) as (core, svc, (sha,)):
            flow = await baseFlow(svc, sha)
            # A capture that starts midstream can have the client's RDP fields on dst.
            flow["dst"]["rdp:hostname"] = "WORKSTATION"
            flow["dst"]["rdp:keyboard:layout"] = "en-us"
            der = b"not a cert"
            cert = {"sha256": hashlib.sha256(der).hexdigest(), "sha1": hashlib.sha1(der).hexdigest(),
                    "md5": hashlib.md5(der).hexdigest(), "error": "unparsable", "stored": False}
            flow["dst"]["ssl:cert"] = cert
            flow["dst"]["ssl:certs"] = [cert]

            q = "$lib.import(slib.pcap.model).flow($flow, $lib.import(slib.pcap.model).fileNode($sha))"
            msgs = await core.stormlist(q, opts={"vars": {"flow": flow, "sha": sha}})
            self.stormHasNoWarnErr(msgs)

            node = (await core.nodes(f"inet:flow={flow['iden']}"))[0]
            assert node.get("dst:rdp:hostname") is None
            certnode = (await core.nodes("inet:flow -> crypto:x509:cert"))[0]
            # The cert's bytes weren't saved, so there's no :file (or file:bytes) for them.
            assert certnode.get("file") is None
            self.len(0, await core.nodes(f"file:bytes=sha256:{cert['sha256']}"))

            cert["stored"] = True
            msgs = await core.stormlist(q, opts={"vars": {"flow": flow, "sha": sha}})
            self.stormHasNoWarnErr(msgs)
            certnode = (await core.nodes("inet:flow -> crypto:x509:cert"))[0]
            assert certnode.get("file") == f"sha256:{cert['sha256']}"

    async def test_invalid_model_opts(self):
        async with pcapCore(self, g.pcap(g.session())) as (core, svc, (sha,)):
            for opt, flag in (("--tag", "--tag"), ("--host", "--host"),
                              ("--sandbox-file", "--sandbox-file")):
                msgs = await core.stormlist(f"slib.pcap.flows {sha} {opt} foo..bar")
                self.stormIsInWarn(f"Invalid {flag}", msgs)
                # Nothing was modeled (or analyzed).
                self.len(0, await core.nodes("inet:flow"))

            host = await core.callStorm("[ it:host=* ] return($node.value())")
            msgs = await core.stormlist(f"slib.pcap.flows {sha} --tag foo.bar --host {host}")
            self.stormHasNoWarnErr(msgs)
            self.len(4, await core.nodes("inet:flow#foo.bar +:capture:host"))

"""Pytests for the slib.pcap Storm package (the command, modules, modeling, and perms)."""


import contextlib
import hashlib
import pathlib

import synapse.tests.utils as s_tests

from pcapsvc import PcapSvc
from pcapsvc import tshark as p_tshark
from pcapsvc.defs import SVC_GUID

from . import pcapgen as g
from .engines import needs


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

            # Lifted by SHA-256, files extracted from the flows are file:bytes nodes too.
            msgs = await core.stormlist(f"file:bytes={sha} | slib.pcap.flows")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(
                f"slib.pcap: Modeled 4 flows (0 rule matches) from 16 packets in file:bytes=sha256:{sha}", msgs
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
            msgs = await core.stormlist(f"file:bytes={sha} | slib.pcap.flows --yield")
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
            self.len(2, await core.nodes(f"file:bytes:sha256={shas[0]} file:bytes:sha256={shas[1]}"))
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
            self.stormIsInPrint("Modeled 4 flows (0 rule matches) from 15 packets", msgs)
            self.stormIsInWarn(f"slib.pcap: {cut} is truncated, read up to the error", msgs)

            for sha, err in ((bad, "The file is not a pcap or pcapng file"),
                             (missing, "is not in the Axon"),
                             ("nope", "Invalid SHA-256: nope")):
                msgs = await core.stormlist(f"slib.pcap.flows {sha}")
                self.stormHasNoErr(msgs)
                self.stormIsInWarn(f"slib.pcap: Unable to analyze {sha}", msgs)
                self.stormIsInWarn(err, msgs)

            # Bad PCAPs don't create file:bytes nodes.
            self.len(0, await core.nodes(f"file:bytes:sha256={bad} file:bytes:sha256={missing}"))
            self.len(4, await core.nodes("inet:flow"))

            # Unsupported inbound nodes warn and are dropped.
            await core.nodes("[ inet:fqdn=vertex.link file:bytes=* ]")
            msgs = await core.stormlist(f"inet:fqdn file:bytes:sha256={cut} | slib.pcap.flows")
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
                $opts = ({"tag": "lib.test", "timeout": (0), "limit": (1), "handshake": (0)})
                file:bytes:sha256=$sha
                for $n in $pcap.flows(:sha256, opts=$opts, file=$node) {
                    yield $n
                }
                +inet:flow
            """
            nodes = await core.nodes(q, opts={"vars": {"sha": sha}})
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
            self.len(0, await core.nodes(f"file:bytes:sha256={bad}"))

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


DATA = pathlib.Path(__file__).parent / "data"
needsTshark = needs("tshark")
CAPTURES = ("http", "tls", "ssh", "ftp", "smtp", "rdp")


@needsTshark
class TestPcapStormTshark(s_tests.SynTest):

    async def test_enrichment(self):
        blobs = [(DATA / f"{name}.pcapng").read_bytes() for name in CAPTURES]
        async with pcapCore(self, *blobs) as (core, _, shas):
            sha = dict(zip(CAPTURES, shas))
            msgs = await core.stormlist("slib.pcap.flows " + " ".join(shas))
            self.stormHasNoWarnErr(msgs)

            # TLS: both certificates, the SNI, and the fingerprints in :raw.
            tls = (await core.nodes("inet:flow:dst:port=443"))[0]
            dstcert = (await core.nodes("inet:flow:dst:port=443 :dst:ssl:cert -> crypto:x509:cert"))[0]
            assert dstcert.get("subject") == "CN=vertex.link,O=Test"
            assert dstcert.get("identities:fqdns") == ("vertex.link",)
            assert dstcert.get("ext:sans") == (("dns", "vertex.link"),)
            assert dstcert.get("selfsigned") == 1
            assert dstcert.get("file") == f"sha256:{dstcert.get('sha256')}"
            srccert = (await core.nodes("inet:flow:dst:port=443 :src:ssl:cert -> crypto:x509:cert"))[0]
            assert srccert.get("subject") == "CN=client.vertex.link,O=Test"
            self.len(1, await core.nodes("inet:flow:dst:port=443 -(refs)> inet:fqdn=vertex.link"))
            self.len(2, await core.nodes("inet:flow:dst:port=443 -(refs)> crypto:x509:cert"))
            assert tls.get("raw")["tls"]["ja4"]

            # SSH: the host key and software.
            ssh = (await core.nodes("inet:flow:dst:port=22"))[0]
            key = (await core.nodes("inet:flow:dst:port=22 :dst:ssh:key -> crypto:key"))[0]
            assert key.get("algorithm") == "ssh-ed25519"
            assert key.get("public").startswith("0000000b7373682d65643235353139")
            assert ssh.get("src:softnames") == ("openssh_9.6p1 ubuntu-3ubuntu13.20",)
            assert ssh.get("dst:cpes") == ("cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*",)
            self.len(1, await core.nodes("it:sec:cpe=cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"))

            # RDP.
            rdp = (await core.nodes("inet:flow:dst:port=3389"))[0]
            assert rdp.get("src:rdp:hostname") == "workstation-7"
            assert rdp.get("src:rdp:keyboard:layout") == "en_us"

            # Files: HTTP download and upload, FTP RETR and STOR, the email and its attachment.
            download = hashlib.sha256(bytes(range(256)) * 64).hexdigest()
            upload = hashlib.sha256(b"uploaded file contents\n" * 100).hexdigest()
            q = "inet:flow:dst:port=80 :dst:txfiles -> file:attachment +:name=sample.bin"
            att = (await core.nodes(q))[0]
            assert att.get("file") == f"sha256:{download}"
            filenode = (await core.nodes(f"file:bytes=sha256:{download}"))[0]
            assert filenode.get("size") == 16384
            assert filenode.get("mime") == "application/octet-stream"
            self.len(1, await core.nodes(
                f"inet:flow:dst:port=80 :src:txfiles -> file:attachment +:file=sha256:{upload}"))
            self.len(2, await core.nodes(
                f"inet:flow :dst:txfiles -> file:attachment +:file=sha256:{download}"))
            # The HTTP and FTP uploads are the same file, so the same file:bytes.
            self.len(2, await core.nodes(
                f"inet:flow :src:txfiles -> file:attachment +:name=report.txt +:file=sha256:{upload} "
                "-> file:bytes +:mime=text/plain"))
            q = "inet:flow:dst:port=25 :src:txfiles -> file:attachment"
            names = {(n.get("name"), n.get("text")) for n in await core.nodes(q)}
            assert names == {(None, "the report"), ("report.pdf", None)}
            assert (await core.nodes(f"file:bytes={sha['smtp']} -(refs)> inet:flow"))[0].get(
                "src:softnames") == ("thunderbird/115.6.0",)

            # Running again doesn't duplicate anything.
            counts = {f: len(await core.nodes(f)) for f in
                      ("inet:flow", "file:attachment", "crypto:x509:cert", "crypto:key")}
            msgs = await core.stormlist("slib.pcap.flows " + " ".join(shas))
            self.stormHasNoWarnErr(msgs)
            for form, count in counts.items():
                self.len(count, await core.nodes(form))

    async def test_options(self):
        async with pcapCore(self, (DATA / "http.pcapng").read_bytes()) as (core, svc, (sha,)):
            await core.nodes("[ file:bytes=sha256:" + "a" * 64 + " ]")
            msgs = await core.stormlist(f"slib.pcap.flows {sha} --no-tshark --no-suricata --sandbox-file {'a' * 64}")
            self.stormHasNoWarnErr(msgs)
            nodes = await core.nodes("inet:flow")
            assert all(n.get("src:softnames") is None for n in nodes)
            assert all(n.get("sandbox:file") == "sha256:" + "a" * 64 for n in nodes)

            msgs = await core.stormlist(f"slib.pcap.flows {sha} --no-files")
            self.stormHasNoWarnErr(msgs)
            self.len(0, await core.nodes("file:attachment"))
            self.len(2, await core.nodes("inet:flow +:dst:softnames"))

            # Problems are warned about.
            svc.conf["pcap:files:maxsize"] = 100
            msgs = await core.stormlist(f"slib.pcap.flows {sha}")
            self.stormIsInWarn("2 files in", msgs)
            svc.conf["pcap:files:maxsize"] = 0

            async def broken(path, **kwargs):
                raise p_tshark.TsharkError("boom")
            svc.tshark.frames = broken
            msgs = await core.stormlist(f"slib.pcap.flows {sha}")
            self.stormIsInWarn(f"slib.pcap: tshark had a problem with {sha}: boom", msgs)

            svc.tshark.path = None
            msgs = await core.stormlist(f"slib.pcap.flows {sha}")
            self.stormHasNoWarnErr(msgs)
            msgs = await core.stormlist(f"slib.pcap.flows {sha}", opts={"debug": True})
            self.stormIsInPrint("No tshark details", msgs)


class TestPcapStormSettings(s_tests.SynTest):

    async def test_admin_decode(self):
        async with pcapCore(self, g.pcap(g.session())) as (core, svc, (sha,)):
            msgs = await core.stormlist("slib.pcap.admin.decode")
            self.stormIsInPrint("slib.pcap has no Decode As rules for every run.", msgs)

            q = "slib.pcap.admin.decode --add 'TCP.port==8443,tls' --add 'tcp.port==2222,ssh'"
            msgs = await core.stormlist(q)
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("    tcp.port==8443,tls", msgs)
            assert await core.callStorm('return($lib.globals.get("slib:pcap:decode"))') == \
                ("tcp.port==8443,tls", "tcp.port==2222,ssh")

            msgs = await core.stormlist("slib.pcap.admin.decode --del 'tcp.port==2222,ssh' "
                                        "--add 'tcp.port==8443,tls'")
            self.stormNotInPrint("2222", msgs)

            # Invalid rules aren't saved.
            msgs = await core.stormlist("slib.pcap.admin.decode --add '-X lua_script:x.lua'")
            self.stormIsInWarn("Invalid Decode As rule", msgs)
            assert await core.callStorm('return($lib.globals.get("slib:pcap:decode"))') == \
                ("tcp.port==8443,tls",)

            # Every run uses the admin's rules, plus its own.
            seen = []
            async def frames(path, keylog=None, decode=(), gaps=False):
                seen.append(list(decode))
                return {}, {"version": "fake", "error": None}
            svc.tshark.path = "/bin/true"
            svc.tshark.frames = frames
            msgs = await core.stormlist(f"slib.pcap.flows {sha} --decode-as 'udp.port==5000,rtp' "
                                        "--decode-as 'tcp.port==8443,tls'")
            self.stormHasNoWarnErr(msgs)
            assert seen == [["tcp.port==8443,tls", "udp.port==5000,rtp"]]

            msgs = await core.stormlist(f"slib.pcap.flows {sha} --decode-as bad")
            self.stormIsInWarn("Invalid Decode As rule 'bad'", msgs)

            msgs = await core.stormlist("slib.pcap.admin.decode --clear")
            self.stormIsInPrint("no Decode As rules", msgs)

            # Only admins manage the rules, users can still set their own per run.
            user = await core.auth.addUser("analyst")
            await user.allow(("slib", "pcap", "user"))
            await user.allow(("node",))
            msgs = await core.stormlist("slib.pcap.admin.decode", opts={"user": user.iden})
            self.stormIsInErr("slib.pcap.admin", msgs)
            seen.clear()
            msgs = await core.stormlist(f"slib.pcap.flows {sha} --decode-as 'tcp.port==22,ssh'",
                                        opts={"user": user.iden})
            self.stormHasNoWarnErr(msgs)
            assert seen == [["tcp.port==22,ssh"]]

    async def test_keylog_no_tshark(self):
        async with pcapCore(self, g.pcap(g.session()), b"CLIENT_RANDOM 00 00\n") as \
                (core, svc, (sha, keylog)):
            msgs = await core.stormlist(f"slib.pcap.flows {sha} --keylog {keylog} --no-tshark")
            self.stormIsInWarn(f"slib.pcap: TLS key logs need tshark, {sha} wasn't decrypted.", msgs)


@needsTshark
class TestPcapStormDecrypt(s_tests.SynTest):

    async def test_keylog(self):
        blobs = ((DATA / "tls13.pcapng").read_bytes(), (DATA / "tls13.keylog").read_bytes())
        async with pcapCore(self, *blobs) as (core, _, (sha, keylog)):
            msgs = await core.stormlist(f"slib.pcap.flows {sha}")
            self.stormHasNoWarnErr(msgs)
            self.len(0, await core.nodes("inet:flow +:dst:ssl:cert"))

            msgs = await core.stormlist(f"slib.pcap.flows {sha} --keylog sha256:{keylog}")
            self.stormHasNoWarnErr(msgs)
            self.len(2, await core.nodes("inet:flow +:dst:ssl:cert"))
            cert = await core.nodes("inet:flow :dst:ssl:cert -> crypto:x509:cert")
            assert {n.get("subject") for n in cert} == {"CN=secure.vertex.link,O=Test"}
            download = hashlib.sha256(bytes(range(256)) * 64).hexdigest()
            upload = hashlib.sha256(b"uploaded file contents\n" * 100).hexdigest()
            self.len(1, await core.nodes(
                f"inet:flow :dst:txfiles -> file:attachment +:file=sha256:{download}"))
            self.len(1, await core.nodes(
                f"inet:flow :src:txfiles -> file:attachment +:name=report.txt "
                f"+:file=sha256:{upload}"))
            self.len(2, await core.nodes("inet:flow +:src:softnames*[=curl/8.5.0]"))


@needs("suricata")
class TestPcapStormSuricata(s_tests.SynTest):
    """The protocols only Suricata parses: DNS, QUIC, SMB, and Kerberos."""

    async def test_protocols(self):
        names = ("dns", "quic", "smb", "krb5")
        blobs = [(DATA / f"{name}.pcapng").read_bytes() for name in names]
        async with pcapCore(self, *blobs) as (core, _, shas):
            sha = dict(zip(names, shas))
            msgs = await core.stormlist("slib.pcap.flows " + " ".join(shas))
            self.stormHasNoWarnErr(msgs)

            # DNS: every query, its answers, and the response code.
            reqs = await core.nodes("inet:dns:request")
            assert sorted((n.get("query:name"), n.get("query:type")) for n in reqs) == [
                ("nope.vertex.link", 1), ("vertex.link", 1), ("vertex.link", 15),
                ("vertex.link", 16), ("vertex.link", 28), ("www.vertex.link", 1),
            ]
            nope = (await core.nodes("inet:dns:request:query:name=nope.vertex.link"))[0]
            assert nope.get("reply:code") == 3
            assert nope.get("server") == "udp://127.0.0.1:53"
            client, name, qtype = nope.get("query")
            assert client.startswith("udp://127.0.0.1:") and (name, qtype) == ("nope.vertex.link", 1)
            self.len(0, await core.nodes("inet:dns:request:query:name=nope.vertex.link "
                                         "-> inet:dns:answer"))
            q = "inet:dns:request:query:name=vertex.link +:query:type=1 -> inet:dns:answer"
            ans = (await core.nodes(q))[0]
            assert ans.get("a") == ("vertex.link", 0x5DB8D822) and ans.get("ttl") == 300
            q = "inet:dns:request:query:name=www.vertex.link -> inet:dns:answer"
            assert {n.get("cname") or n.get("a") for n in await core.nodes(q)} == {
                ("www.vertex.link", "vertex.link"), ("vertex.link", 0x5DB8D822),
            }
            q = "inet:dns:request:query:type=28 -> inet:dns:answer"
            assert (await core.nodes(q))[0].get("aaaa") == ("vertex.link", "2001:db8::34")
            q = "inet:dns:request:query:type=15 -> inet:dns:answer"
            assert (await core.nodes(q))[0].get("mx") == ("vertex.link", "mail.vertex.link")
            # The TXT query was over TCP.
            q = "inet:dns:request:query:type=16 <(refs)- inet:flow"
            assert (await core.nodes(q))[0].get("ip:proto") == 6
            self.len(6, await core.nodes(f"file:bytes={sha['dns']} -(refs)> inet:flow "
                                         "-(refs)> inet:dns:request"))

            # QUIC: the SNI and fingerprints.
            quic = (await core.nodes("inet:flow:dst:port=443 +:ip:proto=17"))[0]
            raw = quic.get("raw")
            assert raw["app_proto"] == ("quic",)
            assert raw["quic"][0]["sni"] == "quic.vertex.link"
            assert raw["tls"]["ja4"] and raw["tls"]["ja3s"] and raw["tls"]["alpn"] == ("h3",)
            self.len(1, await core.nodes("inet:flow:dst:port=443 +:ip:proto=17 "
                                         "-(refs)> inet:fqdn=quic.vertex.link"))

            # SMB: the files read and written.
            download = hashlib.sha256(bytes(range(256)) * 64).hexdigest()
            upload = hashlib.sha256(b"uploaded file contents\n" * 100).hexdigest()
            smb = (await core.nodes("inet:flow:dst:port=445"))[0]
            assert smb.get("raw")["app_proto"] == ("smb",)
            assert {"share": "\\\\127.0.0.1\\DATA", "share_type": "FILE"}.items() <= \
                [e for e in smb.get("raw")["smb"] if e.get("share")][0].items()
            att = (await core.nodes("inet:flow:dst:port=445 :dst:txfiles -> file:attachment"))[0]
            assert att.get("file") == f"sha256:{download}" and att.get("name") == "sample.bin"
            att = (await core.nodes("inet:flow:dst:port=445 :src:txfiles -> file:attachment"))[0]
            assert att.get("file") == f"sha256:{upload}" and att.get("name") == "report.txt"

            # Kerberos: the AS-REQ and the KDC's error, over TCP and UDP.
            krbs = await core.nodes("inet:flow:dst:port=88")
            self.len(2, krbs)
            for krb in krbs:
                msgs = krb.get("raw")["krb5"]
                assert msgs[0] == {"msg_type": "KRB_AS_REQ", "cname": "alice",
                                   "realm": "VERTEX.LINK", "sname": "krbtgt/VERTEX.LINK",
                                   "weak_encryption": False}
                assert msgs[1]["error_code"] == "KDC_ERR_PREAUTH_REQUIRED"
                assert "cname" not in msgs[1]

            # Running again doesn't duplicate anything.
            counts = {f: len(await core.nodes(f)) for f in
                      ("inet:flow", "inet:dns:request", "inet:dns:answer", "file:attachment")}
            msgs = await core.stormlist("slib.pcap.flows " + " ".join(shas))
            self.stormHasNoWarnErr(msgs)
            for form, count in counts.items():
                self.len(count, await core.nodes(form))

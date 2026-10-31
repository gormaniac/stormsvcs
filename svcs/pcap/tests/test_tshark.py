"""Pytests for pcapsvc.tshark, and tshark enrichment of the real captures in tests/data.

These need tshark, they're skipped when it isn't installed (CI installs it).
"""


import hashlib
import io
import os
import pathlib
import shutil
import stat

import pytest

from pcapsvc import enrich as p_enrich
from pcapsvc import flows as p_flows
from pcapsvc import tshark as p_tshark

from . import pcapgen as g


DATA = pathlib.Path(__file__).parent / "data"

DOWNLOAD = hashlib.sha256(bytes(range(256)) * 64).hexdigest()
"""The SHA-256 of the file the captures' servers send (see tests/data/capture.py)."""
UPLOAD = hashlib.sha256(b"uploaded file contents\n" * 100).hexdigest()
"""The SHA-256 of the file the captures' clients send."""
ATTACHMENT = hashlib.sha256(b"%PDF-1.4 not really a pdf\n" * 20).hexdigest()
"""The SHA-256 of the email's attachment."""

needsTshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark isn't installed")


async def enriched(name: str, tmp_path, files: bool = True) -> tuple[list[dict], dict]:
    """The enriched flows and summary of a capture in tests/data."""

    path = str(DATA / f"{name}.pcapng")
    frames, _ = await p_tshark.Tshark().frames(path)
    store = p_enrich.FileStore(str(tmp_path)) if files else None
    with open(path, "rb") as fd:
        return p_flows.analyze(fd, frames=frames, files=store)


def fakeTshark(tmp_path, script: str) -> str:
    """A fake tshark binary that runs a shell script."""

    path = tmp_path / "tshark"
    path.write_text("#!/bin/sh\n" + script)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


@needsTshark
class TestCaptures:

    async def test_http(self, tmp_path):
        flows, summary = await enriched("http", tmp_path)
        assert summary["tshark"] == {"frames": 4, "matched": 4}
        assert summary["files"] == {"count": 3, "skipped": 0}
        get, post = flows

        assert get["src"]["softnames"] == ["curl/8.5.0"]
        assert get["dst"]["softnames"] == ["nginx/1.24.0"]
        assert get["dst"]["cpes"] == ["cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"]
        assert get["http"]["requests"] == [{"method": "GET", "uri": "/files/sample.bin"}]
        (dl,) = get["dst"]["txfiles"]
        assert dl["sha256"] == DOWNLOAD and dl["name"] == "sample.bin"
        assert dl["mime"] == "application/octet-stream"
        assert (tmp_path / DOWNLOAD).stat().st_size == 16384

        (up,) = post["src"]["txfiles"]
        assert up["sha256"] == UPLOAD and up["name"] == "report.txt"
        assert post["dst"]["txfiles"][0]["name"] is None

    async def test_tls(self, tmp_path):
        (flow,), summary = await enriched("tls", tmp_path)
        assert flow["tls"]["sni"] == ["vertex.link"]
        assert flow["tls"]["ja3"] and flow["tls"]["ja3s"]
        assert flow["dst"]["ssl:cert"]["subject"] == "CN=vertex.link,O=Test"
        assert flow["dst"]["ssl:cert"]["identities"]["fqdns"] == ["vertex.link"]
        assert flow["src"]["ssl:cert"]["subject"] == "CN=client.vertex.link,O=Test"
        # Certificates are written to the file store too.
        assert summary["files"]["count"] == 2
        assert (tmp_path / flow["dst"]["ssl:cert"]["sha256"]).exists()

    async def test_ssh(self, tmp_path):
        from cryptography.hazmat.primitives import serialization
        import base64

        (flow,), _ = await enriched("ssh", tmp_path)
        assert flow["src"]["softnames"] == ["openssh_9.6p1 ubuntu-3ubuntu13.20"]
        assert flow["dst"]["cpes"] == ["cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"]
        key = flow["dst"]["ssh:key"]
        assert key["algo"] == "ssh-ed25519"
        assert flow["src"]["ssh:key"] is None  # The client's key is only sent encrypted.
        serialization.load_ssh_public_key(
            b"ssh-ed25519 " + base64.b64encode(bytes.fromhex(key["blob"]))
        )

    async def test_ftp(self, tmp_path):
        flows, _ = await enriched("ftp", tmp_path)
        control, retr, stor = flows
        assert control["dst"]["port"] == 21
        assert control["dst"]["txfiles"] == [] and control["src"]["txfiles"] == []
        # Passive mode, the client opens both data connections.
        assert retr["dst"]["txfiles"][0]["sha256"] == DOWNLOAD
        assert retr["dst"]["txfiles"][0]["name"] == "sample.bin"
        assert retr["dst"]["txfiles"][0]["complete"] is True
        assert stor["src"]["txfiles"][0]["sha256"] == UPLOAD
        assert stor["src"]["txfiles"][0]["name"] == "report.txt"

    async def test_smtp(self, tmp_path):
        (flow,), _ = await enriched("smtp", tmp_path)
        msg, att = flow["src"]["txfiles"]
        assert msg["mime"] == "message/rfc822" and msg["text"] == "the report"
        assert att["sha256"] == ATTACHMENT and att["name"] == "report.pdf"
        assert flow["src"]["softnames"] == ["thunderbird/115.6.0"]

    async def test_rdp(self, tmp_path):
        (flow,), _ = await enriched("rdp", tmp_path)
        assert flow["src"]["rdp:hostname"] == "workstation-7"
        assert flow["src"]["rdp:keyboard:layout"] == "en_us"

    async def test_no_files(self, tmp_path):
        flows, summary = await enriched("http", tmp_path, files=False)
        assert "files" not in summary
        assert flows[0]["dst"]["txfiles"] == []
        assert flows[0]["dst"]["softnames"] == ["nginx/1.24.0"]

    async def test_frame_numbers(self, tmp_path):
        # Frame numbers line up with tshark's, even in pcapng files with SPBs and bad interfaces.
        frame = g.eth(g.udp("10.0.0.1", 5000, "10.0.0.2", 6000))
        data = g.shb() + g.idb(1) + g.epb(9, g.usec(0), frame) + g.spb(frame) + g.epb(0, g.usec(1), frame)
        pkts = list(p_flows.readPackets(io.BytesIO(data)))
        assert [p.num for p in pkts] == [2, 3]
        pkts = list(p_flows.readPackets(io.BytesIO(g.pcap(g.session()))))
        assert [p.num for p in pkts] == list(range(1, 17))

        path = tmp_path / "x.pcap"
        path.write_bytes(g.pcap(g.session()))
        frames, _ = await p_tshark.Tshark().frames(str(path))
        with open(path, "rb") as fd:
            flows, summary = p_flows.analyze(fd, frames=frames)
        assert summary["tshark"]["frames"] == summary["tshark"]["matched"] == 3
        http = flows[0]
        assert http["src"]["softnames"] == ["test"]
        assert http["http"]["hosts"] == ["vertex.link"]
        assert flows[3]["dst"]["softnames"] == ["openssh_9.6"]


@needsTshark
class TestTshark:

    async def test_load(self):
        ts = p_tshark.Tshark()
        assert ts.available
        await ts.load()
        assert ts.version.startswith("TShark")
        assert "http.user_agent" in ts.supported
        supported = ts.supported
        await ts.load()  # Only loads once.
        assert ts.supported is supported

    async def test_unsupported_fields(self):
        # Fields an older tshark doesn't know are left out instead of failing.
        ts = p_tshark.Tshark()
        await ts.load()
        ts.supported = ts.supported - {"tls.handshake.ja4", "http.user_agent"}
        frames, info = await ts.frames(str(DATA / "http.pcapng"))
        assert info["error"] is None
        assert all("http.user_agent" not in rec for rec in frames.values())
        assert any("http.server" in rec for rec in frames.values())

    async def test_args(self, tmp_path):
        # Extra args, ex. decoding SSH on another port.
        src = DATA / "ssh.pcapng"
        ts = p_tshark.Tshark(args=("-d", "tcp.port==22,http"))
        frames, _ = await ts.frames(str(src))
        assert not any("ssh.protocol" in rec for rec in frames.values())

    async def test_errors(self, tmp_path):
        ts = p_tshark.Tshark()
        with pytest.raises(p_tshark.TsharkError, match="tshark failed"):
            await ts.frames(str(tmp_path / "nope.pcap"))

        # A truncated capture still returns what tshark read, with the error.
        data = (DATA / "http.pcapng").read_bytes()
        path = tmp_path / "cut.pcapng"
        path.write_bytes(data[:len(data) - 600])
        frames, info = await ts.frames(str(path))
        assert frames and info["error"]


class TestTsharkFake:
    """Tshark failures, with fake tshark binaries."""

    async def test_missing(self):
        ts = p_tshark.Tshark(path="/nonexistent/tshark")
        assert not ts.available
        with pytest.raises(p_tshark.TsharkError, match="tshark is not installed"):
            await ts.frames("x")

    async def test_failures(self, tmp_path):
        ts = p_tshark.Tshark(path=fakeTshark(tmp_path, "echo broken >&2; exit 1"))
        with pytest.raises(p_tshark.TsharkError, match="tshark -v failed: broken"):
            await ts.load()

        script = 'if [ "$1" = "-v" ]; then echo "TShark (Wireshark) 9.9"; exit 0; fi\n' \
                 "echo nofields >&2; exit 2"
        ts = p_tshark.Tshark(path=fakeTshark(tmp_path, script))
        with pytest.raises(p_tshark.TsharkError, match="tshark -G fields failed: nofields"):
            await ts.load()

        ts = p_tshark.Tshark(path=fakeTshark(tmp_path, "sleep 5"), timeout=0.2)
        with pytest.raises(p_tshark.TsharkError, match="longer than 0.2 seconds"):
            await ts.load()

    async def test_output(self, tmp_path):
        # Lines that aren't frames are skipped, and a bad email pass is ignored.
        script = (
            'case "$1" in\n'
            '  -v) echo "TShark (Wireshark) 9.9" ;;\n'
            '  -G) printf "F\\tUser Agent\\thttp.user_agent\\tFT_STRING\\nP\\tIMF\\timf\\n" ;;\n'
            '  *) case "$*" in\n'
            '       *json*) echo "not json" ;;\n'
            '       *) echo \'{"index":{}}\'\n'
            '          echo \'{"timestamp":"1","layers":{}}\'\n'
            '          echo \'{"timestamp":"1","layers":{"frame_number":["3"],"imf":["imf"]}}\' ;;\n'
            '     esac ;;\n'
            'esac\n'
        )
        ts = p_tshark.Tshark(path=fakeTshark(tmp_path, script))
        frames, info = await ts.frames("x")
        assert frames == {3: {"imf": ["imf"]}}
        assert info == {"version": "TShark (Wireshark) 9.9", "error": None}
        assert os.path.exists(ts.path)


class TestDecodeAs:

    def test_checkDecodeAs(self):
        assert p_tshark.checkDecodeAs(None) == []
        assert p_tshark.checkDecodeAs(["TCP.port==8443,TLS ", "tcp.port==8443,tls",
                                       "udp.port==5000-5010,rtp"]) == \
            ["tcp.port==8443,tls", "udp.port==5000-5010,rtp"]
        for bad in ("tcp.port==8443", "-X lua_script:x.lua", "tcp.port==8443,tls;rm",
                    "tcp.port==abc,tls", "tcp.port==1,", "", "tcp.port == 1,tls"):
            with pytest.raises(p_tshark.TsharkError, match="Invalid Decode As rule"):
                p_tshark.checkDecodeAs([bad])
        with pytest.raises(p_tshark.TsharkError, match="must be a list"):
            p_tshark.checkDecodeAs("tcp.port==1,tls")


@needsTshark
class TestDecrypt:

    async def test_decode(self):
        # Decode As rules change what tshark dissects, ex. SSH's port as HTTP.
        ts = p_tshark.Tshark()
        frames, _ = await ts.frames(str(DATA / "ssh.pcapng"), decode=["tcp.port==22,http"])
        assert not any("ssh.protocol" in rec for rec in frames.values())
        with pytest.raises(p_tshark.TsharkError, match="Invalid Decode As rule"):
            await ts.frames(str(DATA / "ssh.pcapng"), decode=["nope"])
        # A valid looking rule tshark doesn't know is a tshark error.
        with pytest.raises(p_tshark.TsharkError, match="tshark failed"):
            await ts.frames(str(DATA / "ssh.pcapng"), decode=["tcp.port==22,nosuchproto"])

    async def test_tls13(self, tmp_path):
        path = str(DATA / "tls13.pcapng")
        keylog = str(DATA / "tls13.keylog")

        # Without the keys only the ClientHello and ServerHello are readable.
        frames, _ = await p_tshark.Tshark().frames(path)
        with open(path, "rb") as fd:
            flows, _ = p_flows.analyze(fd, frames=frames,
                                       files=p_enrich.FileStore(str(tmp_path)))
        h1, h2 = flows
        assert h1["tls"]["sni"] == ["secure.vertex.link"]
        assert h1["tls"]["ja4"][0].startswith("t13")
        assert h1["dst"]["ssl:cert"] is None
        assert h1["http"] is None and h1["dst"]["txfiles"] == []

        frames, _ = await p_tshark.Tshark().frames(path, keylog=keylog)
        with open(path, "rb") as fd:
            flows, summary = p_flows.analyze(fd, frames=frames,
                                             files=p_enrich.FileStore(str(tmp_path)))
        h1, h2 = flows
        assert h1["dst"]["ssl:cert"]["subject"] == "CN=secure.vertex.link,O=Test"
        assert h2["dst"]["ssl:cert"]["subject"] == "CN=secure.vertex.link,O=Test"

        # HTTP/1.1 inside TLS 1.3.
        assert h1["src"]["softnames"] == ["curl/8.5.0"]
        assert h1["http"]["requests"] == [{"method": "GET", "uri": "/files/sample.bin"}]
        (dl,) = h1["dst"]["txfiles"]
        assert dl["sha256"] == DOWNLOAD and dl["name"] == "sample.bin" and dl["proto"] == "http"

        # HTTP/2 inside TLS 1.3.
        assert h2["http"] == {"hosts": ["secure.vertex.link"],
                              "requests": [{"method": "POST", "uri": "/upload/report.txt"}]}
        assert h2["src"]["softnames"] == ["curl/8.5.0"]
        assert h2["dst"]["softnames"] == ["hypercorn-h11"]
        (up,) = h2["src"]["txfiles"]
        assert up["sha256"] == UPLOAD and up["name"] == "report.txt" and up["proto"] == "http2"
        (resp,) = h2["dst"]["txfiles"]
        assert resp["sha256"] == hashlib.sha256(b"thanks").hexdigest() and resp["name"] is None

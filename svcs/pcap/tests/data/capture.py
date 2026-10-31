"""Record the real traffic captures in this directory, used by the tshark tests.

The tshark tests need traffic that real clients and servers produced, so these captures are
recorded on the loopback interface and committed. Re-record them with (as root, on Linux):

    apt-get install tshark openssh-server openssh-client openssl curl
    python3 -m venv /tmp/capvenv && /tmp/capvenv/bin/pip install pyftpdlib aiosmtpd
    /tmp/capvenv/bin/python tests/data/capture.py

Each scenario starts its server(s), captures the loopback interface with dumpcap while a client
talks to them, and writes ``<scenario>.pcapng``. The files transferred in the captures are
deterministic, so the tests can check their hashes; keys and certificates are generated per run.
"""


import email.message
import ftplib
import http.server
import os
import pathlib
import shutil
import smtplib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


HERE = pathlib.Path(__file__).parent

DOWNLOAD = bytes(range(256)) * 64
"""The file the HTTP and FTP servers send (16 KiB, so it spans several segments)."""
UPLOAD = b"uploaded file contents\n" * 100
"""The file the HTTP and FTP clients send."""
ATTACHMENT = b"%PDF-1.4 not really a pdf\n" * 20
"""The file attached to the email."""


def waitPort(port: int, timeout: float = 10) -> None:
    """Wait for a TCP port on localhost to accept connections."""

    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"Port {port} never opened")


class Capture:
    """Capture the loopback interface into a file while the block runs."""

    def __init__(self, name: str, bpf: str) -> None:
        self.path = HERE / f"{name}.pcapng"
        self.bpf = bpf

    def __enter__(self):
        self.path.unlink(missing_ok=True)
        self.proc = subprocess.Popen(
            ["dumpcap", "-q", "-i", "lo", "-f", self.bpf, "-w", str(self.path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(1.5)
        return self

    def __exit__(self, *args) -> None:
        time.sleep(1.5)
        self.proc.terminate()
        self.proc.wait()
        os.chmod(self.path, 0o644)
        print(f"wrote {self.path.name}", file=sys.stderr)


class Handler(http.server.BaseHTTPRequestHandler):
    """Serves DOWNLOAD for GET and accepts POSTed uploads."""

    server_version = "nginx/1.24.0"
    sys_version = ""

    def log_message(self, *args) -> None:
        pass

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(DOWNLOAD)))
        self.end_headers()
        self.wfile.write(DOWNLOAD)

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers["Content-Length"]))
        body = b"thanks"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def scenario_http(tmp: pathlib.Path) -> None:
    """An HTTP download (GET) and upload (POST) with curl."""

    srv = http.server.HTTPServer(("127.0.0.1", 80), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    upload = tmp / "upload.txt"
    upload.write_bytes(UPLOAD)
    with Capture("http", "tcp port 80"):
        subprocess.run(["curl", "-s", "-o", "/dev/null", "-A", "curl/8.5.0",
                        "http://127.0.0.1:80/files/sample.bin"], check=True)
        subprocess.run(["curl", "-s", "-o", "/dev/null", "-A", "curl/8.5.0",
                        "-H", "Content-Type: text/plain", "--data-binary", f"@{upload}",
                        "http://127.0.0.1:80/upload/report.txt"], check=True)
    srv.shutdown()


def scenario_tls(tmp: pathlib.Path) -> None:
    """A TLS 1.2 session (certificates are only cleartext before TLS 1.3) with a client cert."""

    def mkcert(name: str, cn: str) -> None:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                        "ec_paramgen_curve:prime256v1", "-nodes", "-days", "3650",
                        "-subj", f"/O=Test/CN={cn}", "-addext", f"subjectAltName=DNS:{cn}",
                        "-keyout", str(tmp / f"{name}.key"), "-out", str(tmp / f"{name}.pem")],
                       check=True, capture_output=True)

    mkcert("server", "vertex.link")
    mkcert("client", "client.vertex.link")
    server = subprocess.Popen(
        ["openssl", "s_server", "-quiet", "-accept", "443", "-tls1_2",
         "-cert", str(tmp / "server.pem"), "-key", str(tmp / "server.key"),
         "-Verify", "1", "-CAfile", str(tmp / "client.pem")],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    waitPort(443)
    with Capture("tls", "tcp port 443"):
        subprocess.run(["openssl", "s_client", "-quiet", "-no_ign_eof", "-connect", "127.0.0.1:443",
                        "-tls1_2", "-servername", "vertex.link",
                        "-cert", str(tmp / "client.pem"), "-key", str(tmp / "client.key")],
                       input=b"hello\n", capture_output=True, timeout=10)
    server.kill()


def scenario_tls13(tmp: pathlib.Path) -> None:
    """HTTPS over TLS 1.3 (HTTP/1.1 then HTTP/2), with the client's TLS key log.

    Writes ``tls13.keylog`` (the NSS key log curl wrote) next to the capture, everything in
    the connections (certificates included) is only readable with it.
    """

    import asyncio

    from hypercorn.asyncio import serve
    from hypercorn.config import Config

    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:prime256v1", "-nodes", "-days", "3650",
                    "-subj", "/O=Test/CN=secure.vertex.link",
                    "-addext", "subjectAltName=DNS:secure.vertex.link",
                    "-keyout", str(tmp / "key.pem"), "-out", str(tmp / "cert.pem")],
                   check=True, capture_output=True)

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        body = b""
        while True:
            event = await receive()
            body += event.get("body", b"")
            if not event.get("more_body"):
                break
        resp = DOWNLOAD if scope["method"] == "GET" else b"thanks"
        await send({"type": "http.response.start", "status": 200, "headers": [
            (b"content-type", b"application/octet-stream"), (b"server", b"hypercorn-h11"),
            (b"content-length", str(len(resp)).encode())]})
        await send({"type": "http.response.body", "body": resp})

    config = Config()
    config.bind = ["127.0.0.1:443"]
    config.certfile, config.keyfile = str(tmp / "cert.pem"), str(tmp / "key.pem")
    config.alpn_protocols = ["h2", "http/1.1"]
    config.include_server_header = False
    loop = asyncio.new_event_loop()
    stop = asyncio.Event()
    thread = threading.Thread(target=loop.run_until_complete,
                              args=(serve(app, config, shutdown_trigger=stop.wait),), daemon=True)
    thread.start()
    waitPort(443)

    keylog = HERE / "tls13.keylog"
    keylog.unlink(missing_ok=True)
    env = {**os.environ, "SSLKEYLOGFILE": str(keylog)}
    upload = tmp / "upload.txt"
    upload.write_bytes(UPLOAD)
    url = "https://secure.vertex.link/files/sample.bin"
    resolve = ["--noproxy", "*", "--resolve", "secure.vertex.link:443:127.0.0.1", "-k", "-s",
               "-o", "/dev/null",
               "--tlsv1.3", "-A", "curl/8.5.0"]
    with Capture("tls13", "tcp port 443"):
        subprocess.run(["curl", *resolve, "--http1.1", url], check=True, env=env)
        subprocess.run(["curl", *resolve, "--http2", "--data-binary", f"@{upload}",
                        "https://secure.vertex.link/upload/report.txt"], check=True, env=env)
    loop.call_soon_threadsafe(stop.set)
    thread.join(5)
    os.chmod(keylog, 0o644)


def scenario_ssh(tmp: pathlib.Path) -> None:
    """An SSH key exchange (authentication fails, the host key is sent before that)."""

    key = tmp / "host_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    os.makedirs("/run/sshd", exist_ok=True)
    server = subprocess.Popen(
        ["/usr/sbin/sshd", "-D", "-p", "22", "-h", str(key), "-o", "ListenAddress=127.0.0.1",
         "-o", f"PidFile={tmp / 'sshd.pid'}", "-o", "PasswordAuthentication=no",
         "-o", "KbdInteractiveAuthentication=no"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    waitPort(22)
    with Capture("ssh", "tcp port 22"):
        subprocess.run(["ssh", "-p", "22", "-o", "BatchMode=yes",
                        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                        "-o", "HostKeyAlgorithms=ssh-ed25519", "nobody@127.0.0.1", "true"],
                       capture_output=True, timeout=20)
    server.kill()


def scenario_ftp(tmp: pathlib.Path) -> None:
    """An FTP download (RETR) and upload (STOR), in passive mode."""

    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer

    root = tmp / "ftproot"
    root.mkdir()
    (root / "sample.bin").write_bytes(DOWNLOAD)
    auth = DummyAuthorizer()
    auth.add_anonymous(str(root), perm="elrw")
    handler = FTPHandler
    handler.authorizer = auth
    handler.banner = "pyftpdlib ready."
    handler.passive_ports = range(40000, 40010)
    srv = FTPServer(("127.0.0.1", 21), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    waitPort(21)
    with Capture("ftp", "tcp port 21 or tcp portrange 40000-40009"):
        client = ftplib.FTP()
        client.connect("127.0.0.1", 21)
        client.login()
        client.retrbinary("RETR sample.bin", lambda _: None)
        with open(tmp / "upload.bin", "wb") as fd:
            fd.write(UPLOAD)
        with open(tmp / "upload.bin", "rb") as fd:
            client.storbinary("STOR report.txt", fd)
        client.quit()
    srv.close_all()


def scenario_smtp(tmp: pathlib.Path) -> None:
    """An email with an attachment sent over SMTP."""

    from aiosmtpd.controller import Controller

    class Sink:
        async def handle_DATA(self, server, session, envelope):
            return "250 OK"

    ctrl = Controller(Sink(), hostname="127.0.0.1", port=25)
    ctrl.start()
    msg = email.message.EmailMessage()
    msg["From"] = "alice@vertex.link"
    msg["To"] = "bob@vertex.link"
    msg["Subject"] = "the report"
    msg["User-Agent"] = "Thunderbird/115.6.0"
    msg.set_content("See attached.\n")
    msg.add_attachment(ATTACHMENT, maintype="application", subtype="pdf",
                       filename="report.pdf")
    with Capture("smtp", "tcp port 25"):
        with smtplib.SMTP("127.0.0.1", 25) as client:
            client.send_message(msg)
    ctrl.stop()


def _per(n: int) -> bytes:
    """A PER encoded length."""

    return bytes([n]) if n < 0x80 else struct.pack(">H", 0x8000 | n)


def _ber(tag: bytes, body: bytes) -> bytes:
    """A BER TLV with a long form length."""

    return tag + b"\x82" + struct.pack(">H", len(body)) + body


def rdpConnectInitial(name: str, layout: int) -> bytes:
    """An RDP client's X.224 Data + MCS Connect-Initial with Client Core Data ([MS-RDPBCGR]).

    This is what a client sends right after the X.224 negotiation when standard RDP security
    (no TLS/CredSSP) is used, so its client name and keyboard layout are in cleartext.
    """

    core = struct.pack("<IHHHHII", 0x00080004, 1280, 1024, 0xCA01, 0xAA03, layout, 19041)
    core += name.encode("utf-16-le").ljust(32, b"\x00")[:32]
    core += struct.pack("<III", 4, 0, 12) + b"\x00" * 64
    core += struct.pack("<HHI", 0xCA01, 1, 0) + struct.pack("<HHH", 0x18, 0x07, 0x0001)
    core += b"\x00" * 64 + b"\x00\x00" + struct.pack("<I", 0)
    core = struct.pack("<HH", 0xC001, len(core) + 4) + core
    security = struct.pack("<HHII", 0xC002, 12, 0x1B, 0)
    userdata = core + security

    # GCC Conference Create Request (T.124), wrapped in a ConnectData PDU.
    gcc = b"\x00\x08\x00\x10\x00\x01\xc0\x00\x44\x75\x63\x61" + _per(len(userdata)) + userdata
    connectdata = b"\x00\x05\x00\x14\x7c\x00\x01" + _per(len(gcc)) + gcc

    def domainParams(a, b, c, d, e, f, g, h) -> bytes:
        body = b"".join(b"\x02\x02" + struct.pack(">H", v) for v in (a, b, c, d, e, f, g, h))
        return b"\x30" + bytes([len(body)]) + body

    mcs = (
        b"\x04\x01\x01" + b"\x04\x01\x01" + b"\x01\x01\xff"
        + domainParams(34, 2, 0, 1, 0, 1, 0xFFFF, 2)
        + domainParams(1, 1, 1, 1, 0, 1, 0x420, 2)
        + domainParams(0xFFFF, 0xFC17, 0xFFFF, 1, 0, 1, 0xFFFF, 2)
        + _ber(b"\x04", connectdata)
    )
    mcs = _ber(b"\x7f\x65", mcs)
    x224 = b"\x02\xf0\x80" + mcs
    return struct.pack(">BBH", 3, 0, len(x224) + 4) + x224


def scenario_rdp(tmp: pathlib.Path) -> None:
    """An RDP client connection using standard RDP security, up to its MCS Connect-Initial."""

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 3389))
    srv.listen(1)

    def serve() -> None:
        conn, _ = srv.accept()
        conn.recv(4096)
        # X.224 Connection Confirm selecting standard RDP security (PROTOCOL_RDP).
        neg = struct.pack("<BBHI", 2, 0, 8, 0)
        cc = b"\xd0\x00\x00\x12\x34\x00" + neg
        conn.sendall(struct.pack(">BBH", 3, 0, len(cc) + 5) + bytes([len(cc)]) + cc)
        conn.recv(65535)
        conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    with Capture("rdp", "tcp port 3389"):
        client = socket.create_connection(("127.0.0.1", 3389))
        cookie = b"Cookie: mstshash=analyst\r\n"
        neg = struct.pack("<BBHI", 1, 0, 8, 0)
        cr = b"\xe0\x00\x00\x00\x00\x00" + cookie + neg
        client.sendall(struct.pack(">BBH", 3, 0, len(cr) + 5) + bytes([len(cr)]) + cr)
        client.recv(4096)
        client.sendall(rdpConnectInitial("WORKSTATION-7", 0x00000409))
        thread.join(5)
        client.close()
    srv.close()


SCENARIOS = {
    name.removeprefix("scenario_"): func
    for name, func in globals().copy().items() if name.startswith("scenario_")
}


def main(names: list[str]) -> None:
    for name in names or SCENARIOS:
        tmp = pathlib.Path(tempfile.mkdtemp())
        try:
            SCENARIOS[name](tmp)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main(sys.argv[1:])

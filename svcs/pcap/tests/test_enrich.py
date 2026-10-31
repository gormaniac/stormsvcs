"""Pytests for pcapsvc.enrich and pcapsvc.x509, with hand built tshark records (no tshark)."""


import base64
import datetime
import hashlib
import io

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from pcapsvc import enrich as p_enrich
from pcapsvc import flows as p_flows
from pcapsvc import x509 as p_x509

from . import pcapgen as g


def mkcert(cn: str = "vertex.link", key=None, serial: int = 0x1234, sans=None,
           issuer: str | None = None) -> bytes:
    """A DER certificate."""

    key = key or ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer or cn)]))
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
    )
    if sans is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def sshString(valu: bytes) -> bytes:
    return len(valu).to_bytes(4, "big") + valu


def apply(recs: list[tuple[bool, dict]], files=None) -> dict:
    """Run records through an Enricher and return the flow dict it produces."""

    flows, _ = p_flows.analyze(io.BytesIO(g.pcap([(0, g.eth(g.udp("10.0.0.1", 1, "10.0.0.2", 2)))])))
    enricher = p_enrich.Enricher(files)
    for client, rec in recs:
        enricher.add(client, rec)
    return enricher.apply(flows[0])


class TestX509:

    def test_parse(self):
        import ipaddress

        sans = [
            x509.DNSName("*.vertex.link"), x509.DNSName("vertex.link"),
            x509.RFC822Name("Visi@Vertex.link"), x509.UniformResourceIdentifier("https://vertex.link"),
            x509.IPAddress(ipaddress.ip_address("1.2.3.4")),
            x509.IPAddress(ipaddress.ip_address("::1")),
            x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dir")])),
            x509.RegisteredID(x509.ObjectIdentifier("1.2.3")),
            x509.OtherName(x509.ObjectIdentifier("1.2.4"), b"\x04\x01x"),
        ]
        der = mkcert(cn="www.vertex.link", sans=sans, serial=0xABC)
        cert = p_x509.parseCert(der)
        assert cert["error"] is None
        assert cert["sha256"] == hashlib.sha256(der).hexdigest()
        assert cert["size"] == len(der)
        assert cert["serial"] == "0abc"
        assert cert["version"] == 2
        assert cert["subject"] == "CN=www.vertex.link"
        assert cert["selfsigned"] is True
        assert cert["notbefore"] == 1767225600000
        assert cert["algo"] == "1.2.840.10045.4.3.2"
        assert ("dns", "*.vertex.link") in cert["sans"]
        assert ("dirname", "CN=dir") in cert["sans"]
        assert ("registeredid", "1.2.3") in cert["sans"]
        assert ("othername", "1.2.4:040178") in cert["sans"]
        assert cert["identities"] == {
            "fqdns": ["vertex.link", "www.vertex.link"],
            "emails": ["visi@vertex.link"],
            "ipv4s": ["1.2.3.4"],
            "ipv6s": ["::1"],
            "urls": ["https://vertex.link"],
        }
        assert cert["pubkey"]["algo"] == "ec"

        rsakey = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        cert = p_x509.parseCert(mkcert(cn="1.2.3.4", key=rsakey, issuer="Some CA"))
        assert cert["pubkey"]["rsa"]["exp"] == 65537
        assert cert["selfsigned"] is False
        assert cert["identities"]["ipv4s"] == ["1.2.3.4"]
        assert cert["sans"] == []

        cert = p_x509.parseCert(mkcert(cn="admin@vertex.link"))
        assert cert["identities"]["emails"] == ["admin@vertex.link"]

    def test_bad_cert(self):
        cert = p_x509.parseCert(b"not a cert")
        assert cert["sha256"] == hashlib.sha256(b"not a cert").hexdigest()
        assert cert["error"].startswith("Unable to parse the certificate")
        assert "subject" not in cert

    def test_helpers(self):
        assert p_x509.serialHex(1) == "01"
        assert p_x509.serialHex(0x100) == "0100"
        assert p_x509.serialHex(-1) == "ff"
        naive = datetime.datetime(2026, 1, 1)
        assert p_x509.toMillis(naive) == 1767225600000


class TestEnrich:

    def test_tls(self):
        leaf, ca = mkcert("vertex.link", issuer="CA"), mkcert("CA")
        flow = apply([
            (True, {"tls.handshake.extensions_server_name": ["Vertex.Link"],
                    "tls.handshake.ja3": ["aaa"], "tls.handshake.ja4": ["t13d"]}),
            (False, {"tls.handshake.certificate": [leaf.hex(), ca.hex()],
                     "tls.handshake.ja3s": ["bbb"]}),
            # Only the first certificate message counts.
            (False, {"tls.handshake.certificate": [ca.hex()]}),
            (True, {"tls.handshake.certificate": [ca.hex()]}),
        ])
        assert flow["tls"] == {"sni": ["vertex.link"], "ja3": ["aaa"], "ja3s": ["bbb"],
                               "ja4": ["t13d"]}
        assert flow["dst"]["ssl:cert"]["sha256"] == hashlib.sha256(leaf).hexdigest()
        assert [c["sha256"] for c in flow["dst"]["ssl:certs"]] == \
            [hashlib.sha256(leaf).hexdigest(), hashlib.sha256(ca).hexdigest()]
        assert flow["src"]["ssl:cert"]["subject"] == "CN=CA"
        assert flow["http"] is None

    def test_ssh_keys(self):
        def rec(ktype, **fields):
            r = {"ssh.host_key.type": [ktype]}
            for k, v in fields.items():
                r[f"ssh.host_key.{k.replace('_', '.')}"] = [v.hex()]
            return r

        ed = bytes(range(32))
        blob = sshString(b"ssh-ed25519") + sshString(ed)
        flow = apply([(False, {**rec("ssh-ed25519", eddsa_key=ed),
                               "ssh.host_key.length": [str(len(blob))]})])
        key = flow["dst"]["ssh:key"]
        assert key["algo"] == "ssh-ed25519"
        assert key["blob"] == blob.hex()
        assert key["sha256"] == hashlib.sha256(blob).hexdigest()
        # The blob is a real OpenSSH public key.
        serialization.load_ssh_public_key(b"ssh-ed25519 " + base64.b64encode(blob))

        rsakey = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        nums = rsakey.public_key().public_numbers()
        mpint = lambda i: i.to_bytes((i.bit_length() + 8) // 8, "big")
        blob = sshString(b"ssh-rsa") + sshString(mpint(nums.e)) + sshString(mpint(nums.n))
        assert p_enrich.sshKeyBlob(rec("ssh-rsa", rsa_e=mpint(nums.e), rsa_n=mpint(nums.n))) == blob
        serialization.load_ssh_public_key(b"ssh-rsa " + base64.b64encode(blob))

        eckey = ec.generate_private_key(ec.SECP256R1()).public_key()
        q = eckey.public_bytes(serialization.Encoding.X962,
                               serialization.PublicFormat.UncompressedPoint)
        r = rec("ecdsa-sha2-nistp256", ecdsa_q=q)
        r["ssh.host_key.ecdsa.id"] = ["nistp256"]
        blob = p_enrich.sshKeyBlob(r)
        serialization.load_ssh_public_key(b"ecdsa-sha2-nistp256 " + base64.b64encode(blob))

        dss = rec("ssh-dss", dsa_p=b"p", dsa_q=b"q", dsa_g=b"g", dsa_y=b"y")
        assert p_enrich.sshKeyBlob(dss) == b"".join(sshString(x) for x in (b"ssh-dss", b"p", b"q", b"g", b"y"))

        # Unknown types fall back to the key data, and incomplete or mismatched keys are skipped.
        assert p_enrich.sshKeyBlob(rec("ssh-foo", data=b"xyz")) == sshString(b"ssh-foo") + b"xyz"
        assert p_enrich.sshKeyBlob(rec("ssh-rsa", rsa_e=b"\x03")) is None
        assert p_enrich.sshKeyBlob({}) is None
        bad = {**rec("ssh-ed25519", eddsa_key=ed), "ssh.host_key.length": ["7"]}
        assert p_enrich.sshKeyBlob(bad) is None

    def test_software(self):
        flow = apply([
            (True, {"ssh.protocol": ["SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"],
                    "http.user_agent": ["curl/8.5.0", "curl/8.5.0"]}),
            (False, {"ssh.protocol": ["SSH-2.0-dropbear_2022.83", "not a banner"],
                     "http.server": ["Apache/2.4.58 (Ubuntu) "], "sip.Server": ["Asterisk PBX"]}),
            (False, {"http.server": ["Microsoft-IIS/10.0", "nginx/1.25.3", "lighttpd/1.4.73"]}),
            (True, {"imf.ext.mailer": ["Wget/1.21.4"], "gquic.tag.uaid": ["  "]}),
        ])
        assert flow["src"]["softnames"] == ["openssh_9.6p1 ubuntu-3ubuntu13", "curl/8.5.0",
                                            "wget/1.21.4"]
        assert flow["src"]["cpes"] == [
            "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*",
            "cpe:2.3:a:haxx:curl:8.5.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:gnu:wget:1.21.4:*:*:*:*:*:*:*",
        ]
        assert flow["dst"]["softnames"] == ["dropbear_2022.83", "apache/2.4.58 (ubuntu)",
                                            "asterisk pbx", "microsoft-iis/10.0", "nginx/1.25.3",
                                            "lighttpd/1.4.73"]
        assert flow["dst"]["cpes"] == [
            "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2022.83:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*",
            "cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*",
            "cpe:2.3:a:lighttpd:lighttpd:1.4.73:*:*:*:*:*:*:*",
        ]
        assert p_enrich.softCpes("openssh_9.6") == ["cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"]

    def test_rdp(self):
        flow = apply([(True, {"rdp.client.name": [" WORKSTATION-7 "], "rdp.keyboardLayout": ["1031"]})])
        assert flow["src"]["rdp:hostname"] == "workstation-7"
        assert flow["src"]["rdp:keyboard:layout"] == "de_de"
        # Layouts that aren't a plain locale (ex. US Dvorak) are their KLID.
        assert p_enrich.keyboardLayout(0x00010409) == "00010409"
        assert p_enrich.keyboardLayout(0x0000FFFF) == "0000ffff"

    def test_http(self, tmp_path):
        files = p_enrich.FileStore(str(tmp_path))
        multipart = (
            b"--XYZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n"
            b"--XYZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"C:\\\\evil.exe\"\r\n"
            b"Content-Type: application/x-msdownload\r\n\r\nMZ\x90\x00\r\n--XYZ--\r\n"
        )
        flow = apply([
            (True, {"http.request.method": ["GET"], "http.request.uri": ["/a/b/payload.bin?x=1"],
                    "http.host": ["Vertex.Link"]}),
            (False, {"http.response_for.uri": ["http://vertex.link/a/b/payload.bin?x=1"],
                     "http.file_data": [b"payload".hex()],
                     "http.content_type": ["application/octet-stream; charset=x"]}),
            (True, {"http.request.method": ["POST"], "http.request.uri": ["/upload"],
                    "http.file_data": [multipart.hex()],
                    "http.content_type": ["multipart/form-data; boundary=XYZ"]}),
            # The POST's response isn't the file at its URI.
            (False, {"http.response_for.uri": ["http://vertex.link/upload"],
                     "http.file_data": [b"ok".hex()], "http.content_type": ["text/plain"]}),
            (True, {"http.request.method": ["GET"], "http.request.uri": ["/"]}),
            (False, {"http.response_for.uri": ["http://vertex.link/"]}),  # No body.
            (True, {"http.request.method": ["GET"], "http.request.uri": ["/again"]}),
            (False, {"http.response_for.uri": ["http://vertex.link/again"],
                     "http.file_data": [b"again".hex()]}),
        ], files=files)
        assert flow["http"]["hosts"] == ["vertex.link"]
        assert [r["method"] for r in flow["http"]["requests"]] == ["GET", "POST", "GET", "GET"]

        dst = {f["name"]: f for f in flow["dst"]["txfiles"]}
        assert dst["payload.bin"]["mime"] == "application/octet-stream"
        assert dst["payload.bin"]["sha256"] == hashlib.sha256(b"payload").hexdigest()
        assert dst[None]["sha256"] == hashlib.sha256(b"ok").hexdigest()
        assert dst["again"]["proto"] == "http"
        assert (tmp_path / hashlib.sha256(b"payload").hexdigest()).read_bytes() == b"payload"

        # Multipart uploads are split into their files.
        src = flow["src"]["txfiles"]
        assert len(src) == 1
        assert src[0]["name"] == "C:\\evil.exe"
        assert src[0]["mime"] == "application/x-msdownload"
        assert src[0]["sha256"] == hashlib.sha256(b"MZ\x90\x00").hexdigest()

        # A multipart body with no files is kept whole.
        flow = apply([(True, {"http.request.method": ["POST"], "http.request.uri": ["/f"],
                              "http.file_data": [b"--B\r\n\r\nx\r\n--B--".hex()],
                              "http.content_type": ["multipart/form-data; boundary=B"]})],
                     files=p_enrich.FileStore(str(tmp_path)))
        assert flow["src"]["txfiles"][0]["name"] == "f"
        assert p_enrich.uriName(None) is None and p_enrich.uriName("/dir/") is None
        assert p_enrich.uriName("/a%20b.txt") == "a b.txt"
        assert p_enrich.mimeType(None) is None and p_enrich.mimeType(";x") is None

    def test_ftp(self, tmp_path):
        files = p_enrich.FileStore(str(tmp_path))

        def seg(seq, data, cmd="RETR dir/sample.bin"):
            return {"ftp-data.command": [cmd], "tcp.seq": [str(seq)], "tcp.payload": [data.hex()]}

        flow = apply([
            (False, seg(1, b"hello ")),
            (False, seg(7, b"world")),
            (False, seg(4, b"lo wor")),  # Overlapping retransmission.
            (False, seg(1, b"HELLO ")),  # Duplicate, the first copy wins.
            (True, seg(1, b"x", cmd="LIST")),  # Directory listings aren't files.
            (True, {"ftp-data.command": ["RETR x"]}),  # No payload.
        ], files=files)
        assert flow["dst"]["txfiles"] == [{
            "sha256": hashlib.sha256(b"hello world").hexdigest(), "size": 11, "name": "sample.bin",
            "mime": None, "text": None, "proto": "ftp", "complete": True,
        }]
        assert flow["src"]["txfiles"] == []

        flow = apply([(True, seg(1, b"abc", cmd="STOR up.txt")),
                      (True, seg(10, b"xyz", cmd="STOR up.txt"))], files=files)
        assert flow["src"]["txfiles"][0]["complete"] is False
        assert flow["src"]["txfiles"][0]["size"] == 6

    def test_email(self, tmp_path):
        files = p_enrich.FileStore(str(tmp_path))
        raw = (
            b"From: a@vertex.link\r\nSubject: hi\r\nMIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain"
            b"\r\n\r\nbody\r\n--B\r\nContent-Type: application/pdf\r\nContent-Disposition: "
            b"attachment; filename=\"../r.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            + base64.b64encode(b"%PDF") + b"\r\n--B--\r\n"
        )
        flow = apply([(True, {"imf.raw": [raw.hex()], "imf.user_agent": ["Thunderbird/115.6.0"]})],
                     files=files)
        msg, att = flow["src"]["txfiles"]
        assert msg["mime"] == "message/rfc822" and msg["text"] == "hi" and msg["name"] is None
        assert msg["sha256"] == hashlib.sha256(raw).hexdigest()
        assert att["name"] == "r.pdf" and att["mime"] == "application/pdf"
        assert att["sha256"] == hashlib.sha256(b"%PDF").hexdigest()
        assert flow["src"]["cpes"] == ["cpe:2.3:a:mozilla:thunderbird:115.6.0:*:*:*:*:*:*:*"]

        # Without a subject there's no text.
        flow = apply([(True, {"imf.raw": [b"From: a@b\r\n\r\nx".hex()]})], files=files)
        assert flow["src"]["txfiles"][0]["text"] is None

    def test_no_files(self):
        # Without a FileStore files aren't extracted, but everything else is.
        der = mkcert()
        flow = apply([(False, {"tls.handshake.certificate": [der.hex()],
                               "http.response_for.uri": ["/x"], "http.file_data": ["00"]})])
        assert flow["dst"]["ssl:cert"]["sha256"] == hashlib.sha256(der).hexdigest()
        assert flow["dst"]["txfiles"] == []

    def test_filestore(self, tmp_path):
        store = p_enrich.FileStore(str(tmp_path), maxsize=5, limit=2)
        assert store.add(b"123456") is None
        a = store.add(b"a")
        assert a == hashlib.sha256(b"a").hexdigest()
        assert store.add(b"a") == a  # Duplicates don't count against the limit.
        assert store.add(b"b") is not None
        assert store.add(b"c") is None
        assert store.skipped == 2
        assert store.files == {a: 1, hashlib.sha256(b"b").hexdigest(): 1}
        assert open(store.path(a), "rb").read() == b"a"

        # Files over the limits are left out of the flow.
        flow = apply([(False, {"http.response_for.uri": ["/x"],
                               "http.file_data": [b"123456".hex()]})], files=store)
        assert flow["dst"]["txfiles"] == []

    def test_empty(self):
        flow = apply([])
        assert flow["tls"] is None and flow["http"] is None
        assert {k: flow["src"][k] for k in p_enrich.emptySide()} == p_enrich.emptySide()

    @pytest.mark.parametrize("banner,soft", [
        ("SSH-2.0-OpenSSH_9.6", "OpenSSH_9.6"), ("SSH-1.99-Cisco-1.25", "Cisco-1.25"),
        ("garbage", None), ("HTTP-1.1-x", None),
    ])
    def test_sshSoftware(self, banner, soft):
        assert p_enrich.sshSoftware(banner) == soft

"""Pytests for pcapsvc.eve with recorded style EVE lines (no Suricata needed)."""


import base64
import hashlib
import io

from pcapsvc import enrich as p_enrich
from pcapsvc import eve as p_eve
from pcapsvc import flows as p_flows

from . import pcapgen as g
from .test_enrich import mkcert

CLIENT = {"src_ip": "10.0.0.1", "src_port": 50000, "dest_ip": "93.184.216.34", "dest_port": 80}
SERVER = {"src_ip": "93.184.216.34", "src_port": 80, "dest_ip": "10.0.0.1", "dest_port": 50000}
TS = "2023-11-14T22:13:20.100000+0000"


def baseFlow() -> dict:
    """The HTTP flow of pcapgen.session (10.0.0.1:50000 -> 93.184.216.34:80)."""

    flows, _ = p_flows.analyze(io.BytesIO(g.pcap(g.session())))
    return flows[0]


def run(events, files=None, filestore=None, rules=None, recs=(), counts=None) -> dict:
    """Run EVE events (and tshark records) through an Enricher, return the flow dict."""

    enr = p_enrich.Enricher(files, rules=rules, counts=counts, filestore=filestore)
    for client, rec in recs:
        enr.add(client, rec)
    enr.eve.extend(events)
    return enr.apply(baseFlow())


def ev(etype, body=None, side=CLIENT, **extra) -> dict:
    return {"timestamp": TS, "event_type": etype, **side, **({etype: body} if body else {}),
            **extra}


class TestApplyEve:

    def test_tls_chain(self):
        leaf, inter = mkcert("vertex.link", issuer="ca"), mkcert("ca")
        flow = run([ev("tls", {
            "sni": "Vertex.Link", "version": "TLS 1.2", "ja3": {"hash": "j3"},
            "ja3s": {"hash": "j3s"}, "ja4": "j4",
            "chain": [base64.b64encode(leaf).decode(), base64.b64encode(inter).decode(), "!!"],
        })])
        assert flow["tls"]["sni"] == ["vertex.link"]
        assert flow["tls"]["ja3"] == ["j3"] and flow["tls"]["ja3s"] == ["j3s"]
        assert flow["tls"]["ja4"] == ["j4"] and flow["tls"]["versions"] == ["TLS 1.2"]
        dst = flow["dst"]
        assert dst["ssl:cert"]["sha256"] == hashlib.sha256(leaf).hexdigest()
        assert [c["sha256"] for c in dst["ssl:certs"]] == [
            hashlib.sha256(leaf).hexdigest(), hashlib.sha256(inter).hexdigest()
        ]
        # Without a FileStore, the certs' bytes aren't saved.
        assert dst["ssl:cert"]["stored"] is False

    def test_dns(self):
        flow = run([
            ev("dns", {"type": "query", "id": 7, "rrname": "Vertex.Link", "rrtype": "A"}),
            ev("dns", {"type": "answer", "id": 7, "rrname": "vertex.link", "rrtype": "A",
                       "rcode": "NOERROR", "answers": [
                           {"rrname": "vertex.link", "rrtype": "A", "ttl": 60, "rdata": "1.2.3.4"},
                           {"rrname": "vertex.link", "rrtype": "A", "ttl": 60, "rdata": "5.6.7.8"},
                       ]}, side=SERVER),
        ])
        (query,) = flow["dns"]
        assert query["rrname"] == "vertex.link" and query["rcode"] == 0
        assert [a["rdata"] for a in query["answers"]] == ["1.2.3.4", "5.6.7.8"]
        assert query["time"] == p_eve.eveTime(TS)

    def test_http_fileinfo(self, tmp_path):
        store = p_enrich.FileStore(str(tmp_path / "files"))
        (tmp_path / "files").mkdir()
        body = b"hello file"
        sha = hashlib.sha256(body).hexdigest()
        fstore = tmp_path / "filestore"
        (fstore / sha[:2]).mkdir(parents=True)
        (fstore / sha[:2] / sha).write_bytes(body)

        flow = run([
            ev("http", {"hostname": "Vertex.Link", "url": "/a/b.txt", "http_method": "GET",
                        "status": 200, "http_user_agent": "curl/8.0",
                        "response_headers": [{"name": "Content-Type", "value": "text/plain"},
                                             {"name": "Server", "value": "nginx/1.25"}]},
               tx_id=0),
            ev("fileinfo", {"sha256": sha, "stored": True, "state": "CLOSED", "size": len(body),
                            "tx_id": 0, "filename": "/a/b.txt"}, side=SERVER, app_proto="http"),
        ], files=store, filestore=str(fstore))
        assert flow["http"]["hosts"] == ["vertex.link"]
        assert flow["http"]["requests"] == [{"method": "GET", "uri": "/a/b.txt", "status": 200}]
        assert "curl/8.0" in flow["src"]["softnames"]
        assert "nginx/1.25" in flow["dst"]["softnames"]
        (txfile,) = flow["dst"]["txfiles"]
        assert txfile["sha256"] == sha and txfile["name"] == "b.txt"
        assert txfile["mime"] == "text/plain" and txfile["proto"] == "http"
        assert store.files == {sha: len(body)}

    def test_http_dedup(self):
        # With a key log tshark sees cleartext HTTP too, Suricata's copy of a request is merged
        # into tshark's (adding its status), and requests the flow repeats are kept.
        recs = [(True, {"http.request.method": ["GET", "GET"], "http.request.uri": ["/", "/"]}),
                (True, {"http.request.method": ["POST"], "http.request.uri": ["/up"]})]
        events = [ev("http", {"url": "/", "http_method": "GET", "status": 200}, tx_id=0),
                  ev("http", {"url": "/", "http_method": "GET", "status": 304}, tx_id=1),
                  ev("http", {"url": "/x", "http_method": "GET", "status": 404}, tx_id=2)]
        flow = run(events, recs=recs)
        assert flow["http"]["requests"] == [
            {"method": "GET", "uri": "/", "status": 200},
            {"method": "GET", "uri": "/", "status": 304},
            {"method": "POST", "uri": "/up"},
            {"method": "GET", "uri": "/x", "status": 404},
        ]

    def test_smb_krb5(self):
        flow = run([
            ev("smb", {"command": "SMB2_COMMAND_TREE_CONNECT", "status": "STATUS_SUCCESS",
                       "share": "\\\\srv\\c$", "dialect": "", "ntlmssp": {"user": "visi"},
                       "request": {"native_os": "Windows 10"}}),
            ev("krb5", {"msg_type": "KRB_AS_REQ", "cname": "visi", "realm": "VERTEX.LINK",
                        "sname": "<empty>", "encryption": "aes256", "weak_encryption": False}),
        ])
        (smb,) = flow["smb"]
        assert smb["share"] == "\\\\srv\\c$" and "dialect" not in smb
        assert smb["ntlmssp"] == {"user": "visi"}
        assert smb["native"]["request"] == {"native_os": "Windows 10"}
        (krb,) = flow["krb5"]
        assert krb["cname"] == "visi" and "sname" not in krb
        assert krb["weak_encryption"] is False

    def test_alerts(self):
        guid = "a" * 32
        rules = {"suricata": {"1:2000": {"guid": guid, "rev": 3}}}
        counts = {}
        alert = {"timestamp": TS, "alert": {"gid": 1, "signature_id": 2000, "rev": 4,
                                             "signature": "ET TEST", "action": "allowed"}}
        enr = p_enrich.Enricher(None, rules=rules, counts=counts)
        enr.alerts.extend([
            ("suricata", alert),
            ("suricata", {**alert, "timestamp": "2023-11-14T22:13:21.000000+0000"}),
            ("suricata", {"alert": {"gid": 1, "signature_id": 9}}),
            ("suricata", {"alert": {"gid": 116, "signature_id": 1}}),
            ("suricata", {"alert": {"gid": 1, "signature_id": "nope"}}),
        ])
        flow = enr.apply(baseFlow())
        (hit,) = flow["hits"]
        assert hit["rule"] == guid and hit["rev"] == 4 and hit["count"] == 2
        assert hit["msg"] == "ET TEST" and hit["last"] - hit["time"] == 900
        assert counts["unknown"] == {"suricata:1:9": 1}
        assert counts["builtin"] == {"suricata:116:1": 1}
        assert counts["malformed"] == {"suricata:alert": 1}
        assert p_eve.alertKey("snort", {"gid": "1", "sid": "5", "rev": "2", "msg": "m"}) == \
            (1, 5, 2, "m", None)
        assert p_eve.alertTime("snort", {"seconds": 1700000000, "timestamp": "x.25"}) == \
            1700000000250

    def test_malformed(self):
        # Engine output is untrusted, a bad record is skipped and counted, not fatal.
        counts = {}
        flow = run([
            ev("http", {"url": "/ok", "http_method": "GET"}),
            ev("http", {"url": "/bad", "http_method": "GET", "hostname": "x",
                        "response_headers": [None]}),
            ev("fileinfo", {"sha256": "a" * 64, "stored": True, "size": 1}),
        ], recs=[(False, {"tls.handshake.certificate": ["not hex"]}),
                 (True, {"rdp.keyboardLayout": ["nope"]})], counts=counts)
        assert flow["http"]["requests"][0]["uri"] == "/ok"
        assert counts["malformed"] == {"suricata:http": 1, "tshark:frame": 2}

    def test_keyboard_layout(self):
        assert p_eve.keyboardLayout("en-US") == "en_us"
        assert p_eve.keyboardLayout("unknown") is None and p_eve.keyboardLayout(None) is None

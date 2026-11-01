"""Pytests for pcapsvc.suricata. The config tests run everywhere, the rest run Suricata."""

import os
import pathlib

import pytest
import yaml

from pcapsvc import flows as p_flows
from pcapsvc import sandbox as p_sandbox
from pcapsvc import suricata as p_suricata

from .engines import needs

DATA = pathlib.Path(__file__).parent / "data"

BASE = {
    "vars": {"address-groups": {"HOME_NET": "[10.0.0.0/8]"}},
    "outputs": [{"fast": {"enabled": True}}],
    "app-layer": {
        "protocols": {
            "tls": {"detection-ports": {"dp": 443}},
            "dns": {"tcp": {"detection-ports": {"dp": 53}}, "udp": {"detection-ports": {"dp": 53}}},
            "http": {"libhtp": {"default-config": {"request-body-limit": 100}}},
            "smtp": {"mime": {"decode-mime": False}},
            "ssh": "yes",
        }
    },
    "stream": {"reassembly": {"depth": "1mb"}},
}


def test_decode_ports():
    assert p_suricata.decodePorts(
        [
            "tcp.port==8443,tls",
            "tcp.port==8000-8010,http",
            "udp.port==5353,dns",
            "tcp.port==2222,ssh",
            # Not a port rule, or a protocol Suricata doesn't parse.
            "sctp.port==1,tls",
            "udp.port==5000,rtp",
        ]
    ) == {
        "tls": {"tcp": ["8443"]},
        "http": {"tcp": ["8000:8010"]},
        "dns": {"udp": ["5353"]},
        "ssh": {"tcp": ["2222"]},
    }


@pytest.fixture
def suri(tmp_path):
    base = tmp_path / "suricata.yaml"
    base.write_text(yaml.safe_dump(BASE))
    return p_suricata.Suricata(
        str(tmp_path / "work"),
        binpath="/nonexistent/suricata",
        conf=str(base),
        addrvars={"HOME_NET": "[192.168.0.0/16]"},
    )


def test_config(suri, tmp_path):
    out = str(tmp_path / "out")
    conf = suri.config(
        out, decode=["tcp.port==8443,tls", "udp.port==5353,dns", "tcp.port==2222,ssh"],
        filestore=True, maxbody=1000,
    )

    # The service's outputs replace the base's.
    eve = conf["outputs"][0]["eve-log"]
    assert eve["community-id"] is True and eve["community-id-seed"] == 0
    assert conf["outputs"][1]["file-store"]["enabled"] is True
    assert conf["default-log-dir"] == out
    assert conf["vars"]["address-groups"]["HOME_NET"] == "[192.168.0.0/16]"

    protos = conf["app-layer"]["protocols"]
    # Decode As rules add detection ports, to the transport for parsers that have them.
    assert protos["tls"]["detection-ports"]["dp"] == "443, 8443"
    assert protos["dns"]["udp"]["detection-ports"]["dp"] == "53, 5353"
    assert protos["dns"]["tcp"]["detection-ports"]["dp"] == 53
    # A parser that was only "yes" becomes a dict.
    assert protos["ssh"]["enabled"] is True and protos["ssh"]["detection-ports"]["dp"] == "2222"
    assert protos["tls"]["ja3-fingerprints"] is True and protos["tls"]["ja4-fingerprints"] is True
    assert protos["smtp"]["mime"]["decode-mime"] is True

    # Bodies are cut off one byte over the limit (so a cut off file is over it), and whole
    # streams are reassembled.
    htp = protos["http"]["libhtp"]["default-config"]
    assert htp["request-body-limit"] == htp["response-body-limit"] == 1001
    assert conf["stream"]["reassembly"]["depth"] == 0

    assert suri.config(out, filestore=False)["outputs"][1]["file-store"]["enabled"] is False
    htp = suri.config(out, maxbody=0)["app-layer"]["protocols"]["http"]["libhtp"]
    assert htp["default-config"]["request-body-limit"] == 0

    # The base isn't changed.
    assert BASE["app-layer"]["protocols"]["tls"]["detection-ports"]["dp"] == 443
    assert suri.baseConfig()["outputs"] == [{"fast": {"enabled": True}}]


def test_netvars_overrides(tmp_path):
    base = tmp_path / "suricata.yaml"
    base.write_text(yaml.safe_dump(BASE))
    suri = p_suricata.Suricata(
        str(tmp_path / "work"),
        conf=str(base),
        addrvars={"HOME_NET": "[192.168.0.0/16]", "EXTERNAL_NET": "any"},
        overrides={"stream.memcap": "2gb", "detect.profile": "high", "outputs": "nope"},
    )
    conf = suri.config(str(tmp_path), netvars={"HOME_NET": "[10.9.0.0/16]", "DNS_SERVERS": "[10.9.0.53]"})
    assert conf["vars"]["address-groups"] == {
        "HOME_NET": "[10.9.0.0/16]", "EXTERNAL_NET": "any", "DNS_SERVERS": "[10.9.0.53]",
    }
    # The operator's overrides win, even over the service's settings.
    assert conf["stream"]["memcap"] == "2gb" and conf["detect"]["profile"] == "high"
    assert conf["outputs"] == "nope"
    # Without run variables the service's config is used.
    assert suri.config(str(tmp_path))["vars"]["address-groups"]["HOME_NET"] == "[192.168.0.0/16]"

    with pytest.raises(p_suricata.SuricataError, match="isn't a mapping"):
        p_suricata.setPath({"a": 1}, "a.b", 2)
    with pytest.raises(p_suricata.SuricataError, match="Invalid suricata:set key"):
        p_suricata.setPath({}, "..", 2)


def test_bad_base(tmp_path):
    suri = p_suricata.Suricata(str(tmp_path / "work"), conf=str(tmp_path / "nope.yaml"))
    with pytest.raises(p_suricata.SuricataError, match="Unable to read the base Suricata config"):
        suri.config(str(tmp_path))


def test_from_client():
    from pcapsvc import eve as p_eve

    # Suricata writes IPv6 addresses fully expanded.
    flow = {"src": {"ip": "2001:db8::1", "port": 50000}}
    ev = {"src_ip": "2001:0db8:0000:0000:0000:0000:0000:0001", "src_port": 50000}
    assert p_eve.fromClient(flow, ev)
    assert not p_eve.fromClient(flow, {**ev, "src_port": 80})
    assert not p_eve.fromClient(flow, {"src_ip": "nope", "src_port": 50000})
    assert p_eve.fromClient({"src": {"ip": "10.0.0.1", "port": None}}, {"src_ip": "10.0.0.1"})


def test_iter_eve(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text('{"event_type": "flow"}\n\nnot json\n{"event_type": "dns"}\n')
    assert [e["event_type"] for e in p_suricata.iterEve(str(path))] == ["flow", "dns"]
    assert list(p_suricata.iterEve(str(tmp_path / "missing.json"))) == []


@needs("suricata")
class TestSuricata:
    @pytest.fixture
    def suri(self, tmp_path):
        return p_suricata.Suricata(str(tmp_path / "work"), sandbox=p_sandbox.Sandbox())

    async def test_version(self, suri):
        assert suri.available()
        assert (await suri.version()).startswith("8.")

    async def test_validate(self, suri, tmp_path):
        rules = {
            "good": 'alert http any any -> any any (msg:"a"; http.uri; content:"/x"; sid:1;)',
            "bad": 'alert http any any -> any any (msg:"b"; http.nope; content:"x"; sid:2;)',
            "multi": 'alert tcp any any -> any any (msg:"c";\nsid:3;)',
            "good2": 'alert udp any any -> any 53 (msg:"d"; content:"x"; sid:4;)',
        }
        path = tmp_path / "rules"
        keys, errors = await suri.validate(rules, str(path))
        assert keys == ["good", "good2"]
        assert set(errors) == {"bad", "multi"}
        assert "http.nope" in errors["bad"] or "unknown" in errors["bad"].lower()
        assert errors["multi"] == "The rule must be a single line."
        assert path.read_text().splitlines() == [rules["good"], rules["good2"]]

        assert await suri.check(rules["good"]) is None
        assert await suri.check(rules["bad"])
        assert await suri.check("not a rule")

    async def test_run(self, suri, tmp_path):
        # Suricata's Community IDs are the flows' (so the loose matching agrees with it), and
        # its packet counts are frame numbers.
        for name in ("http", "dns", "quic", "krb5"):
            capture = str(DATA / f"{name}.pcapng")
            out = tmp_path / name
            out.mkdir()
            res = await suri.run(capture, str(out))
            events = list(p_suricata.iterEve(res["eve"]))
            assert events, name
            with open(capture, "rb") as fd:
                flows, summary = p_flows.analyze(fd)
            ids = {f["community_id"] for f in flows}
            seen = {e["community_id"] for e in events if e.get("community_id")}
            assert seen and seen <= ids, name
            nums = [e["pcap_cnt"] for e in events if e.get("pcap_cnt")]
            assert nums and max(nums) <= summary["packets"], name

        # Files are stored by SHA-256.
        (tmp_path / "http2").mkdir()
        res = await suri.run(str(DATA / "http.pcapng"), str(tmp_path / "http2"))
        stored = [
            e["fileinfo"]["sha256"]
            for e in p_suricata.iterEve(res["eve"])
            if e.get("event_type") == "fileinfo"
        ]
        assert len(stored) == 3
        for sha256 in stored:
            assert os.path.exists(os.path.join(res["filestore"], sha256[:2], sha256))

        with pytest.raises(p_suricata.SuricataError, match="failed to read the capture"):
            bad = tmp_path / "bad.pcap"
            bad.write_bytes(b"not a pcap at all")
            (tmp_path / "bad").mkdir()
            await suri.run(str(bad), str(tmp_path / "bad"))

"""Pytests for pcapsvc.feeds (no Snort needed)."""

import gzip
import io
import zipfile

import aiohttp
import pytest
from pcapsvc import feeds as s_feeds

from .fakefeeds import SNORT2_RULES, SNORT3_RULES, FakeFeeds, tarGz


def test_norm_feed():
    fdef = s_feeds.normFeed(
        {"name": "My-Feed", "url": "https://example.com/x.rules", "exclude": "*.bad"}
    )
    assert fdef == {
        "name": "my-feed",
        "url": "https://example.com/x.rules",
        "engine": "snort3",
        "enabled": True,
        "exclude": ["*.bad"],
        "desc": "",
    }
    assert s_feeds.normFeed({"name": "x", "url": "http://e.com", "engine": "2"})["engine"] == "snort2"
    assert s_feeds.normFeed({"name": "x", "url": "http://e.com", "engine": "Suricata"})["engine"] == \
        "suricata"

    with pytest.raises(s_feeds.FeedError, match="name"):
        s_feeds.normFeed({"name": "bad name", "url": "https://e.com"})
    with pytest.raises(s_feeds.FeedError, match="URL"):
        s_feeds.normFeed({"name": "x", "url": "ftp://e.com"})
    with pytest.raises(s_feeds.FeedError, match="engine"):
        s_feeds.normFeed({"name": "x", "url": "https://e.com", "engine": 1})
    with pytest.raises(s_feeds.FeedError, match="engine"):
        s_feeds.normFeed({"name": "x", "url": "https://e.com", "engine": "abc"})

    for fdef in s_feeds.DEFAULT_FEEDS:
        assert s_feeds.normFeed(fdef) == fdef


def test_unpack_formats():
    rules = {
        "a.rules": "alert tcp any any -> any any (sid:1;)",
        "b.txt": "nope",
        "dir/c.rules": "c",
    }

    tgz = tarGz(rules)
    assert sorted(n for n, _ in s_feeds.unpack(tgz)) == ["a.rules", "dir/c.rules"]
    assert [n for n, _ in s_feeds.unpack(tgz, exclude=["c.rules"])] == ["a.rules"]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zfd:
        for name, text in rules.items():
            zfd.writestr(name, text)
    assert sorted(n for n, _ in s_feeds.unpack(buf.getvalue())) == ["a.rules", "dir/c.rules"]

    assert list(s_feeds.unpack(b"alert tcp any any -> any any (sid:1;)")) == [
        ("feed.rules", "alert tcp any any -> any any (sid:1;)")
    ]
    assert list(s_feeds.unpack(gzip.compress(b"plain"))) == [("feed.rules", "plain")]

    with pytest.raises(s_feeds.FeedError, match="max size"):
        list(s_feeds.unpack(tgz, maxsize=10))
    with pytest.raises(s_feeds.FeedError, match="max size"):
        list(s_feeds.unpack(gzip.compress(b"x" * 100), maxsize=10))
    with pytest.raises(s_feeds.FeedError, match="unpack"):
        list(s_feeds.unpack(b"PK\x03\x04garbage"))


def test_parse_feed():
    fdef = s_feeds.normFeed({"name": "t", "url": "https://e.com", "engine": 2})
    dup = 'alert tcp any any -> any any (msg:"old"; sid:2000001; rev:1;)'
    byts = tarGz({"one.rules": SNORT2_RULES, "two.rules": dup + '\nalert tcp (msg:"bad";)\n'})
    parsed = s_feeds.parseFeed(fdef, byts, maxsize=1024 * 1024)

    recs = {r["sid"]: r for r in parsed["rules"]}
    assert sorted(recs) == [2000001, 2000002, 2000003]
    # The duplicate sid keeps the highest rev.
    assert recs[2000001]["rev"] == 4 and recs[2000001]["file"] == "one.rules"
    assert recs[2000001]["guid"] == s_feeds.ruleGuid("t", 1, 2000001)
    assert recs[2000001]["engine"] == "snort2" and recs[2000001]["engineid"] == 2
    assert recs[2000001]["form"] == "it:app:snort:rule" and recs[2000001]["family"] == "SlibTest"
    assert recs[2000001]["refs"] == [["md5", "662002d61f1aebd64fc204ce40fd65f2"]]
    assert recs[2000003]["enabled"] is False
    assert parsed["errors"] == [("two.rules", 2, "A Snort rule must have a sid.")]
    assert parsed["files"] == ["one.rules", "two.rules"]

    with pytest.raises(s_feeds.FeedError, match="no .rules"):
        s_feeds.parseFeed(fdef, tarGz({"readme.txt": "x"}), maxsize=1024)


def test_guids():
    assert s_feeds.ruleGuid("a", 1, 2) == s_feeds.ruleGuid("a", 1, 2)
    assert s_feeds.ruleGuid("a", 1, 2) != s_feeds.ruleGuid("b", 1, 2)
    assert s_feeds.rulesetGuid("a") != s_feeds.rulesetGuid("b")


async def test_download():
    async with FakeFeeds() as fake, aiohttp.ClientSession() as sess:
        url = f"{fake.url}/snort3.tar.gz"
        resp = await s_feeds.download(sess, url, maxsize=1024 * 1024, timeout=10)
        assert resp["status"] == 200 and resp["etag"]
        assert SNORT3_RULES in dict(s_feeds.unpack(resp["byts"])).values()

        again = await s_feeds.download(
            sess, url, maxsize=1024 * 1024, timeout=10, etag=resp["etag"]
        )
        assert again["status"] == 304 and again["byts"] is None

        with pytest.raises(s_feeds.FeedError, match="HTTP 404"):
            await s_feeds.download(sess, f"{fake.url}/nope", maxsize=1024, timeout=10)
        with pytest.raises(s_feeds.FeedError, match="max size"):
            await s_feeds.download(sess, url, maxsize=10, timeout=10)
        with pytest.raises(s_feeds.FeedError, match="failed"):
            await s_feeds.download(sess, "http://127.0.0.1:1/x", maxsize=10, timeout=10)


def test_ref_edges():
    refs = [
        ["cve", "2021-44228"],
        ["cve", "CVE-2020-0001"],
        ["cve", "nope"],
        ["url", "www.example.com/a?b=c"],
        ["url", "https://1.2.3.4:8080/x"],
        ["url", "url,example.org/x"],
        ["url", "url,url,attack.mitre.org/techniques/T1219/"],
        ["url", "www,example.com/x"],
        ["url", "http://www.corelan.be#=#=8800/x"],
        ["url", "e9bc44cf548a70e7285499209973faf44b7374de"],
        ["url", '"example.com/x"'],
        ["url", "bad url"],
        ["url", "[::1]/x"],
        ["md5", "662002D61F1AEBD64FC204CE40FD65F2"],
        ["md5", "abc"],
        ["sha256", "aa" * 32],
        ["bugtraq", "123"],
    ]
    assert s_feeds.refEdges(refs) == [
        ("detects", ("it:sec:cve", "cve-2021-44228")),
        ("detects", ("it:sec:cve", "cve-2020-0001")),
        ("refs", ("inet:url", "http://www.example.com/a?b=c")),
        ("refs", ("inet:url", "https://1.2.3.4:8080/x")),
        ("refs", ("inet:url", "http://example.org/x")),
        ("refs", ("inet:url", "http://attack.mitre.org/techniques/T1219/")),
        ("refs", ("inet:url", "http://[::1]/x")),
        ("refs", ("hash:md5", "662002d61f1aebd64fc204ce40fd65f2")),
        ("refs", ("hash:sha256", "aa" * 32)),
    ]


def test_rule_nodedef():
    fdef = s_feeds.normFeed({"name": "t", "url": "https://e.com", "engine": 2})
    rec = s_feeds.parseFeed(fdef, tarGz({"a.rules": SNORT2_RULES}), maxsize=1024 * 1024)["rules"][0]
    (form, guid), info = s_feeds.ruleNodeDef(rec)
    assert form == "it:app:snort:rule" and guid == rec["guid"]
    assert info["props"] == {
        "id": "2000001",
        "text": rec["text"],
        "engine": 2,
        "version": "4",
        "enabled": True,
        "name": "ET SLIB TEST Response Body",
        "family": "SlibTest",
        "created": "2021-11-01",
        "updated": "2024-03-05",
    }
    assert info["edges"] == [("refs", ("hash:md5", "662002d61f1aebd64fc204ce40fd65f2"))]

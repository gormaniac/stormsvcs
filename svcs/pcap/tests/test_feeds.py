"""Pytests for pcapsvc.feeds (no Snort needed)."""

import gzip
import io
import zipfile

import aiohttp
import pytest
import synapse.tests.utils as s_tests
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


def test_feed_secrets():
    secrets = {
        "talos:oinkcode": {"value": "abc123", "hosts": ["www.snort.org", "*.example.com"]},
        "bad": "a plain string",
    }
    url = "https://www.snort.org/rules/x.tar.gz?oinkcode=${talos:oinkcode}"
    assert s_feeds.feedUrl(url, secrets).endswith("oinkcode=abc123")
    assert s_feeds.feedUrl("https://a.b.example.com/${talos:oinkcode}", secrets) == (
        "https://a.b.example.com/abc123"
    )

    # Admins choose feed URLs, a secret is only sent to its hosts.
    for bad in (
        "https://attacker.example.net/?k=${talos:oinkcode}",
        "https://www.snort.org.attacker.net/?k=${talos:oinkcode}",
        "https://example.com/?k=${talos:oinkcode}",
        "https://${talos:oinkcode}.attacker.net/",
    ):
        with pytest.raises(s_feeds.FeedError, match="isn't allowed to be sent"):
            s_feeds.feedUrl(bad, secrets)
    with pytest.raises(s_feeds.FeedError, match="needs the secret"):
        s_feeds.feedUrl("https://www.snort.org/${nope}", secrets)
    with pytest.raises(s_feeds.FeedError, match="needs the secret"):
        s_feeds.feedUrl("https://www.snort.org/${bad}", secrets)

    assert s_feeds.redact("GET https://www.snort.org/?oinkcode=abc123 failed", secrets) == (
        "GET https://www.snort.org/?oinkcode=${talos:oinkcode} failed"
    )


class TestRetiredFeeds(s_tests.SynTest):
    async def test_retired(self):
        from pcapsvc import PcapSvc

        url = s_feeds.RETIRED_FEEDS["abusech-sslbl-c2"]
        with self.getTestDir() as dirn:
            feeds = [
                {"name": "abusech-sslbl-c2", "url": url, "engine": "suricata"},
                {"name": "keep", "url": "https://example.com/x.rules", "engine": "suricata"},
            ]
            async with self.getTestCell(PcapSvc, dirn=dirn, conf={"pcap:feeds": feeds}) as svc:
                # A service that seeded the retired feed (an older version) drops it.
                assert sorted(f["name"] for f in await svc.feeds()) == ["keep"]
            # One an admin pointed elsewhere stays.
            async with self.getTestCell(PcapSvc, dirn=dirn) as svc:
                await svc.feedAdd({"name": "abusech-sslbl-c2", "url": "https://mirror.example/x.rules",
                                   "engine": "suricata"})
            async with self.getTestCell(PcapSvc, dirn=dirn) as svc:
                assert sorted(f["name"] for f in await svc.feeds()) == ["abusech-sslbl-c2", "keep"]

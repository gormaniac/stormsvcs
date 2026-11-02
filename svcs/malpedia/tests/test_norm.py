"""Tests for normalizing Malpedia's data."""

from malpediasvc import norm

from . import fakemalpedia as fm


def test_tags():
    assert norm.tagPart("[Vault 7/8]") == "vault_7_8"
    assert norm.tagPart("NoName057(16)") == "noname057_16"
    assert norm.tagPart("asnarök") == "asnarök"
    assert norm.tagPart("+++") is None
    assert norm.tagPath("win.xagent") == "win.xagent"
    assert norm.tagPath("win..odd name") == "win.odd_name"
    assert norm.actorTag("apt28") == "threat.apt28"
    assert norm.actorTag("keymous+") == "threat.keymous"
    assert norm.actorTag("$$$") is None
    assert norm.familyTag("win.tinyturla_ng") == "mal.win.tinyturla_ng"
    assert norm.familyTag("...") is None


def test_dates():
    assert norm.normDate("2026-03-10") == "2026-03-10"
    assert norm.normDate("2014") == "2014"
    assert norm.normDate("2017-05") == "2017-05"
    assert norm.normDate("20170517") == "2017-05-17"
    assert norm.normDate("2017-02-30") is None
    assert norm.normDate("May 2017") is None
    assert norm.normDate(None) is None
    assert norm.normDate("") is None


def test_authors():
    assert norm.splitAuthors("ESET Research") == ["ESET Research"]
    assert norm.splitAuthors("0xtornado and v3t0_ and 0xtornado") == ["0xtornado", "v3t0_"]
    assert norm.splitAuthors("Alice  and\nBob") == ["Alice", "Bob"]
    assert norm.splitAuthors(None) == []


def test_actor_slugs():
    actors = fm.initialState()["actors"]
    actors["Keymous+"] = {"value": "Keymous+", "meta": {}}
    actors["Dup"] = {"value": "Dup", "meta": {}}
    actors["not a dict"] = "nope"
    ids = ["apt28", "lazarus_group", "[vault_7_8]", "keymous+", "turla"]
    matched, unmatched = norm.resolveActorIds(actors, ids)
    assert set(matched) == {"apt28", "lazarus_group", "[vault_7_8]", "keymous+"}
    assert unmatched == ["Dup"]

    # A display name that only matches by its letters and numbers.
    matched, unmatched = norm.resolveActorIds({"Sath-ı Müdafaa": {}}, ["sath-ı_müdafaa"])
    assert set(matched) == {"sath-ı_müdafaa"}


def test_actor():
    data = fm.initialState()["actors"]["APT28"]
    rec = norm.normActor("apt28", data)
    assert rec["key"] == rec["id"] == "apt28"
    assert rec["name"] == "APT28"
    assert rec["aliases"] == ["APT 28", "Fancy Bear", "G0007", "Hidden Bear", "Sofacy"]
    assert rec["country"] == "ru"
    assert rec["sectors"] == ["Government", "Military"]
    assert rec["mitre"] == "G0007"
    assert rec["tag"] == "threat.apt28"
    assert rec["url"] == "https://malpedia.caad.fkie.fraunhofer.de/actor/apt28"

    # Sparse and odd data.
    rec = norm.normActor("x", {"meta": {"country": "Russia", "synonyms": "X", "targeted-sector": None}})
    assert rec["name"] == "x"
    assert rec["aliases"] == []
    assert rec["country"] is None
    assert rec["sectors"] == []
    assert rec["desc"] is None
    assert rec["mitre"] is None
    rec = norm.normActor("x", {"value": "X", "meta": {"synonyms": ["G0001", "G0002"]}})
    assert rec["mitre"] is None


def test_family_and_attribution():
    state = fm.initialState()
    actors = {aid: norm.normActor(aid, data) for aid, data in norm.resolveActorIds(state["actors"], state["actorids"])[0].items()}
    index = norm.ActorIndex(actors.values())

    assert index.resolve("APT28") == "apt28"
    assert index.resolve("apt 28") == "apt28"
    assert index.resolve("Fancy Bear") == "apt28"
    assert index.resolve("Hidden Cobra") == "lazarus_group"
    assert index.resolve("Hidden Bear") is None
    assert index.resolve("Nobody") is None
    assert index.resolve("") is None
    assert index.resolve("!!!") is None

    rec = norm.normFamily("win.wannacryptor", state["families"]["win.wannacryptor"], index)
    assert rec["name"] == "WannaCryptor"
    assert rec["platform"] == "win"
    assert rec["aliases"] == ["WannaCry", "Wcry"]
    assert rec["actors"] == ["lazarus_group"]
    assert rec["unresolved"] == ["Hidden Bear", "Nobody Knows"]
    assert rec["tag"] == "mal.win.wannacryptor"
    assert rec["desc"] == "WannaCry ransomware."

    xagent = norm.normFamily("win.xagent", state["families"]["win.xagent"], index)
    # The common name isn't repeated as an alias, and an empty description is None.
    assert xagent["aliases"] == ["chopstick", "splm"]
    assert xagent["desc"] is None
    assert xagent["updated"] == "2026-03-11"

    fams = {
        fid: norm.normFamily(fid, data, index) for fid, data in state["families"].items()
    }
    raw = norm.resolveActorIds(state["actors"], state["actorids"])[0]
    norm.addActorLinks(fams, raw)
    assert fams["win.sedreco"]["actors"] == ["apt28"]
    norm.withActorTags(fams["win.sedreco"])
    assert fams["win.sedreco"]["actortags"] == [["apt28", "threat.apt28"]]

    # No index, nothing resolves.
    assert norm.normFamily("x", {"attribution": ["APT28"]})["unresolved"] == ["APT28"]
    assert norm.normFamily("nodot", {})["platform"] is None


def test_news():
    fake = fm.FakeMalpedia()
    bibs, errors = norm.parseBib(fake.bibText() + "\n@online{nourl, title = {x}}\n" + fm.bibEntry(
        "online", "dupe:2026:key:1", "Someone", "Dupe", "2026", "Org", fm.URL_PLAIN))
    assert errors == ["Skipped the BibTeX entry nourl: it has no url."]
    assert set(bibs) == {fm.URL_SEDNIT, fm.URL_XAGENT_PDF, fm.URL_WANNACRY, fm.URL_PLAIN}
    assert bibs[fm.URL_PLAIN]["keys"] == ["dupe:2026:key:1", "plain:2020:report:bbbb222"]
    pdf = bibs[fm.URL_XAGENT_PDF]
    assert pdf["publisher"] == "FireEye"
    assert pdf["authors"] == ["FireEye", "Jane Doe"]
    assert pdf["published"] == "2014"
    assert pdf["type"] == "techreport"

    fams = {"win.xagent": {"library": ["fireeye:2014:apt28:27799d1", "missing:key"]}}
    refs = dict(fake.state["references"])
    refs["  "] = [{"type": "family", "id": "x"}]
    refs["https://bad.example/"] = "not a list"
    refs[fm.URL_PLAIN] = [{"type": "other", "id": "x"}, {"type": "actor"}, "junk"]
    news = norm.buildNews(bibs, refs, fams)
    byurl = {rec["url"]: rec for rec in news.values()}
    assert set(byurl) == {fm.URL_SEDNIT, fm.URL_XAGENT_PDF, fm.URL_WANNACRY, fm.URL_PLAIN, fm.URL_NOBIB, "https://bad.example/"}
    assert byurl[fm.URL_SEDNIT]["actors"] == [["apt28", "threat.apt28"]]
    assert byurl[fm.URL_SEDNIT]["families"] == [["win.xagent", "mal.win.xagent"]]
    # Tagged through the family's library entries.
    assert byurl[fm.URL_XAGENT_PDF]["families"] == [["win.xagent", "mal.win.xagent"]]
    assert byurl[fm.URL_NOBIB]["title"] is None
    assert byurl[fm.URL_NOBIB]["families"] == [["win.sedreco", "mal.win.sedreco"]]
    assert byurl[fm.URL_PLAIN]["actors"] == []
    for key, rec in news.items():
        assert key == norm.urlKey(rec["url"])


def test_yara():
    rec = norm.normYara("win.xagent_w0.yar", fm.YARA_XAGENT_W0, tlp="tlp_white",
                        families={"win.xagent": {"name": "X-Agent"}})
    assert rec["key"] == rec["file"] == "win.xagent_w0.yar"
    assert rec["name"] == "win_xagent_w0"
    assert rec["family"] == "win.xagent"
    assert rec["familyname"] == "X-Agent"
    assert rec["familytag"] == "mal.win.xagent"
    assert rec["tlp"] == "white"
    assert rec["auto"] is False
    assert rec["desc"] == "Sofacy Group Malware Sample 3"
    assert rec["author"] == "Florian Roth"
    assert rec["created"] == "2015-06-19"
    assert rec["updated"] == "2017-05-17"
    assert rec["license"] == "CC BY-NC-SA 4.0"
    assert rec["url"] == "https://malpedia.caad.fkie.fraunhofer.de/details/win.xagent"

    rec = norm.normYara("win.xagent_auto.yar", fm.YARA_XAGENT_AUTO)
    assert rec["auto"] is True
    assert rec["familyname"] is None
    # No TLP directory, the rule's malpedia_sharing is used.
    assert rec["tlp"] == "white"

    text = 'private rule odd_name { meta: malpedia_sharing = "TLP:AMBER" condition: true }'
    rec = norm.normYara("weird.yar", text)
    assert rec["name"] == "odd_name"
    assert rec["family"] is None
    assert rec["familytag"] is None
    assert rec["url"] is None
    assert rec["tlp"] == "amber"

    assert norm.normYara("empty.yar", "  ") is None
    assert norm.normYara("norule.yar", "// just a comment") is None
    assert norm.normYara("bad.yar", None) is None

    assert norm.tlpName("TLP:CLEAR") == "clear"
    assert norm.tlpName("tlp_green") == "green"
    assert norm.tlpName("purple") is None
    assert norm.tlpName(None) is None

    assert norm.yaraMeta("rule x { condition: true }") == {}
    assert norm.yaraMeta('rule x { meta: a = "1" condition: true }') == {"a": "1"}
    meta = norm.yaraMeta('rule x {\n meta:\n  a = "1"\n  a = "2"\n  b = "say \\"hi\\""\n condition:\n  true\n}')
    assert meta == {"a": "1", "b": 'say "hi"'}

    assert norm.yaraTlpRules({"tlp_white": {"a/b.yar": "x", 1: "y", "c.yar": 2}, "bad": []}) == [
        ("tlp_white", "b.yar", "x")
    ]
    listing = norm.yaraListing({
        "win.a": [{"path": "/win.a/yara/tlp_white/win.a_w0.yar", "tlp": "tlp_white"},
                  {"path": "/win.a/yara/tlp_green/win.a_g0.yar"}, {"nopath": 1}, "junk"],
        "win.b": "junk",
    })
    assert listing == {"win.a_w0.yar": ("win.a", "tlp_white"), "win.a_g0.yar": ("win.a", "tlp_green")}


def test_rechash():
    assert norm.recHash({"a": 1, "b": [1, 2]}) == norm.recHash({"b": [1, 2], "a": 1})
    assert norm.recHash({"a": 1}) != norm.recHash({"a": 2})

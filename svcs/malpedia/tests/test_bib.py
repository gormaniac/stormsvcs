"""Tests for the BibTeX parser."""

from malpediasvc import bib


def test_malpedia_format():
    text = """@online{research:20260310:sednit:86e9801,
   author = {ESET Research},
   title = {{Sednit reloaded: Back in the trenches}},
   date = {2026-03-10},
   organization = {ESET Research},
   url = {https://www.welivesecurity.com/en/eset-research/sednit-reloaded-back-trenches/},
   language = {English},
   urldate = {2026-03-11}
}

@techreport{uk:20181004:indicators:af0d14a,
   author = {NCSC UK},
   title = {{Indicators of Compromise for Malware used by APT28}},
   date = {2018-10-04},
   institution = {NCSC UK},
   url = {https://www.thecssc.com/wp-content/uploads/2018/10/4OctoberIOC-APT28-malware-advisory.pdf},
   language = {English},
   urldate = {2019-11-29}
}
"""
    entries, errors = bib.parse(text)
    assert errors == []
    assert len(entries) == 2
    assert entries[0] == {
        "type": "online",
        "key": "research:20260310:sednit:86e9801",
        "fields": {
            "author": "ESET Research",
            "title": "Sednit reloaded: Back in the trenches",
            "date": "2026-03-10",
            "organization": "ESET Research",
            "url": "https://www.welivesecurity.com/en/eset-research/sednit-reloaded-back-trenches/",
            "language": "English",
            "urldate": "2026-03-11",
        },
    }
    assert entries[1]["type"] == "techreport"
    assert entries[1]["fields"]["institution"] == "NCSC UK"


def test_syntax_variants():
    text = r"""
% A comment line with an @ sign
@comment{ignored, stuff = {x}}
@string{foo = "bar"}
@preamble{"\newcommand"}
@Article(key1,
  TITLE = "Quoted {Nested} Title",
  author = {A. Author and B. Author},
  year = 2020,
  note = "part one" # " and two",
  multi = {line
     wrapped   value},
  escaped = {Q\&A 100\% \{braces\} C:\path},
)
@online{key2, title = {{Deep {nested {braces}}}}}
"""
    entries, errors = bib.parse(text)
    assert errors == []
    assert [e["key"] for e in entries] == ["key1", "key2"]
    fields = entries[0]["fields"]
    assert entries[0]["type"] == "article"
    assert fields["title"] == "Quoted Nested Title"
    assert fields["author"] == "A. Author and B. Author"
    assert fields["year"] == "2020"
    assert fields["note"] == "part one and two"
    assert fields["multi"] == "line wrapped value"
    assert fields["escaped"] == r"Q&A 100% {braces} C:\path"
    assert entries[1]["fields"]["title"] == "Deep nested braces"


def test_bad_entries_skipped():
    text = """@online{good1, url = {https://a.example/}}
@online{broken, url = {https://unterminated.example/
@online{good2, url = {https://b.example/}}
@online{, url = {https://nokey.example/}}
@online{nokey}
@online{good3, url = {https://c.example/}, }
"""
    entries, errors = bib.parse(text)
    assert [e["key"] for e in entries] == ["good1", "good2", "good3"]
    assert len(errors) == 3
    assert all(e.startswith("Skipped a BibTeX @online entry") for e in errors)


def test_empty():
    assert bib.parse("") == ([], [])
    assert bib.parse(None) == ([], [])
    assert bib.parse("no entries @ here {") == ([], [])


def test_unescape():
    assert bib.unescape("{{Title}}") == "Title"
    assert bib.unescape("  a\n  b  ") == "a b"
    assert bib.unescape(r"\_\#\$") == "_#$"

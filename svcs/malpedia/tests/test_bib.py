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
        "names": {"author": ["ESET Research"]},
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


def test_author_braces():
    # MALP-10: braces protect an "and" inside a name, ex. an organization.
    text = "@online{k, author = {{Ernst and Young} and Jane Doe and {R and D Team}}, url = {https://a}}"
    entries, errors = bib.parse(text)
    assert errors == []
    assert entries[0]["names"]["author"] == ["Ernst and Young", "Jane Doe", "R and D Team"]
    # The joined field is still there, unescaped.
    assert entries[0]["fields"]["author"] == "Ernst and Young and Jane Doe and R and D Team"
    assert bib.splitNames("A and  B AND C and A") == ["A", "B AND C"]
    assert bib.splitNames("Andy Anderson and Sandra") == ["Andy Anderson", "Sandra"]


def test_backslashes():
    # MALP-11: a backslash only escapes a brace, and a value may end in a backslash.
    text = r"""@online{k1,
   title = {{C:\}},
   note = {a \} b \{ c},
   path = {C:\Windows\},
   url = {https://example.com/1}
}
@online{k2, title = {plain {C:\}}, url = {https://example.com/2}}
"""
    entries, errors = bib.parse(text)
    assert errors == []
    assert [e["key"] for e in entries] == ["k1", "k2"]
    fields = entries[0]["fields"]
    assert fields["title"] == "C:\\"
    assert fields["note"] == "a } b { c"
    assert fields["path"] == "C:\\Windows\\"
    assert entries[1]["fields"]["title"] == "plain C:\\"

    # An escaped brace that ends a value isn't taken for a backslash that ends the entry, the
    # fields after it are kept. At the end of an entry, it's still a backslash.
    text = r"""@online{k1, title = {ends \}}, url = {https://example.com/1}}
@online{k2, title = {{nested \}}}, url = {https://example.com/2}}
@online{k3, url = {https://example.com/3}, path = {C:\}}
% a comment
@online{k4, url = {https://example.com/4}, path = {D:\}}"""
    entries, errors = bib.parse(text)
    assert errors == []
    got = {e["key"]: e["fields"] for e in entries}
    assert got["k1"] == {"title": "ends }", "url": "https://example.com/1"}
    assert got["k2"] == {"title": "nested }", "url": "https://example.com/2"}
    assert got["k3"]["path"] == "C:\\"
    assert got["k4"]["path"] == "D:\\"


def test_latex_accents():
    # MALP-11: the common LaTeX accents and letters are decoded.
    assert bib.unescape(r"M\"{u}ller") == "Müller"
    assert bib.unescape(r"{\'e}t{\'{e}} \`a \^o \~n \c{c} \v{s} \c c") == "été à ô ñ ç š ç"
    # A space after a letter command ends it (LaTeX drops it), braces keep the spacing.
    assert bib.unescape(r"Stra\ss{}e {\o} {\AA} \'{\i} \o x") == "Straße ø Å í øx"
    # Not accents: a Windows path, and an unknown command.
    assert bib.unescape(r"C:\vault \foo") == r"C:\vault \foo"
    entries, _ = bib.parse(
        r"@online{k, author = {J\"{o}rg M\"uller and Ren\'e}, url = {https://a}}"
    )
    assert entries[0]["names"]["author"] == ["Jörg Müller", "René"]


def test_parse_errors():
    # Unterminated quoted values, bare value errors, and parenthesized blocks.
    text = """@online{bad1, title = "never closed, url = {https://a}}
@online{bad2, title = , url = {https://b}}
@comment(skipped (entirely))
@online(good, title = {Good}, url = {https://c})
"""
    entries, errors = bib.parse(text)
    assert [e["key"] for e in entries] == ["good"]
    assert entries[0]["fields"]["title"] == "Good"
    assert len(errors) == 2
    assert "Unterminated quoted value" in errors[0]
    assert "Expected a value" in errors[1]

"""Pytests for pcapsvc.rules (no Snort needed)."""

import pytest
from pcapsvc import rules as s_rules

ET_RULE = (
    'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET MALWARE Test \\"quoted\\"; semi"; '
    'flow:established,to_server; content:"/count.asp?exe="; http_uri; reference:url,www.example.com/x; '
    "reference:cve,2021-44228; classtype:trojan-activity; sid:2013502; rev:3; "
    "metadata:created_at 2011_08_31, malware_family Cobalt_Strike, signature_severity Minor, updated_at 2019_09_28;)"
)


def test_parse_et_rule():
    rule = s_rules.parseRule(ET_RULE)
    assert rule["enabled"] is True
    assert rule["action"] == "alert"
    assert rule["header"] == "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS"
    assert (rule["gid"], rule["sid"], rule["rev"]) == (1, 2013502, 3)
    assert rule["msg"] == 'ET MALWARE Test "quoted"; semi'
    assert rule["classtype"] == "trojan-activity"
    assert rule["refs"] == [["url", "www.example.com/x"], ["cve", "2021-44228"]]
    assert rule["created"] == "2011-08-31" and rule["updated"] == "2019-09-28"
    assert rule["family"] == "Cobalt Strike"
    assert rule["metadata"]["signature_severity"] == ["Minor"]
    assert s_rules.ruleId(rule) == "2013502"


def test_parse_commented_and_gid():
    rule = s_rules.parseRule('# alert tcp any any -> any any (msg:"x"; gid:3; sid:5; priority:2;)')
    assert rule["enabled"] is False
    assert rule["text"].startswith("alert tcp")
    assert (rule["gid"], rule["sid"], rule["rev"], rule["priority"]) == (3, 5, 1, 2)
    assert s_rules.ruleId(rule) == "3:5"
    assert (
        s_rules.parseRule("#alert tcp any any -> any any (sid:5;)", enabled=True)["enabled"] is True
    )


def test_parse_unquoted_snort2():
    # Snort 2 splits options on ";" only, a pcre can have an unescaped quote.
    rule = s_rules.parseRule(
        'alert tcp any any -> any any (msg:"x"; pcre:"/[\'"]+evil/i"; sid:7; rev:2;)'
    )
    assert (rule["sid"], rule["rev"]) == (7, 2)


def test_parse_errors():
    with pytest.raises(s_rules.RuleError, match="Not a Snort rule"):
        s_rules.parseRule("rule yara { condition: true }")
    with pytest.raises(s_rules.RuleError, match="parentheses"):
        s_rules.parseRule("alert tcp any any -> any any")
    with pytest.raises(s_rules.RuleError, match="sid"):
        s_rules.parseRule('alert tcp any any -> any any (msg:"no sid";)')
    with pytest.raises(s_rules.RuleError, match="Invalid sid"):
        s_rules.parseRule("alert tcp any any -> any any (sid:abc;)")


def test_parse_rules_file():
    text = "\n".join(
        (
            "# A comment, not a rule",
            "",
            'alert tcp any any -> any any (msg:"one"; sid:1;)',
            'alert tcp any any -> any any (msg:"two"; \\',
            '    content:"x"; sid:2;)',
            "alert http (",
            '    msg:"three";',
            "    sid:3;",
            ")",
            '# alert tcp any any -> any any (msg:"four"; \\',
            "#   sid:4;)",
            'alert tcp any any -> any any (msg:"no sid";)',
            'alert tcp any any -> any any (msg:"five"; sid:5;)',
        )
    )
    parsed = list(s_rules.parseRules(text))
    rules = [r for r, _, _ in parsed if r]
    assert [(r["sid"], r["enabled"]) for r in rules] == [
        (1, True),
        (2, True),
        (3, True),
        (4, False),
        (5, True),
    ]
    assert rules[1]["text"] == 'alert tcp any any -> any any (msg:"two"; content:"x"; sid:2;)'
    assert rules[2]["text"] == 'alert http ( msg:"three"; sid:3; )'
    assert [(line, err) for r, line, err in parsed if r is None] == [
        (12, "A Snort rule must have a sid.")
    ]
    assert [line for r, line, _ in parsed if r] == [3, 4, 6, 10, 13]


def test_split_options():
    assert s_rules.splitOptions(r'msg:"a;b"; nocase; content:"x\;y"') == [
        ("msg", '"a;b"'),
        ("nocase", None),
        ("content", r'"x\;y"'),
    ]
    assert s_rules.splitOptions('msg:"a;b"', quotes=False) == [("msg", '"a'), ('b"', None)]


def test_rule_warnings():
    warn = s_rules.ruleWarnings
    assert warn('alert http any any -> any any (msg:"a"; http.uri; content:"/x"; sid:1;)') == []
    # IP only rules (ex. blocklists) don't need content.
    assert warn("alert ip [1.2.3.4] any -> $HOME_NET any (msg:\"c2\"; sid:2;)") == []
    assert "no content" in warn('alert tcp any any -> any 80 (msg:"a"; flow:established; sid:3;)')[0]
    assert "no fast pattern" in warn('alert http any any -> any any (pcre:"/a+b/"; sid:4;)')[0]
    assert any("pass rule" in w for w in warn('pass tcp any any -> any any (content:"a"; sid:5;)'))
    assert any(
        "noalert" in w
        for w in warn('alert tcp any any -> any any (content:"a"; flowbits:set,x; flowbits:noalert; sid:6;)')
    )
    assert any("only logged" in w for w in warn('drop tcp any any -> any any (content:"a"; sid:7;)'))
    assert warn("not a rule") == []


def test_check_net_vars():
    assert s_rules.checkNetVars(None) == {}
    assert s_rules.checkNetVars({"home_net": " [10.0.0.0/8, !10.1.0.0/16] ", "EXTERNAL_NET": "!$HOME_NET"}) == {
        "HOME_NET": "[10.0.0.0/8, !10.1.0.0/16]",
        "EXTERNAL_NET": "!$HOME_NET",
    }
    assert s_rules.checkNetVars({"X_NET": "[10.0.0.0/8,[!$HOME_NET, 2001:db8::/32],!192.0.2.1]"})
    for bad in (
        {"HOME NET": "any"},
        {"HOME_NET": "any'; os.exit()"},
        {"HOME_NET": ""},
        ["x"],
        # Unbalanced, ports, not an address, an empty item.
        {"HOME_NET": "[10.0.0.0/8"},
        {"HOME_NET": "10.0.0.0/8]"},
        {"HTTP_PORTS": "[80,8080]"},
        {"HOME_NET": "[10.0.0.0/8,,]"},
        {"HOME_NET": "nope"},
        {"HOME_NET": "$"},
    ):
        with pytest.raises(s_rules.RuleError):
            s_rules.checkNetVars(bad)

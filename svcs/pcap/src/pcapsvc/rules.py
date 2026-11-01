"""Parse Snort (2.x and 3) and Suricata rule text into the metadata the service and Storm need.

Snort and Suricata rules share the same shape (an action, a header, and options in
parentheses), so one parser handles both. Only enough of a rule is parsed to identify and model
it (its action, header, and a handful of options). Whether an engine can actually load a rule
is decided by the engine itself, see ``pcapsvc.snort`` and ``pcapsvc.suricata``.
"""

import datetime
import ipaddress
import re
from collections.abc import Iterator
from typing import Any, TypedDict

ACTIONS = (
    "alert",
    "block",
    "drop",
    "log",
    "pass",
    "react",
    "reject",
    "rejectboth",
    "rejectdst",
    "rejectsrc",
    "rewrite",
    "sdrop",
)
"""The rule actions Snort 2.x, Snort 3, and Suricata support."""

ENGINE_SNORT2 = "snort2"
"""Snort 2.x syntax rules (``it:app:snort:rule:engine=2``), converted to Snort 3 with snort2lua."""

ENGINE_SNORT3 = "snort3"
"""Snort 3 rules (``it:app:snort:rule:engine=3``, or no ``:engine``)."""

ENGINE_SURICATA = "suricata"
"""Suricata rules (``it:app:suricata:rule``)."""

ENGINES = (ENGINE_SNORT2, ENGINE_SNORT3, ENGINE_SURICATA)
"""The rule engines the service can run."""

SNORT_ENGINES = (ENGINE_SNORT2, ENGINE_SNORT3)
"""The engines Snort runs."""

FORMS = {
    ENGINE_SNORT2: "it:app:snort:rule",
    ENGINE_SNORT3: "it:app:snort:rule",
    ENGINE_SURICATA: "it:app:suricata:rule",
}
"""The form of each engine's rules."""

SNORT_ENGINE_IDS = {ENGINE_SNORT2: 2, ENGINE_SNORT3: 3}
"""The ``it:app:snort:rule:engine`` value of each Snort engine."""


def normEngine(engine: Any) -> str:
    """Normalize an engine name, or an ``it:app:snort:rule:engine`` value (2 or 3).

    Raises
    ------
    RuleError
        If it isn't an engine the service can run.
    """

    if engine is None:
        return ENGINE_SNORT3
    if isinstance(engine, str):
        valu = engine.strip().lower()
        if valu in ENGINES:
            return valu
        if valu in ("2", "3"):
            return f"snort{valu}"
    elif isinstance(engine, int) and not isinstance(engine, bool) and engine in (2, 3):
        return f"snort{engine}"
    raise RuleError(f"Unsupported rule engine {engine!r}, use one of: {', '.join(ENGINES)}.")


def ruleEngine(form: str, engine: Any = None) -> str:
    """The engine that runs a rule node, from its form and (for Snort rules) its ``:engine``.

    Raises
    ------
    RuleError
        If it isn't a rule form, or engine, the service can run.
    """

    if form == "it:app:suricata:rule":
        return ENGINE_SURICATA
    if form == "it:app:snort:rule":
        eng = normEngine(engine)
        if eng in SNORT_ENGINES:
            return eng
    raise RuleError(f"{form} rules (with :engine {engine!r}) can't be run by the service.")


_RULE_START = re.compile(r"^\s*(#+\s*)?(" + "|".join(ACTIONS) + r")\s", re.IGNORECASE)
_DATE = re.compile(r"^(\d{4})[_-](\d{2})[_-](\d{2})$")


class RuleError(Exception):
    """Raised when rule text can't be parsed."""

    def __init__(self, mesg: str) -> None:
        super().__init__(mesg)
        self.mesg = mesg


class Rule(TypedDict):
    """The parsed metadata of a Snort rule."""

    text: str
    enabled: bool
    action: str
    header: str
    gid: int
    sid: int
    rev: int
    msg: str | None
    classtype: str | None
    priority: int | None
    refs: list[list[str]]
    metadata: dict[str, list[str]]
    family: str | None
    created: str | None
    updated: str | None


def splitOptions(body: str, quotes: bool = True) -> list[tuple[str, str | None]]:
    """Split a rule's option body (the text inside the outer parentheses) into (name, value) pairs.

    Options are separated by ``;``, a backslash escapes the next character. With ``quotes``, a ``;``
    in a quoted string doesn't separate options. Snort 2.x ignores quotes (so a pcre can contain
    an unescaped ``"``), use ``quotes=False`` to split the same way.
    Options without a value (ex. ``nocase``) have a value of None.
    """

    opts = []
    buf = []
    quoted = False
    escaped = False
    for char in body:
        if escaped:
            buf.append(char)
            escaped = False
            continue
        if char == "\\":
            buf.append(char)
            escaped = True
            continue
        if char == '"' and quotes:
            quoted = not quoted
        if char == ";" and not quoted:
            opts.append("".join(buf))
            buf = []
            continue
        buf.append(char)
    if "".join(buf).strip():
        opts.append("".join(buf))

    pairs = []
    for opt in opts:
        opt = opt.strip()
        if not opt:
            continue
        name, sep, valu = opt.partition(":")
        pairs.append((name.strip().lower(), valu.strip() if sep else None))
    return pairs


def _unquote(valu: str | None) -> str | None:
    if valu is None:
        return None
    valu = valu.strip()
    if len(valu) >= 2 and valu[0] == valu[-1] == '"':
        valu = valu[1:-1]
    return re.sub(r"\\(.)", r"\1", valu)


def _int(valu: str | None, name: str) -> int | None:
    if valu is None:
        return None
    try:
        return int(valu.strip())
    except ValueError as err:
        raise RuleError(f"Invalid {name} value: {valu}") from err


def _metadata(valu: str) -> dict[str, list[str]]:
    """Parse a ``metadata`` option (``key value, key value``) into key -> values."""

    meta: dict[str, list[str]] = {}
    for item in valu.split(","):
        key, _, mval = item.strip().partition(" ")
        if not key:
            continue
        meta.setdefault(key.lower(), []).append(mval.strip())
    return meta


def _date(valus: list[str] | None) -> str | None:
    """An ET style metadata date (``2011_08_31``) as an ISO date, or None."""

    for valu in valus or ():
        if match := _DATE.match(valu.strip()):
            try:
                return datetime.date(*map(int, match.groups())).isoformat()
            except ValueError:
                continue
    return None


def parseRule(text: str, enabled: bool | None = None) -> Rule:
    """Parse a single rule.

    A rule that is commented out (ex. ``# alert tcp ...``) is parsed as a disabled rule,
    unless ``enabled`` is given. Its ``text`` never includes the comment marker.

    Raises
    ------
    RuleError
        If the text isn't a rule, or doesn't have a sid.
    """

    text = text.strip()
    match = _RULE_START.match(text)
    if match is None:
        raise RuleError(f"Not a Snort rule, it must start with one of: {', '.join(ACTIONS)}.")

    if match.group(1):
        text = text[match.end(1) :].strip()
        if enabled is None:
            enabled = False
    if enabled is None:
        enabled = True

    # Multi-line rules (a trailing backslash) are joined into one line.
    text = re.sub(r"\s*\\\s*\n\s*", " ", text)
    text = " ".join(line.strip() for line in text.splitlines())

    start = text.find("(")
    end = text.rfind(")")
    if start == -1 or end < start:
        raise RuleError("A Snort rule's options must be in parentheses.")

    header = text[:start].strip()
    action = header.split()[0].lower()
    opts = splitOptions(text[start + 1 : end])
    if not any(name == "sid" for name, _ in opts):
        opts = splitOptions(text[start + 1 : end], quotes=False)

    rule = Rule(
        text=text,
        enabled=enabled,
        action=action,
        header=header,
        gid=1,
        sid=0,
        rev=1,
        msg=None,
        classtype=None,
        priority=None,
        refs=[],
        metadata={},
        family=None,
        created=None,
        updated=None,
    )

    sid = None
    for name, valu in opts:
        if name == "sid":
            sid = _int(valu, "sid")
        elif name == "gid":
            rule["gid"] = _int(valu, "gid")
        elif name == "rev":
            rule["rev"] = _int(valu, "rev")
        elif name == "msg":
            rule["msg"] = _unquote(valu)
        elif name == "classtype" and valu:
            rule["classtype"] = valu.strip()
        elif name == "priority":
            rule["priority"] = _int(valu, "priority")
        elif name == "reference" and valu:
            scheme, _, ref = valu.partition(",")
            rule["refs"].append([scheme.strip().lower(), ref.strip()])
        elif name == "metadata" and valu:
            for key, mvals in _metadata(valu).items():
                rule["metadata"].setdefault(key, []).extend(mvals)

    if sid is None:
        raise RuleError("A Snort rule must have a sid.")
    rule["sid"] = sid

    meta = rule["metadata"]
    rule["created"] = _date(meta.get("created_at"))
    rule["updated"] = _date(meta.get("updated_at"))
    if meta.get("malware_family"):
        rule["family"] = meta["malware_family"][0].replace("_", " ")

    return rule


def iterRuleText(text: str) -> Iterator[tuple[int, str]]:
    """Yield (line number, rule text) for every rule, enabled or commented out, in a rules file.

    Comments and blank lines are skipped. Rules may span several lines, either with trailing
    backslashes (Snort 2.x) or by ending the rule's last line with the closing parenthesis
    (Snort 3). A line that starts a new rule always ends the previous one.
    """

    buf: list[str] = []
    first = 0
    commented = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        if buf and not buf[-1].rstrip().endswith("\\") and _RULE_START.match(line):
            yield first, "\n".join(buf)
            buf = []

        if not buf:
            if not _RULE_START.match(line):
                continue
            first = lineno
            commented = line.lstrip().startswith("#")
        elif commented:
            # A commented out multi-line rule comments out every line.
            line = re.sub(r"^\s*#+", "", line)

        buf.append(line)
        stripped = line.rstrip()
        if stripped.endswith(")") or (not stripped and not buf[-1].endswith("\\")):
            yield first, "\n".join(buf)
            buf = []

    if buf:
        yield first, "\n".join(buf)


def parseRules(text: str) -> Iterator[tuple[Rule | None, int, str | None]]:
    """Parse every rule in a rules file.

    Yields (rule, line number, error) - the rule is None, with an error, if it couldn't be parsed.
    """

    for lineno, rtext in iterRuleText(text):
        try:
            yield parseRule(rtext), lineno, None
        except RuleError as err:
            yield None, lineno, err.mesg


def ruleKey(gid: int, sid: int) -> str:
    """The ``gid:sid`` string that identifies a rule to an engine."""

    return f"{gid}:{sid}"


def ruleId(rule: Rule | dict[str, Any]) -> str:
    """The ``:id`` of a rule node, its sid (or ``gid:sid`` if its gid isn't 1)."""

    if rule["gid"] == 1:
        return str(rule["sid"])
    return ruleKey(rule["gid"], rule["sid"])


NETVAR_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
"""A network variable's name, ex. ``HOME_NET`` or ``HTTP_SERVERS``."""

NETVAR_VALU = re.compile(r"[0-9A-Za-z\[\]\.:/,!$_ -]{1,4096}")
"""A network variable's value: an address group, ex. ``[10.0.0.0/8,!$DNS_SERVERS]`` or ``any``."""


def checkNetVars(valu: Any) -> dict[str, str]:
    """Validate network variables (name -> address group) both engines use, ex. ``HOME_NET``.

    Raises
    ------
    RuleError
        If it isn't a dict of valid names and address groups.
    """

    if valu is None:
        return {}
    if not isinstance(valu, dict):
        raise RuleError("Network variables must be a dict of name -> address group.")
    out = {}
    for name, addrs in valu.items():
        name = str(name).strip().upper()
        if not NETVAR_NAME.fullmatch(name):
            raise RuleError(f"Invalid network variable name {name!r}, ex. HOME_NET.")
        addrs = str(addrs).strip()
        if not NETVAR_VALU.fullmatch(addrs) or not _addressGroup(addrs):
            raise RuleError(
                f"Invalid {name} value {addrs!r}, use an address group like [10.0.0.0/8], "
                "!$HOME_NET, or any."
            )
        out[name] = addrs
    return out


def _addressGroup(valu: str, depth: int = 0) -> bool:
    """Whether a value is an address group both engines read: ``any``, an IP or CIDR, a
    ``$VARIABLE``, or a ``[...]`` list of those (negated with ``!``, nested)."""

    valu = valu.strip()
    if valu.startswith("!"):
        valu = valu[1:].strip()
    if not valu or depth > 8:
        return False
    if valu.startswith("["):
        if not valu.endswith("]"):
            return False
        items, level, start = [], 0, 1
        for idx, char in enumerate(valu[1:-1], start=1):
            if char == "[":
                level += 1
            elif char == "]":
                level -= 1
                if level < 0:
                    return False
            elif char == "," and level == 0:
                items.append(valu[start:idx])
                start = idx + 1
        if level:
            return False
        items.append(valu[start:-1])
        return all(_addressGroup(item, depth + 1) for item in items)
    if valu == "any":
        return True
    if valu.startswith("$"):
        return NETVAR_NAME.fullmatch(valu[1:]) is not None
    try:
        ipaddress.ip_network(valu, strict=False)
    except ValueError:
        return False
    return True


_PAYLOAD_OPTS = {
    "content",
    "uricontent",
    "pcre",
    "byte_test",
    "byte_jump",
    "byte_math",
    "dsize",
    "isdataat",
    "base64_data",
    "regex",
}
"""Options that inspect a packet's (or buffer's) bytes."""


def ruleWarnings(text: str) -> list[str]:
    """Why a rule an engine loads might still not do what it looks like it does.

    These are heuristics, not errors: ex. a rule with no content match is checked against
    every packet its header matches, and a pass rule hides the traffic it matches from every
    other rule.
    """

    try:
        rule = parseRule(text, enabled=True)
    except RuleError:
        return []
    start, end = rule["text"].find("("), rule["text"].rfind(")")
    names = {name for name, _ in splitOptions(rule["text"][start + 1 : end])}
    flowbits = [
        valu or ""
        for name, valu in splitOptions(rule["text"][start + 1 : end])
        if name in ("flowbits", "xbits")
    ]
    proto = (rule["header"].split()[1:2] or [""])[0].lower()

    warnings = []
    if not names & _PAYLOAD_OPTS and proto not in ("ip", "ipv4", "ipv6", "pkthdr"):
        warnings.append(
            "It has no content (or other payload) match, so it's checked against all the "
            "traffic its header matches, which is slow on a busy capture."
        )
    elif "pcre" in names and not names & {"content", "uricontent"}:
        warnings.append("It has a pcre but no content match, so it has no fast pattern (slow).")
    if rule["action"] == "pass":
        warnings.append("It's a pass rule: no other rule alerts on the traffic it matches.")
    if "noalert" in names or any("noalert" in valu for valu in flowbits):
        warnings.append("It never alerts on its own (noalert), it only sets state for others.")
    if rule["action"] in ("drop", "sdrop", "reject", "rejectsrc", "rejectdst", "rejectboth"):
        warnings.append(
            f"Its action is {rule['action']}, offline nothing is blocked: it's only logged."
        )
    return warnings

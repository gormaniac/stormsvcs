"""Load a capa rules directory and convert it into the records slib.capa models in Synapse.

Every capa rule becomes a ``meta:rule`` (see ``ruleRecord``) and every rule namespace
becomes a tag under the configured prefix (see ``tagRecords``), ex. the namespace
``anti-analysis/anti-debugging`` is the tag ``<prefix>.anti_analysis.anti_debugging``.
"""


import functools
import hashlib
import os
import re
from pathlib import Path
from typing import Any

import capa.rules
import capa.rules.cache
import synapse.common as s_common
import synapse.datamodel as s_datamodel
import synapse.exc as s_exc
import synapse.lib.types as s_types


RULE_TYPE = "capa"
"""The ``meta:rule:type`` of capa rules."""

LIB_RULE_TYPE = "capa.lib"
"""The ``meta:rule:type`` of capa library rules, which are only used by other rules."""

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
TECHNIQUE_RE = re.compile(r"\[(T\d{4}(?:\.\d{3})?)\]\s*$")
BEHAVIOR_RE = re.compile(r"\[([A-Z]\d{4}(?:\.[A-Z]?\d{3})?)\]\s*$")


class CapaRulesError(Exception):
    """Raised when a capa rules directory can't be loaded."""

    def __init__(self, mesg: str) -> None:
        super().__init__(mesg)
        self.mesg = mesg


def ruleGuid(name: str) -> str:
    """The ``meta:rule`` guid of a capa rule, by its (unique) name."""

    return s_common.guid(("slib.capa", "rule", name))


def rulesetGuid(version: str) -> str:
    """The ``meta:ruleset`` guid of a version of the capa rules."""

    return s_common.guid(("slib.capa", "ruleset", version))


@functools.cache
def _tagPartType() -> s_types.TagPart:
    """Synapse's ``syn:tag:part`` type, built once (a data model takes a moment to build)."""

    return s_datamodel.Model().type("syn:tag:part")


def tagPart(text: str) -> str:
    """Normalize a tag part with Synapse's own ``syn:tag:part`` type.

    Returns an empty string for text with no valid characters (Synapse rejects those).
    """

    try:
        return _tagPartType().norm(text)[0]
    except s_exc.BadTypeValu:
        return ""


def nsTag(namespace: str | None) -> str | None:
    """The tag (without a prefix) for a capa rule namespace, or None if it has no namespace."""

    if not namespace:
        return None
    parts = [tagPart(p) for p in namespace.split("/")]
    parts = [p for p in parts if p]
    return ".".join(parts) or None


def contact(author: str) -> dict[str, str]:
    """The ``ps:contact`` guid ctor props for a capa rule author (an email or a handle)."""

    author = author.strip()
    if EMAIL_RE.match(author):
        return {"email": author.lower()}
    return {"name": author.lower()}


def techniques(attack: list[str]) -> list[str]:
    """The ATT&CK technique IDs in a rule's ``att&ck`` meta, ex. ``Execution::... [T1059]``."""

    ids = []
    for entry in attack:
        if (match := TECHNIQUE_RE.search(str(entry))) and match.group(1) not in ids:
            ids.append(match.group(1))
    return ids


def ruleDoc(meta: dict[str, Any]) -> str:
    """A Markdown description of a capa rule built from all of the documentation in its meta."""

    lines = []
    if desc := str(meta.get("description") or "").strip():
        lines.extend([desc, ""])

    if meta.get("lib"):
        lines.extend([
            "This is a capa library rule. It is only used by other rules, capa never reports it.",
            "",
        ])

    if namespace := meta.get("namespace"):
        lines.append(f"Namespace: {namespace}")

    scopes = meta.get("scopes") or {}
    if isinstance(scopes, dict) and scopes:
        lines.append("Scopes: " + ", ".join(f"{k}: {v}" for k, v in scopes.items()))

    if authors := meta.get("authors"):
        lines.append("Authors: " + ", ".join(str(a) for a in authors))

    for title, key in (
        ("ATT&CK", "att&ck"),
        ("MBC", "mbc"),
        ("MAEC malware category", "maec/malware-category"),
        ("MAEC malware family", "maec/malware-family"),
        ("References", "references"),
        ("Examples", "examples"),
    ):
        vals = meta.get(key)
        if not vals:
            continue
        if not isinstance(vals, (list, tuple)):
            vals = [vals]
        lines.extend(["", f"{title}:"])
        lines.extend(f"- {v}" for v in vals)

    return "\n".join(lines).strip()


def ruleMeta(meta: dict[str, Any]) -> dict[str, Any]:
    """The JSON safe copy of a rule's meta, saved as node data on its ``meta:rule``."""

    def norm(valu):
        if isinstance(valu, dict):
            return {str(k): norm(v) for k, v in valu.items()}
        if isinstance(valu, (list, tuple, set)):
            return [norm(v) for v in valu]
        if valu is None or isinstance(valu, (str, int, float, bool)):
            return valu
        return str(valu)

    return norm(meta)


def readRules(path: str) -> list[tuple[str, str]]:
    """Read every rule file in a capa rules directory.

    Returns
    -------
    list[tuple[str, str]]
        The ``(path, text)`` of every rule, sorted by path (relative to the directory).

    Raises
    ------
    CapaRulesError
        If the directory is missing, has no rules, or a rule can't be read as UTF-8.
    """

    root = Path(path)
    if not root.is_dir():
        raise CapaRulesError(f"The capa rules directory {path} does not exist.")

    try:
        paths = sorted(capa.rules.collect_rule_file_paths([root]))
    except OSError as err:
        raise CapaRulesError(f"Unable to read the capa rules directory {path}: {err}") from None
    if not paths:
        raise CapaRulesError(f"The capa rules directory {path} has no rules.")

    files = []
    for rpath in paths:
        relpath = rpath.relative_to(root).as_posix()
        try:
            text = rpath.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as err:
            raise CapaRulesError(f"Unable to read the capa rule {relpath}: {err}") from None
        files.append((relpath, text))
    return files


def hashRules(files: list[tuple[str, str]]) -> str:
    """The SHA256 of a rules directory's rules (see ``readRules``), their paths and contents."""

    hasher = hashlib.sha256()
    for relpath, text in files:
        hasher.update(relpath.encode() + b"\x00" + text.encode() + b"\x00")
    return hasher.hexdigest()


def rulesSha256(path: str) -> str:
    """The SHA256 of the rules in a capa rules directory, as they are on disk now."""

    return hashRules(readRules(path))


class CapaRules:
    """A loaded capa rules directory and the Synapse records for its rules and namespaces.

    Parameters
    ----------
    path : str
        The capa rules directory (ex. a checkout of ``mandiant/capa-rules``).
    version : str
        The version of the rules (ex. a capa-rules release tag) used to build URLs and
        name the ``meta:ruleset``.
    urlfmt : str | None
        A ``str.format`` template for a rule's URL, given ``version`` and ``path`` (the rule's
        path relative to the rules directory). None (or empty) for no URLs.
    """

    def __init__(self, path: str, version: str, urlfmt: str | None = None) -> None:
        self.path = os.path.abspath(path)
        self.version = version
        self.urlfmt = urlfmt or None
        self.rules: dict[str, dict[str, Any]] = {}
        self.sha256 = ""
        self.load()

    def load(self) -> None:
        """Parse every rule in the rules directory.

        Raises
        ------
        CapaRulesError
            If the directory is missing, has no rules, has an unreadable or invalid rule,
            or has two rules with the same name.
        """

        files = readRules(self.path)

        rules = {}
        for relpath, text in files:
            try:
                rule = capa.rules.Rule.from_yaml(text)
            except Exception as err:
                raise CapaRulesError(f"Invalid capa rule {relpath}: {err}") from None

            if rule.name in rules:
                raise CapaRulesError(
                    f"Duplicate capa rule name {rule.name!r} in {relpath} and "
                    f"{rules[rule.name]['path']}."
                )
            rules[rule.name] = self.ruleRecord(rule.meta, text, relpath)

        self.rules = rules
        self.sha256 = hashRules(files)
        # The name capa gives its cache of these rules, see cacheName.
        self.cacheId = capa.rules.cache.compute_cache_identifier(
            [text.encode("utf-8") for _, text in files]
        )

    def cacheName(self, cachedir: str) -> str:
        """The file name capa caches these rules under in a cache directory."""

        return capa.rules.cache.get_cache_path(Path(cachedir), self.cacheId).name

    def url(self, relpath: str) -> str | None:
        """The URL that documents a rule, by its path relative to the rules directory."""

        if not self.urlfmt:
            return None
        return self.urlfmt.format(version=self.version, path=relpath)

    def ruleRecord(self, meta: dict[str, Any], text: str, relpath: str) -> dict[str, Any]:
        """The record slib.capa models a capa rule's ``meta:rule`` node from."""

        namespace = meta.get("namespace") or None
        lib = bool(meta.get("lib", False))
        return {
            "guid": ruleGuid(meta["name"]),
            "name": meta["name"],
            "namespace": namespace,
            "tag": None if lib else nsTag(namespace),
            "lib": lib,
            "type": LIB_RULE_TYPE if lib else RULE_TYPE,
            "desc": ruleDoc(meta),
            "text": text,
            "path": relpath,
            "url": self.url(relpath),
            "authors": [contact(str(a)) for a in meta.get("authors") or ()],
            "techniques": techniques(meta.get("att&ck") or ()),
            "meta": ruleMeta(meta),
        }

    def info(self) -> dict[str, Any]:
        """A summary of the loaded rules."""

        return {
            "path": self.path,
            "version": self.version,
            "sha256": self.sha256,
            # Changes when anything slib.capa.sync models from the rules changes.
            "key": s_common.guid((self.sha256, self.version, self.urlfmt)),
            "ruleset": rulesetGuid(self.version),
            "rules": len(self.rules),
            "lib": sum(1 for r in self.rules.values() if r["lib"]),
            "namespaces": len(self.namespaces()),
        }

    def namespaces(self) -> dict[str, list[str]]:
        """The namespace of every (non-library) rule, and the names of the rules in each."""

        names: dict[str, list[str]] = {}
        for rule in self.rules.values():
            if rule["lib"] or not rule["tag"]:
                continue
            names.setdefault(rule["namespace"], []).append(rule["name"])
        return {ns: sorted(rules) for ns, rules in sorted(names.items())}

    def tagRecords(self) -> list[dict[str, Any]]:
        """The tags (without a prefix) for every namespace, and every namespace above them.

        Each record is a dict with the tag (``tag``, empty for the prefix itself), a ``title``,
        and a Markdown ``doc`` that lists the rules in the namespace.
        """

        direct: dict[str, list[str]] = {}
        below: dict[str, set[str]] = {}
        nsnames: dict[str, str] = {}

        for namespace, rules in self.namespaces().items():
            tag = nsTag(namespace)
            direct.setdefault(tag, []).extend(rules)
            nsnames.setdefault(tag, namespace)

            parts = namespace.split("/")
            for i in range(len(parts)):
                upns = "/".join(parts[:i])
                uptag = nsTag(upns) or ""
                nsnames.setdefault(uptag, upns)
                below.setdefault(uptag, set()).update(rules)
                direct.setdefault(uptag, [])

        records = []
        for tag in sorted(direct):
            namespace = nsnames[tag]
            if not tag:
                title = "capa"
                doc = [(
                    f"Files that matched capa rules (capa-rules {self.version}). Each tag below "
                    "this one is a capa rule namespace, ex. anti-analysis/anti-debugging is "
                    "anti_analysis.anti_debugging."
                )]
            else:
                title = f"capa: {namespace}"
                doc = [f"Files that matched a capa rule in the {namespace} namespace."]

            if rules := sorted(set(direct[tag])):
                doc.extend(["", "Rules:"])
                doc.extend(f"- {name}" for name in rules)

            if tag and (subrules := len(below.get(tag, set()) - set(direct[tag]))):
                doc.extend(["", f"Plus {subrules} rules in the namespaces below this one."])

            records.append({
                "tag": tag,
                "namespace": namespace,
                "title": title,
                "doc": "\n".join(doc),
            })

        return records

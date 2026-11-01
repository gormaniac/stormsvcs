"""Custom capa rules, written by Synapse users as ``meta:rule`` nodes.

A custom rule is a ``meta:rule`` with a ``:type`` of ``capa.custom`` (or a type below it)
and the capa rule's YAML in ``:text``. The Storm package sends the custom rules in the
view to the service before it scans, and capa runs with them and the official rules.

Official rules win: a custom rule with the same name as an official rule is skipped
(``shadowed``), and the node is left as it is. Invalid custom rules are skipped too.
"""

import hashlib
import os
import re
import shutil
import uuid
from pathlib import Path
from typing import Any

import capa.rules
import capa.rules.cache

from .rules import CapaRules, ruleRecord

CUSTOM_RULE_TYPE = "capa.custom"
"""The ``meta:rule:type`` of custom capa rules (types below it count too)."""

GUID_RE = re.compile(r"^[0-9a-f]{32}$")


class CustomRules:
    """A set of custom capa rules, checked against the official rules and saved to disk.

    Parameters
    ----------
    official : CapaRules
        The official rules the custom rules are used with.
    rules : list[dict]
        The custom rules, each a dict of the ``guid`` of its ``meta:rule`` and its ``text``.
    rootdir : str
        The directory custom rule sets are saved in, each set in a directory named for its key.
    """

    def __init__(self, official: CapaRules, rules: list[dict[str, Any]], rootdir: str) -> None:
        self.official = official
        self.records: dict[str, dict[str, Any]] = {}
        self.errors: list[dict[str, str]] = []
        self.shadowed: list[dict[str, str]] = []
        self.texts: dict[str, str] = {}

        for item in sorted(rules, key=lambda r: str(r.get("guid"))):
            self._add(item)

        hasher = hashlib.sha256()
        for guid, text in sorted(self.texts.items()):
            hasher.update(guid.encode() + b"\x00" + text.encode() + b"\x00")
        self.key = hasher.hexdigest() if self.texts else None

        self.path = None
        self.cacheId = None
        if self.key is not None:
            self.path = os.path.join(rootdir, self.key)
            self._save()
            # capa's cache is for the official and custom rules together.
            self.cacheId = capa.rules.cache.compute_cache_identifier(
                [r["text"].encode("utf-8") for r in official.rules.values()]
                + [text.encode("utf-8") for text in self.texts.values()]
            )

    def _add(self, item: dict[str, Any]) -> None:
        guid = str(item.get("guid") or "")
        text = item.get("text")

        if not GUID_RE.match(guid):
            self.errors.append({"guid": guid, "mesg": "Not a meta:rule guid."})
            return
        if not text or not isinstance(text, str):
            self.errors.append({"guid": guid, "mesg": "The rule has no :text."})
            return

        try:
            rule = capa.rules.Rule.from_yaml(text)
        except Exception as err:
            self.errors.append({"guid": guid, "mesg": f"Invalid capa rule: {err}"})
            return

        name = rule.name
        if name in self.official.rules:
            self.shadowed.append({"guid": guid, "name": name})
            return
        if name in self.records:
            other = self.records[name]["guid"]
            self.errors.append(
                {
                    "guid": guid,
                    "mesg": f"Another custom rule (meta:rule={other}) has the same name: {name}",
                }
            )
            return

        self.texts[guid] = text
        self.records[name] = ruleRecord(
            rule.meta,
            text,
            guid=guid,
            type=CUSTOM_RULE_TYPE,
            custom=True,
        )

    def _save(self) -> None:
        """Write the rules to this set's directory, one file per rule (named for its guid)."""

        if os.path.isdir(self.path):
            return
        # Written to a temporary directory first, so capa never sees a partial set.
        tmp = f"{self.path}.{uuid.uuid4().hex}.tmp"
        os.makedirs(tmp)
        for guid, text in self.texts.items():
            with open(os.path.join(tmp, f"{guid}.yml"), "w", encoding="utf-8") as fd:
                fd.write(text)
        try:
            os.rename(tmp, self.path)
        except OSError:
            # Another registration of the same set saved it first.
            shutil.rmtree(tmp, ignore_errors=True)
            if not os.path.isdir(self.path):
                raise

    def cacheName(self, cachedir: str) -> str | None:
        """The file name capa caches the official and these rules under in a cache directory."""

        if self.cacheId is None:
            return None
        return capa.rules.cache.get_cache_path(Path(cachedir), self.cacheId).name

    def info(self) -> dict[str, Any]:
        """A summary of the set: its key, the rules in it, and the rules that were skipped."""

        return {
            "key": self.key,
            "rules": sorted(
                ({"guid": r["guid"], "name": r["name"]} for r in self.records.values()),
                key=lambda r: r["name"],
            ),
            "errors": self.errors,
            "shadowed": self.shadowed,
        }

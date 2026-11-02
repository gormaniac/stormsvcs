"""A small BibTeX parser for Malpedia's library exports (``/api/get/bib*``).

Malpedia's BibTeX is machine generated and regular::

    @online{research:20260310:sednit:86e9801,
       author = {ESET Research},
       title = {{Sednit reloaded: Back in the trenches}},
       date = {2026-03-10},
       organization = {ESET Research},
       url = {https://www.welivesecurity.com/en/eset-research/sednit-reloaded-back-trenches/},
       language = {English},
       urldate = {2026-03-11}
    }

The parser doesn't rely on that layout though. It handles nested braces, quoted values, bare
values, ``#`` concatenation, comments, and ``@comment``/``@preamble``/``@string`` blocks, and
skips any entry it can't parse instead of failing the whole file.
"""

import re

# BibTeX block types that aren't library entries.
_SKIP_TYPES = frozenset(("comment", "preamble", "string"))

# LaTeX escapes that may appear in field values.
_ESCAPES = {"\\&": "&", "\\%": "%", "\\_": "_", "\\#": "#", "\\$": "$", "\\{": "{", "\\}": "}"}
_ESCRE = re.compile(r"\\[&%_#${}]")

_NAMERE = re.compile(r"[A-Za-z][\w\-:.]*")

# A bare (unquoted, unbraced) value, ex. a number or an @string name.
_BARERE = re.compile(r"[^\s,#}]+")


class BibError(Exception):
    """A BibTeX entry could not be parsed."""


def unescape(text: str) -> str:
    """Strip BibTeX grouping braces and LaTeX escapes from a field value."""

    # Protect escaped braces, drop the grouping ones, then restore the escapes.
    text = text.replace("\\{", "\x00").replace("\\}", "\x01")
    text = text.replace("{", "").replace("}", "")
    text = text.replace("\x00", "\\{").replace("\x01", "\\}")
    text = _ESCRE.sub(lambda m: _ESCAPES[m.group(0)], text)
    return " ".join(text.split())


class _Reader:
    """A cursor over BibTeX text."""

    def __init__(self, text: str):
        self.text = text
        self.size = len(text)
        self.offs = 0

    def skipSpace(self) -> None:
        while self.offs < self.size:
            char = self.text[self.offs]
            if char.isspace():
                self.offs += 1
            elif char == "%":
                # A line comment.
                end = self.text.find("\n", self.offs)
                self.offs = self.size if end == -1 else end + 1
            else:
                return

    def peek(self) -> str:
        return self.text[self.offs] if self.offs < self.size else ""

    def expect(self, char: str) -> None:
        self.skipSpace()
        if self.peek() != char:
            raise BibError(f"Expected {char!r} at offset {self.offs}.")
        self.offs += 1

    def name(self) -> str:
        self.skipSpace()
        match = _NAMERE.match(self.text, self.offs)
        if match is None:
            raise BibError(f"Expected a name at offset {self.offs}.")
        self.offs = match.end()
        return match.group(0)

    def braced(self) -> str:
        """Read a {...} value (the reader is on the opening brace), returning its contents."""

        depth = 0
        start = self.offs + 1
        while self.offs < self.size:
            char = self.text[self.offs]
            if char == "\\":
                self.offs += 2
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    self.offs += 1
                    return self.text[start : self.offs - 1]
            self.offs += 1
        raise BibError("Unterminated braced value.")

    def quoted(self) -> str:
        """Read a "..." value (the reader is on the opening quote), returning its contents."""

        depth = 0
        self.offs += 1
        start = self.offs
        while self.offs < self.size:
            char = self.text[self.offs]
            if char == "\\":
                self.offs += 2
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            elif char == '"' and depth <= 0:
                self.offs += 1
                return self.text[start : self.offs - 1]
            self.offs += 1
        raise BibError("Unterminated quoted value.")

    def value(self) -> str:
        """Read a field value, joining ``#`` concatenations."""

        parts = []
        while True:
            self.skipSpace()
            char = self.peek()
            if char == "{":
                parts.append(self.braced())
            elif char == '"':
                parts.append(self.quoted())
            else:
                match = _BARERE.match(self.text, self.offs)
                if match is None:
                    raise BibError(f"Expected a value at offset {self.offs}.")
                self.offs = match.end()
                parts.append(match.group(0))
            self.skipSpace()
            if self.peek() == "#":
                self.offs += 1
                continue
            return "".join(parts)

    def skipBlock(self) -> None:
        """Skip a {...} or (...) block after an @type."""

        self.skipSpace()
        if self.peek() == "{":
            self.braced()
        elif self.peek() == "(":
            end = self.text.find(")", self.offs)
            self.offs = self.size if end == -1 else end + 1


def _entry(reader: _Reader, kind: str) -> dict:
    """Parse the body of an entry after its @type. The reader is on the opening brace/paren."""

    opener = reader.peek()
    closer = "}" if opener == "{" else ")"
    reader.offs += 1

    reader.skipSpace()
    end = reader.text.find(",", reader.offs)
    stop = reader.text.find(closer, reader.offs)
    if end == -1 or (stop != -1 and stop < end):
        raise BibError("An entry has no key.")
    key = reader.text[reader.offs : end].strip()
    if not key:
        raise BibError("An entry has an empty key.")
    reader.offs = end + 1

    fields = {}
    while True:
        reader.skipSpace()
        char = reader.peek()
        if char == closer:
            reader.offs += 1
            break
        if char == ",":
            reader.offs += 1
            continue
        if not char:
            raise BibError(f"The entry {key} is unterminated.")
        name = reader.name().lower()
        reader.expect("=")
        fields[name] = unescape(reader.value())

    return {"type": kind, "key": key, "fields": fields}


def parse(text: str) -> tuple[list[dict], list[str]]:
    """Parse BibTeX text.

    Returns
    -------
    tuple
        ``(entries, errors)`` where each entry is ``{"type", "key", "fields"}`` (field names
        are lowercased, values unescaped) and errors are messages for entries that were skipped.
    """

    entries = []
    errors = []
    reader = _Reader(text or "")

    while True:
        start = reader.text.find("@", reader.offs)
        if start == -1:
            break
        reader.offs = start + 1
        # The entry type follows the @ directly, a lone @ is just text.
        match = _NAMERE.match(reader.text, reader.offs)
        if match is None:
            continue
        reader.offs = match.end()
        kind = match.group(0).lower()

        reader.skipSpace()
        if reader.peek() not in ("{", "("):
            continue

        if kind in _SKIP_TYPES:
            reader.skipBlock()
            continue

        mark = reader.offs
        try:
            entries.append(_entry(reader, kind))
        except BibError as err:
            errors.append(f"Skipped a BibTeX @{kind} entry at offset {start}: {err}")
            # Resume at the next line that starts an entry.
            nxt = reader.text.find("\n@", mark)
            reader.offs = reader.size if nxt == -1 else nxt + 1

    return entries, errors

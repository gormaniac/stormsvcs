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
import unicodedata

# BibTeX block types that aren't library entries.
_SKIP_TYPES = frozenset(("comment", "preamble", "string"))

# Fields that hold "A and B and C" name lists.
_NAME_FIELDS = frozenset(("author", "editor"))

# LaTeX escapes that may appear in field values.
_ESCAPES = {"\\&": "&", "\\%": "%", "\\_": "_", "\\#": "#", "\\$": "$", "\\{": "{", "\\}": "}"}
_ESCRE = re.compile(r"\\[&%_#${}]")

_NAMERE = re.compile(r"[A-Za-z][\w\-:.]*")

# A bare (unquoted, unbraced) value, ex. a number or an @string name.
_BARERE = re.compile(r"[^\s,#}]+")

# LaTeX accent commands, mapped to the Unicode combining characters they add.
_ACCENTS = {
    "'": "\u0301",
    "`": "\u0300",
    "^": "\u0302",
    '"': "\u0308",
    "~": "\u0303",
    "=": "\u0304",
    ".": "\u0307",
    "c": "\u0327",
    "v": "\u030c",
    "u": "\u0306",
    "H": "\u030b",
    "k": "\u0328",
    "r": "\u030a",
}
# \'e, \'{e}, {\'e}, \c{c}, \c c (letter commands need braces or a space before the letter).
_ACCENTRE = re.compile(
    r"\\(?:([`'^\"~=.])\s*(?:\{\s*(\\?[A-Za-z])\s*\}|(\\?[A-Za-z]))"
    r"|([cvuHkr])(?:\s*\{\s*(\\?[A-Za-z])\s*\}|\s+([A-Za-z])))"
)
# LaTeX letter commands, ex. \ss and \o.
_LETTERS = {
    "ss": "ß",
    "o": "ø",
    "O": "Ø",
    "ae": "æ",
    "AE": "Æ",
    "oe": "œ",
    "OE": "Œ",
    "aa": "å",
    "AA": "Å",
    "l": "ł",
    "L": "Ł",
    "i": "ı",
    "j": "ȷ",
}
_LETTERRE = re.compile(r"\\(ss|ae|AE|oe|OE|aa|AA|[oOlLij])(?![A-Za-z])\s*(?:\{\})?")

# Marks a backslash in a value that isn't an escape (see _Reader.braced).
_PLAINBS = "\x02"

# " and " between names in an author field.
_ANDRE = re.compile(r"\s+and\s+")


class BibError(Exception):
    """A BibTeX entry could not be parsed."""


def _accent(match: re.Match) -> str:
    cmd = match.group(1) or match.group(4)
    letter = match.group(2) or match.group(3) or match.group(5) or match.group(6)
    # A dotless i or j (\'{\i}) takes the accent like a plain one.
    letter = letter.lstrip("\\")
    return unicodedata.normalize("NFC", letter + _ACCENTS[cmd])


def unlatex(text: str) -> str:
    """Decode the common LaTeX accents and letters, ex. ``M\\"{u}ller`` -> ``Müller``."""

    if "\\" not in text:
        return text
    text = _ACCENTRE.sub(_accent, text)
    return _LETTERRE.sub(lambda m: _LETTERS[m.group(1)], text)


def unescape(text: str) -> str:
    """Strip BibTeX grouping braces and LaTeX escapes from a field value."""

    text = unlatex(text)
    # Protect escaped braces, drop the grouping ones, then restore the escapes.
    text = text.replace("\\{", "\x00").replace("\\}", "\x01")
    text = text.replace("{", "").replace("}", "")
    text = text.replace("\x00", "\\{").replace("\x01", "\\}")
    text = _ESCRE.sub(lambda m: _ESCAPES[m.group(0)], text)
    text = text.replace(_PLAINBS, "\\")
    return " ".join(text.split())


def splitNames(text: str) -> list[str]:
    """Split a raw (still braced) BibTeX name list on the top level ``and`` s, then unescape.

    ``{Ernst and Young} and Jane Doe`` is two names: braces protect an ``and`` inside them.
    """

    names = []
    depth = 0
    start = 0
    offs = 0
    while offs < len(text):
        char = text[offs]
        if char == "\\" and offs + 1 < len(text) and text[offs + 1] in "{}":
            offs += 2
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        elif depth <= 0 and char.isspace():
            match = _ANDRE.match(text, offs)
            if match is not None:
                names.append(text[start:offs])
                start = offs = match.end()
                continue
        offs += 1
    names.append(text[start:])
    out = []
    for name in names:
        name = unescape(name).strip(" ,")
        if name and name not in out:
            out.append(name)
    return out


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

    def _closes(self, offs: int, depth: int) -> bool:
        """Whether ``depth - 1`` more closing braces after offs end the value and the field.

        That's how a ``\\}`` right before a value's closing braces (ex. ``{C:\\}`` or
        ``{{C:\\}}``) is told apart from an escaped brace inside the value.
        """

        need = depth - 1
        while offs < self.size:
            char = self.text[offs]
            if char in " \t\r\n":
                offs += 1
            elif char == "}" and need > 0:
                need -= 1
                offs += 1
            else:
                break
        if need:
            return False
        return offs >= self.size or self.text[offs] in ",})#"

    def braced(self) -> str:
        """Read a {...} value (the reader is on the opening brace), returning its contents.

        ``\\{`` and ``\\}`` are escaped braces, other backslashes (ex. ``\\'e``) are plain
        text. A ``\\}`` right before the braces that end the value and the field is a
        backslash and a closing brace (ex. ``{C:\\}``), not an escape.
        """

        depth = 0
        start = self.offs + 1
        # Offsets (in the value) of backslashes that aren't escapes, see unescape().
        plain = []
        while self.offs < self.size:
            char = self.text[self.offs]
            if char == "\\" and self.offs + 1 < self.size and self.text[self.offs + 1] in "{}":
                if not (self.text[self.offs + 1] == "}" and self._closes(self.offs + 2, depth)):
                    self.offs += 2
                    continue
                # A plain backslash, the brace after it closes the value.
                plain.append(self.offs - start)
                self.offs += 1
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    self.offs += 1
                    text = self.text[start : self.offs - 1]
                    for offs in reversed(plain):
                        text = text[:offs] + _PLAINBS + text[offs + 1 :]
                    return text
            self.offs += 1
        raise BibError("Unterminated braced value.")

    def quoted(self) -> str:
        """Read a "..." value (the reader is on the opening quote), returning its contents."""

        depth = 0
        self.offs += 1
        start = self.offs
        while self.offs < self.size:
            char = self.text[self.offs]
            if char == "\\" and self.offs + 1 < self.size and self.text[self.offs + 1] in '{}"':
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
    names = {}
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
        raw = reader.value()
        fields[name] = unescape(raw)
        if name in _NAME_FIELDS:
            # Split before unescaping, so braces still protect an "and" in a name.
            names[name] = splitNames(raw)

    return {"type": kind, "key": key, "fields": fields, "names": names}


def parse(text: str) -> tuple[list[dict], list[str]]:
    """Parse BibTeX text.

    Returns
    -------
    tuple
        ``(entries, errors)`` where each entry is ``{"type", "key", "fields", "names"}``
        (field names are lowercased, values unescaped, and ``names`` has the author and editor
        fields split into names) and errors are messages for entries that were skipped.
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

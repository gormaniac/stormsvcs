"""The slib.crtsh service.

``CrtshSvc`` queries the crt.sh certwatch database directly (see ``crtshsvc.db``)
and returns the complete details of every certificate it finds (see
``crtshsvc.norm``). Methods raise ``CrtshDbError`` on failure, ``CrtshCellApi``
wraps them in the standard ``TelepathRetn`` convention for Storm.
"""

import ipaddress
import re
from collections.abc import AsyncIterator, Iterable
from typing import Any

import synapse.lib.cell as s_cell

from . import norm
from .api import CrtshCellApi
from .db import DEFAULT_DSN, LOOKUPS, NAME_TYPES, CrtshDb, CrtshDbError, likeEscape

PIVOTS = ("issued", "siblings", "key", "subject", "serial", "ski")
"""The ways to pivot from a certificate to other certificates, see ``CrtshSvc.pivotGenr``."""

HEXRE = re.compile(r"^[0-9a-f]+$")


def _serialVariants(serial: bytes) -> list[bytes]:
    """A serial with and without the DER sign byte, since encodings of it vary."""

    bare = serial.lstrip(b"\x00") or b"\x00"
    variants = [bare]
    if bare[0] & 0x80:
        variants.append(b"\x00" + bare)
    if serial not in variants:
        variants.append(serial)
    return variants


def identityQuery(field: str, valu: str, exact: bool = False) -> tuple[str, str | None]:
    """The full text search text and identity ILIKE pattern for a search field.

    Returns ``(text, like)``. ``like`` is None for fields that aren't a single
    identity (``subject``, a whole DN).
    """

    valu = valu.strip()
    if field == "subject":
        # identities() only indexes attribute values, not their names, so "O=Vertex, CN=x"
        # is searched as "Vertex x". The service matches the whole DN afterwards.
        text = re.sub(r"(^|[,+])\s*[A-Za-z0-9][\w.-]*\s*=", " ", valu)
        return " ".join(text.split()), None

    if field == "ip":
        # crt.sh renders IPv6 SANs uncompressed, as ":2001:DB8:0:0:0:0:0:1".
        try:
            addr = ipaddress.ip_address(valu)
        except ValueError:
            raise CrtshDbError(f"Invalid IP address: {valu}") from None
        if addr.version == 6:
            valu = ":" + ":".join(format(int(g, 16), "X") for g in addr.exploded.split(":"))
        else:
            valu = str(addr)
        return valu, likeEscape(valu)

    pattern = likeEscape(valu.lstrip("*").lstrip(".") if field == "dns" else valu)
    if exact:
        return valu, pattern
    if field == "dns":
        # The domain itself, its subdomains, and wildcards for it.
        return valu, "%" + pattern
    return valu, "%" + pattern + "%"


def lookupValu(kind: str, valu: Any) -> list:
    """Convert a user supplied identifier into the database values it may be stored as."""

    if kind not in LOOKUPS:
        raise CrtshDbError(f"Unknown lookup type {kind}, expected one of: {', '.join(LOOKUPS)}")

    if kind == "id":
        try:
            return [int(valu)]
        except (TypeError, ValueError):
            raise CrtshDbError(f"Invalid crt.sh ID: {valu}") from None

    text = norm.normHex(str(valu))
    text = text.removeprefix("0x")
    if not text or not HEXRE.match(text):
        raise CrtshDbError(f"Invalid {kind}, expected a hex string: {valu}")

    if kind == "serial":
        return _serialVariants(norm.serialBytes(text))

    sizes = {"sha256": 64, "sha1": 40, "spki": 64, "spkisha1": 40, "subjectsha1": 40}
    if kind in sizes and len(text) != sizes[kind]:
        raise CrtshDbError(f"Invalid {kind}, expected {sizes[kind]} hex characters: {valu}")
    if len(text) % 2:
        raise CrtshDbError(f"Invalid {kind}, expected an even number of hex characters: {valu}")
    return [bytes.fromhex(text)]


def guessKind(valu: Any) -> str:
    """Guess the identifier type of a value: a crt.sh ID, SHA-256, or SHA-1 fingerprint."""

    if isinstance(valu, int):
        return "id"
    text = norm.normHex(str(valu))
    if text.isdigit() and len(text) < 20:
        return "id"
    if HEXRE.match(text):
        if len(text) == 64:
            return "sha256"
        if len(text) == 40:
            return "sha1"
    raise CrtshDbError(
        f"Unable to tell what kind of identifier {valu} is, specify one of: {', '.join(LOOKUPS)}"
    )


class CrtshSvc(s_cell.Cell):
    """The Cell implementation for the slib.crtsh service."""

    cellapi = CrtshCellApi

    confdefs = {
        "crtsh:dsn": {
            "type": "string",
            "default": DEFAULT_DSN,
            "description": "The PostgreSQL DSN of the crt.sh certwatch database (or a mirror of it).",
        },
        "crtsh:timeout": {
            "type": "number",
            "default": 0,
            "description": (
                "Seconds before a single query times out, 0 for no timeout. crt.sh is slow, "
                "big searches can take minutes."
            ),
        },
        "crtsh:statement:timeout": {
            "type": "number",
            "default": 0,
            "description": (
                "The statement_timeout, in seconds, set on crt.sh connections, 0 for no limit. "
                "crt.sh's default cancels big queries (chains, wide searches) that finish given time."
            ),
        },
        "crtsh:retries": {
            "type": "integer",
            "default": 3,
            "description": "How many times to retry a query when the connection drops.",
        },
        "crtsh:keepalive": {
            "type": "number",
            "default": 10,
            "description": (
                "Seconds between keepalive pings while the connection is in use. crt.sh drops "
                "idle clients quickly (client_idle_timeout)."
            ),
        },
        "crtsh:idle": {
            "type": "number",
            "default": 300,
            "description": (
                "Seconds without a query before the connection is closed. crt.sh only allows one "
                "connection per client, closing it frees it for others from the same IP."
            ),
        },
        "crtsh:connect:timeout": {
            "type": "number",
            "default": 300,
            "description": (
                "Seconds to keep retrying (with backoff) when crt.sh refuses a connection, "
                "ex. max_client_conn right after a dropped connection."
            ),
        },
        "crtsh:limit": {
            "type": "integer",
            "default": 10000,
            "description": "The max number of certificates any one call may return.",
        },
        "crtsh:candidates": {
            "type": "integer",
            "default": 10000,
            "description": (
                "The max number of full text search candidates a search will filter (crt.sh's "
                "own search uses 10000). Searches for very common names only see this many."
            ),
        },
    }

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)

        self.db = CrtshDb(
            dsn=self.conf.get("crtsh:dsn"),
            timeout=self.conf.get("crtsh:timeout"),
            retries=self.conf.get("crtsh:retries"),
            keepalive=self.conf.get("crtsh:keepalive"),
            idle=self.conf.get("crtsh:idle"),
            connect_timeout=self.conf.get("crtsh:connect:timeout"),
            statement_timeout=self.conf.get("crtsh:statement:timeout"),
        )
        self.onfini(self.db.close)

    def _limit(self, limit: int | None) -> int:
        maxlimit = self.conf.get("crtsh:limit")
        if not limit or limit < 0:
            return maxlimit
        return min(int(limit), maxlimit)

    # ---- Building certificate details ----

    @staticmethod
    def _parse(rows: Iterable[dict]) -> list[tuple[dict, dict]]:
        """Parse certificate rows into (row, details) tuples, dropping duplicates."""

        seen, items = set(), []
        for row in rows:
            if row["id"] in seen:
                continue
            seen.add(row["id"])
            items.append((row, norm.certDetails(row)))
        return items

    @staticmethod
    def _sort(items: list[tuple[dict, dict]]) -> list[tuple[dict, dict]]:
        """Newest (by notBefore) first, then by highest crt.sh ID."""
        return sorted(items, key=lambda item: (norm.certTime(item[1]), -item[0]["id"]))

    @staticmethod
    def _lookups(kind: str | None, valus) -> dict[str, list]:
        """Group identifiers into {kind: [database values]}, guessing kinds that aren't given."""

        if not isinstance(valus, (list, tuple)):
            valus = [valus]
        lookups: dict[str, list] = {}
        for valu in valus:
            vkind = kind or guessKind(valu)
            lookups.setdefault(vkind, []).extend(lookupValu(vkind, valu))
        return lookups

    async def _one(self, kind: str | None, valu) -> dict:
        """The row of a single certificate, or raise if crt.sh doesn't have it."""

        rows = await self.db.certs(self._lookups(kind, valu), limit=1)
        if not rows:
            raise CrtshDbError(f"crt.sh has no certificate with {kind or guessKind(valu)} {valu}")
        return rows[0]

    # ---- Lookups ----

    async def lookup(self, kind: str | None, valus, limit: int = 100) -> list[dict]:
        """Find certificates by a unique identifier and return their complete details, newest first.

        ``kind`` is one of ``id``, ``sha256``, ``sha1``, ``serial``, ``ski`` (subject key
        identifier), ``spki``/``spkisha1`` (public key hash), or ``subjectsha1`` (subject
        name hash). When it's None, each value's kind is guessed (a crt.sh ID, SHA-256, or
        SHA-1). ``valus`` is a value or list of values. Serials, SKIs, keys, and
        subjects can match many certificates, up to ``limit`` are returned.
        """

        limit = self._limit(limit)
        rows = await self.db.certs(self._lookups(kind, valus), limit=limit)
        return [details for _, details in self._sort(self._parse(rows))[:limit]]

    async def get(self, valu, kind: str | None = None) -> dict | None:
        """Get a single certificate by crt.sh ID, SHA-256, or SHA-1 (or any ``kind``).

        Returns the newest match, or None when crt.sh doesn't have it.
        """

        kind = kind or guessKind(valu)
        certs = await self.lookup(kind, valu, limit=1 if kind in ("id", "sha256") else 100)
        return certs[0] if certs else None

    # ---- Search ----

    async def searchGenr(
        self,
        dns=None,
        cn=None,
        org=None,
        ou=None,
        email=None,
        ip=None,
        uri=None,
        subject=None,
        identity=None,
        issuer=None,
        caids=None,
        exact: bool = False,
        valid: bool = False,
        since: int | None = None,
        until: int | None = None,
        precerts: bool = True,
        limit: int = 100,
    ) -> AsyncIterator[dict]:
        """Search certificates by their properties, yielding the complete details of each, newest first.

        Every given field must match. ``dns`` matches the domain and its subdomains
        (or only the domain itself with ``exact``), the other text fields match
        substrings (or the whole value with ``exact``). ``issuer`` matches the
        issuing CA's name and ``caids`` the issuing crt.sh CA IDs. ``valid`` only
        returns unexpired certificates, ``since``/``until`` bound notBefore (epoch
        millis), and ``precerts=False`` drops precertificates.
        """

        limit = self._limit(limit)
        fields = {
            "dns": dns,
            "cn": cn,
            "org": org,
            "ou": ou,
            "email": email,
            "ip": ip,
            "uri": uri,
            "subject": subject,
            "identity": identity,
        }
        fields = {k: str(v) for k, v in fields.items() if v not in (None, "")}
        caids = list(caids or [])
        issuer = str(issuer) if issuer else None

        if not fields and not caids and not issuer:
            raise CrtshDbError("A search needs at least one certificate field or an issuer.")

        if fields:
            # Search crt.sh on the most specific field, then filter on every field.
            field = next(
                k
                for k in ("dns", "email", "ip", "cn", "uri", "org", "ou", "subject", "identity")
                if k in fields
            )
            text, like = identityQuery(field, fields[field], exact)
            candidates = min(max(limit * 5, 500), self.conf.get("crtsh:candidates"))
            rows = await self.db.certsByIdentity(
                text,
                like=like,
                nametypes=NAME_TYPES.get(field),
                caids=caids or None,
                issuer=issuer,
                valid=valid,
                since=since,
                until=until,
                limit=candidates,
            )
        else:
            rows = await self.db.certsByIssuer(
                caids=caids or None,
                issuer=issuer,
                valid=valid,
                since=since,
                until=until,
                limit=limit if precerts else limit * 2,
            )

        def keep(details: dict) -> bool:
            if not precerts and details.get("precert"):
                return False
            for field, valu in fields.items():
                mode = "exact" if exact else ("suffix" if field == "dns" else "contains")
                if not norm.matches(details, field, valu, mode):
                    return False
            return True

        for _, details in self._sort([item for item in self._parse(rows) if keep(item[1])])[:limit]:
            yield details

    # ---- Pivots ----

    async def issuedGenr(
        self,
        caids=None,
        kind: str | None = None,
        valu=None,
        valid: bool = False,
        since: int | None = None,
        until: int | None = None,
        precerts: bool = True,
        limit: int = 100,
    ) -> AsyncIterator[dict]:
        """Yield the certificates issued by a CA, newest first.

        The CA is given by its crt.sh ``caids``, or by one of its certificates
        (``kind``/``valu``, as in ``lookup``). Every certificate of a CA shares its
        name and key, so certificates issued under any of them are returned.
        """

        caids = list(caids or [])
        cert = self._lookups(kind, valu) if valu is not None else None
        if not caids and not cert:
            raise CrtshDbError("A CA ID or certificate is required.")

        limit = self._limit(limit)
        # Most certificates have a precertificate twin, fetch enough to fill the limit without them.
        rows = await self.db.certsByIssuer(
            caids=sorted(set(caids)) or None,
            cert=cert,
            valid=valid,
            since=since,
            until=until,
            limit=limit if precerts else limit * 2,
        )
        if not rows and cert and not caids and not (await self._one(kind, valu))["caids"]:
            # Explain why: there's no such certificate, or it isn't a CA certificate.
                raise CrtshDbError(
                    f"crt.sh doesn't know of a CA for certificate {valu}, "
                    "it may not be a CA certificate."
                )

        items = [i for i in self._parse(rows) if precerts or not i[1].get("precert")]
        for _, details in self._sort(items)[:limit]:
            yield details

    async def pivotGenr(
        self,
        valu,
        by: str,
        kind: str | None = None,
        valid: bool = False,
        precerts: bool = True,
        limit: int = 100,
    ) -> AsyncIterator[dict]:
        """Yield the certificates related to a certificate, excluding the certificate itself.

        ``by`` is one of:

        - ``issued``: certificates the certificate's CA issued (it must be a CA cert).
        - ``siblings``: other certificates issued by the same CA.
        - ``key``: certificates with the same public key.
        - ``subject``: certificates with the same subject name.
        - ``serial``: certificates with the same serial number, like the precertificate
          and certificate pair, or certificates from other CAs.
        - ``ski``: certificates with the same subject key identifier.
        """

        if by not in PIVOTS:
            raise CrtshDbError(f"Unknown pivot {by}, expected one of: {', '.join(PIVOTS)}")

        if by == "issued":
            async for details in self.issuedGenr(
                kind=kind, valu=valu, valid=valid, precerts=precerts, limit=limit
            ):
                yield details
            return

        limit = self._limit(limit)
        rows = await self.db.related(
            by, self._lookups(kind, valu), valid=valid, limit=limit if precerts else limit * 2
        )
        if not rows:
            # Explain why: there's no such certificate, or nothing to pivot on.
            source = norm.certDetails(await self._one(kind, valu))
            if by != "siblings":
                if source.get("error"):
                    raise CrtshDbError(f"Unable to pivot by {by}: {source['error']}")
                if not {
                    "key": source["pubkey"].get("sha256"),
                    "subject": source["subject"]["sha1"],
                    "serial": source["serial"],
                    "ski": source.get("ski"),
                }[by]:
                    raise CrtshDbError(f"The certificate has no {by} to pivot on.")

        items = [i for i in self._parse(rows) if precerts or not i[1].get("precert")]
        for _, details in self._sort(items)[:limit]:
            yield details

    async def chain(
        self, valu, kind: str | None = None, maxdepth: int = 10, maxcerts: int = 100
    ) -> dict:
        """Build every certificate chain from a certificate up to its root(s), in one query.

        crt.sh groups certificates by CA (a name and key), so a certificate's issuer
        may have several certificates: cross-signs and reissues. Each of them is a
        possible parent, so this returns a graph of every path up to a root::

            {
                "leaf": <sha256>,
                "certs": [<details>, ...],                      # the leaf first
                "links": [{"child": <sha256>, "parent": <sha256>, "preferred": bool}, ...],
                "paths": [[<leaf sha256>, ..., <root sha256>], ...],
            }

        The ``preferred`` parent of each certificate was valid when the child was
        issued and expires last, it's the one most clients would build a chain with.
        At most ``maxcerts`` certificates, the closest to the leaf, are returned.
        """

        rows = await self.db.chain(self._lookups(kind, valu), maxdepth=maxdepth)
        if not rows:
            raise CrtshDbError(f"crt.sh has no certificate with {kind or guessKind(valu)} {valu}")

        rows.sort(key=lambda row: (row["depth"], row["id"]))
        details: dict[int, dict] = {}
        for row, det in self._parse(rows):
            if len(details) < maxcerts:
                details[row["id"]] = det

        # Each (child, parent) row is unique, a certificate belongs to one CA (ca_certificate's key).
        parents: dict[int, list[int]] = {}
        for row in rows:
            if row["child_id"] in details and row["id"] in details:
                parents.setdefault(row["child_id"], []).append(row["id"])

        links = []
        for childid, parentids in parents.items():
            child = details[childid]
            cands = [details[p] for p in parentids]
            preferred = _preferredParent(child, cands)
            for parent in cands:
                links.append(
                    {
                        "child": child["sha256"],
                        "parent": parent["sha256"],
                        "preferred": parent is preferred,
                    }
                )

        leaf = details[rows[0]["id"]]["sha256"]
        return {
            "leaf": leaf,
            "certs": list(details.values()),
            "links": links,
            "paths": _paths(leaf, links),
        }

    # ---- CAs ----

    async def cas(
        self, name: str | None = None, caids=None, certs: bool = False, limit: int = 100
    ) -> list[dict]:
        """Find crt.sh CAs by name (a substring of the CA's DN) or ID.

        Returns ``{"id", "name", "certs"}`` dicts. ``certs`` holds the complete details
        of each of the CA's certificates when ``certs`` is true, otherwise just their crt.sh IDs.
        """

        if not caids and not name:
            raise CrtshDbError("A CA name or ID is required.")

        rows = await self.db.cas(
            caids=[int(c) for c in caids] if caids else None,
            name=name or None,
            certs=certs,
            limit=self._limit(limit),
        )
        rows.sort(key=lambda row: (row["ca_id"], row["id"] or 0))
        cas: dict[int, dict] = {}
        for row in rows:
            ca = cas.setdefault(
                row["ca_id"], {"id": row["ca_id"], "name": row["ca_name"], "certs": []}
            )
            if row["id"] is not None:
                ca["certs"].append(norm.certDetails(row) if certs else row["id"])
        return list(cas.values())

    # ---- Escape hatch ----

    async def rawQuery(self, sql: str, args: list | None = None) -> list[dict]:
        """Run raw SQL against crt.sh. Bytes are hex encoded and times are epoch millis."""

        return [_safeRow(row) for row in await self.db.raw(sql, args)]


def _safeRow(row: dict) -> dict:
    """Make a raw database row Telepath safe."""

    def conv(valu):
        if isinstance(valu, (bytes, bytearray, memoryview)):
            return norm.hexBytes(bytes(valu))
        if isinstance(valu, norm.datetime.datetime):
            return norm.toMillis(valu)
        if isinstance(valu, (list, tuple)):
            return [conv(v) for v in valu]
        if valu is None or isinstance(valu, (str, int, float, bool)):
            return valu
        return str(valu)

    return {key: conv(valu) for key, valu in row.items()}


def _preferredParent(child: dict, cands: list[dict]) -> dict | None:
    """Pick the parent most clients would use: valid when the child was issued, expiring last."""

    if not cands:
        return None

    nb = child.get("notbefore") or 0

    def score(parent):
        covers = (parent.get("notbefore") or 0) <= nb <= (parent.get("notafter") or 0)
        return (covers, not parent.get("precert"), parent.get("notafter") or 0)

    return max(cands, key=score)


def _paths(leaf: str, links: list[dict], maxpaths: int = 50) -> list[list[str]]:
    """Every path from the leaf to a root, preferred parents first."""

    parents: dict[str, list[dict]] = {}
    for link in links:
        parents.setdefault(link["child"], []).append(link)
    for cands in parents.values():
        cands.sort(key=lambda link: not link["preferred"])

    paths: list[list[str]] = []

    def walk(path: list[str]):
        if len(paths) >= maxpaths:
            return
        cands = [link for link in parents.get(path[-1], []) if link["parent"] not in path]
        if not cands:
            paths.append(path)
            return
        for link in cands:
            walk(path + [link["parent"]])

    walk([leaf])
    return paths

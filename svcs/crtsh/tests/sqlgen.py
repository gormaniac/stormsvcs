"""Generate a psql script of every query the slib.crtsh service runs, for testing them by hand.

    uv run python -m tests.sqlgen > tests/live_queries.sql
    psql -h crt.sh -p 5432 -U guest certwatch -f tests/live_queries.sql

The SQL comes straight from ``CrtshDb`` (a recording ``fetch``), with its ``$n``
parameters rendered as literals or psql variables. The hashes, serial, and key IDs
of a sample certificate are looked up once with ``\\gset`` so the lookups use constants.
Queries that return certificates are wrapped to print a row count and the DER size
instead of the DER itself.
"""


import asyncio
import re
import sys

from crtshsvc.db import NAME_TYPES, CrtshDb
from crtshsvc.svc import identityQuery


CERTID = 29578180990
"""A www.comodo.com certificate (crt.sh ID)."""

ISSUER = 204411
"""Its issuing crt.sh CA ID."""

SINCE = 1735689600000
"""2025-01-01, epoch millis."""

UNTIL = 1767225600000
"""2026-01-01, epoch millis."""


class Var:
    """A psql variable holding a hex string, rendered as bytea."""

    def __init__(self, name: str):
        self.name = name

    def __str__(self) -> str:
        return f"decode(:'{self.name}', 'hex')"


class IntVar(Var):
    """A psql variable holding an integer."""

    def __str__(self) -> str:
        return f":{self.name}"


def literal(valu) -> str:
    """Render a query argument as SQL."""

    if isinstance(valu, Var):
        return str(valu)
    if isinstance(valu, bool):
        return "TRUE" if valu else "FALSE"
    if isinstance(valu, (int, float)):
        return repr(valu)
    if isinstance(valu, str):
        return "'" + valu.replace("'", "''") + "'"
    if isinstance(valu, (list, tuple)):
        return "ARRAY[" + ", ".join(literal(v) for v in valu) + "]"
    raise TypeError(f"Can't render {valu!r}")


def render(sql: str, args: tuple) -> str:
    """Substitute $n parameters, highest first so $1 doesn't clobber $10."""

    for num in range(len(args), 0, -1):
        sql = sql.replace(f"${num}", literal(args[num - 1]))
    return sql


class Recorder(CrtshDb):
    """A CrtshDb that records the SQL it would run instead of running it."""

    def __init__(self):
        super().__init__()
        self.queries: list[tuple[str, str]] = []
        self.title = ""

    async def fetch(self, sql: str, *args) -> list[dict]:
        sql = render(sql, args)
        if re.search(r"\bAS der\b", sql):
            sql = f"SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM ({sql}) q"
        self.queries.append((self.title, sql))
        return []


async def record() -> Recorder:
    db = Recorder()

    async def q(title: str, coro):
        db.title = title
        await coro

    # Lookups by every identifier kind, each with the sample certificate's values.
    await q("Lookup by crt.sh ID", db.certs("id", [IntVar("certid")], limit=1))
    for kind in ("sha256", "sha1", "ski", "spki", "spkisha1", "subjectsha1"):
        await q(f"Lookup by {kind}", db.certs(kind, [Var(kind)], limit=100))
    await q("Lookup by serial (with and without the DER sign byte)",
            db.certs("serial", [Var("serial"), Var("serial00")], limit=100))

    # Searches, one per field, using the same patterns the service builds.
    samples = {
        "dns": "www.comodo.com", "cn": "www.comodo.com", "org": "Sectigo Limited",
        "ou": "Domain Control Validated", "email": "comodo.com", "ip": "8.8.8.8",
        "uri": "comodo.com",
    }
    for field, valu in samples.items():
        text, like = identityQuery(field, valu)
        await q(f"Search --{field} {valu}",
                db.certsByIdentity(text, like=like, nametypes=NAME_TYPES[field], limit=500))

    text, like = identityQuery("dns", "www.comodo.com", exact=True)
    await q("Search --dns www.comodo.com --exact",
            db.certsByIdentity(text, like=like, nametypes=NAME_TYPES["dns"], limit=500))
    text, like = identityQuery("ip", "2606:4700:4700::1111")
    await q("Search --ip 2606:4700:4700::1111",
            db.certsByIdentity(text, like=like, nametypes=NAME_TYPES["ip"], limit=500))
    await q("Search --identity comodo.com",
            db.certsByIdentity("comodo.com", like="%comodo.com%", limit=500))
    await q("Search --subject (full text only)",
            db.certsByIdentity("Sectigo Limited", limit=500))

    text, like = identityQuery("dns", "comodo.com")
    await q("Search --dns comodo.com --valid --since 2025-01-01 --until 2026-01-01 --caid",
            db.certsByIdentity(text, like=like, nametypes=NAME_TYPES["dns"],
                               caids=[IntVar("issuer")], valid=True, since=SINCE, until=UNTIL,
                               limit=500))

    # CAs, issued certificates, and chains.
    await q("CAs by name (--issuer)", db.casByName("Sectigo", limit=1000))
    await q("CAs by ID", db.cas([IntVar("issuer")]))
    await q("Certificates a CA issued (pivot --by issued/siblings, ca --issued)",
            db.certsByIssuer([IntVar("issuer")], limit=100))
    await q("Certificates a CA issued, --valid --since",
            db.certsByIssuer([IntVar("issuer")], valid=True, since=SINCE, limit=100))
    await q("Certificates belonging to a CA (chain building, ca --certs)", db.caCerts([IntVar("issuer")]))

    # Per-result metadata, run for every batch of 100 results.
    await q("Metadata: CA membership", db.certCas([IntVar("certid")]))
    await q("Metadata: issuer CA names", db.cas([IntVar("issuer")]))
    await q("Metadata: CT log entries", db.ctlog([IntVar("certid")]))
    await q("Metadata: CRL revocations",
            db.revoked([(IntVar("issuer"), Var("serial")), (IntVar("issuer"), Var("serial00"))]))
    return db


SETUP = f"""\\timing on
\\pset pager off
SET statement_timeout = '120s';

-- The sample certificate and the values the lookups use.
\\set certid {CERTID}
\\set issuer {ISSUER}
SELECT encode(digest(c.CERTIFICATE, 'sha256'), 'hex') AS sha256,
       encode(digest(c.CERTIFICATE, 'sha1'), 'hex') AS sha1,
       encode(x509_serialNumber(c.CERTIFICATE), 'hex') AS serial,
       '00' || encode(x509_serialNumber(c.CERTIFICATE), 'hex') AS serial00,
       encode(x509_subjectKeyIdentifier(c.CERTIFICATE), 'hex') AS ski,
       encode(digest(x509_publicKey(c.CERTIFICATE), 'sha256'), 'hex') AS spki,
       encode(digest(x509_publicKey(c.CERTIFICATE), 'sha1'), 'hex') AS spkisha1,
       encode(digest(x509_name(c.CERTIFICATE), 'sha1'), 'hex') AS subjectsha1
    FROM certificate c WHERE c.ID = :certid
\\gset
\\echo sha256=:sha256 serial=:serial ski=:ski
"""


def main() -> None:
    db = asyncio.run(record())
    out = [SETUP]
    for num, (title, sql) in enumerate(db.queries, start=1):
        out.append(f"\\echo '-- {num}. {title}'\n{sql};\n")
    sys.stdout.write("\n".join(out))


if __name__ == "__main__":
    main()

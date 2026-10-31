"""Generate a psql script of every query the slib.crtsh service runs, for testing them by hand.

    uv run python -m tests.sqlgen > tests/live_queries.sql
    psql -h crt.sh -p 5432 -U guest certwatch -f tests/live_queries.sql

    # The same queries against the PostgreSQL stub of crt.sh (see tests.pgstub).
    uv run python -m tests.sqlgen --stub | psql <stub dsn> -v ON_ERROR_STOP=1

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


CRTSH = {
    "certid": 29578180990,  # A www.comodo.com certificate.
    "issuer": 204411,  # Its issuing CA, Sectigo Public Server Authentication CA OV R36.
    "cacert": 4267304698,  # The certificate of CA 204411.
    "caname": "Sectigo Public Server Authentication CA OV R36",
    "samples": {
        "dns": "www.comodo.com",
        "cn": "www.comodo.com",
        "org": "Sectigo Limited",
        "ou": "Domain Control Validated",
        "email": "comodo.com",
        "ip": "8.8.8.8",
        "uri": "comodo.com",
        "identity": "comodo.com",
        "subject": "O=Sectigo Limited",
        "domain": "comodo.com",
    },
}
"""The values queries are run with against crt.sh."""

STUB = {
    "certid": 10,
    "issuer": 2,
    "cacert": 2,
    "caname": "Issuing CA",
    "samples": {
        "dns": "www.vertex.link",
        "cn": "www.vertex.link",
        "org": "The Vertex Project",
        "ou": "Engineering",
        "email": "vertex.link",
        "ip": "1.2.3.4",
        "uri": "vertex.link",
        "identity": "vertex.link",
        "subject": "O=The Vertex Project",
        "domain": "vertex.link",
    },
}
"""The values queries are run with against the PostgreSQL stub of crt.sh (see tests.pgstub)."""

SINCE = 1735689600000
"""2025-01-01, epoch millis."""

UNTIL = 1798761600000
"""2027-01-01, epoch millis."""


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
            sql = (
                f"SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, "
                f"count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM ({sql}) q"
            )
        self.queries.append((self.title, sql))
        return []


async def record(samples: dict, caname: str) -> Recorder:
    db = Recorder()

    async def q(title: str, coro):
        db.title = title
        await coro

    # Lookups by every identifier kind, each with the sample certificate's values.
    await q("Lookup by crt.sh ID", db.certs({"id": [IntVar("certid")]}, limit=1))
    for kind in ("sha256", "sha1", "ski", "spki", "spkisha1", "subjectsha1"):
        await q(f"Lookup by {kind}", db.certs({kind: [Var(kind)]}, limit=100))
    await q(
        "Lookup by serial (with and without the DER sign byte)",
        db.certs({"serial": [Var("serial"), Var("serial00")]}, limit=100),
    )
    await q(
        "Lookup by several kinds at once (crt.sh ID and SHA-256)",
        db.certs({"id": [IntVar("certid")], "sha256": [Var("sha256")]}, limit=100),
    )

    # Searches, one per field, using the same patterns the service builds.
    for field in NAME_TYPES:
        text, like = identityQuery(field, samples[field])
        valu = samples[field]
        await q(
            f"Search --{field} {valu}",
            db.certsByIdentity(text, like=like, nametypes=NAME_TYPES[field], limit=500),
        )

    text, like = identityQuery("dns", samples["dns"], exact=True)
    await q(
        f"Search --dns {samples['dns']} --exact",
        db.certsByIdentity(text, like=like, nametypes=NAME_TYPES["dns"], limit=500),
    )
    text, like = identityQuery("ip", "2606:4700:4700::1111")
    await q(
        "Search --ip 2606:4700:4700::1111",
        db.certsByIdentity(text, like=like, nametypes=NAME_TYPES["ip"], limit=500),
    )
    await q(
        f"Search --identity {samples['identity']}",
        db.certsByIdentity(samples["identity"], like=f"%{samples['identity']}%", limit=500),
    )
    text, _ = identityQuery("subject", samples["subject"])
    await q(
        f"Search --subject '{samples['subject']}' (full text only)",
        db.certsByIdentity(text, limit=500),
    )

    text, like = identityQuery("dns", samples["domain"])
    await q(
        f"Search --dns {samples['domain']} --valid --since 2025-01-01 --until 2027-01-01 --caid",
        db.certsByIdentity(
            text,
            like=like,
            nametypes=NAME_TYPES["dns"],
            caids=[IntVar("issuer")],
            valid=True,
            since=SINCE,
            until=UNTIL,
            limit=500,
        ),
    )
    await q(
        f"Search --dns {samples['domain']} --issuer '{caname}' (the CA name is a subquery)",
        db.certsByIdentity(text, like=like, nametypes=NAME_TYPES["dns"], issuer=caname, limit=500),
    )

    # Issued certificates, every CA source is one query.
    await q(
        "Issued by a CA ID (ca --issued, search --caid)",
        db.certsByIssuer(caids=[IntVar("issuer")], limit=100),
    )
    await q(
        "Issued by a CA ID, --valid --since",
        db.certsByIssuer(caids=[IntVar("issuer")], valid=True, since=SINCE, limit=100),
    )
    await q("Issued by a CA name (search --issuer)", db.certsByIssuer(issuer=caname, limit=100))
    await q(
        "Issued by the CA of a CA certificate (pivot --by issued)",
        db.certsByIssuer(cert={"id": [IntVar("cacert")]}, limit=100),
    )

    # Pivots, the source certificate is a subquery.
    for by in ("siblings", "key", "subject", "serial", "ski"):
        await q(f"Pivot --by {by}", db.related(by, {"id": [IntVar("certid")]}, limit=100))

    # Chains, one recursive query.
    await q("Chain (slib.crtsh.chain)", db.chain({"id": [IntVar("certid")]}))

    # CAs.
    await q("CAs by ID (ca --id)", db.cas(caids=[IntVar("issuer")]))
    await q(f"CAs by name (ca '{caname}')", db.cas(name=caname))
    await q(
        "CAs with their certificates (ca --certs)", db.cas(caids=[IntVar("issuer")], certs=True)
    )
    return db


SETUP = """\\timing on
\\pset pager off
SET statement_timeout = '600s';

-- The sample certificate and the values the lookups use.
\\set certid {certid}
\\set issuer {issuer}
\\set cacert {cacert}
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
    vals = STUB if "--stub" in sys.argv[1:] else CRTSH
    db = asyncio.run(record(vals["samples"], vals["caname"]))
    out = [SETUP.format(**vals)]
    for num, (title, sql) in enumerate(db.queries, start=1):
        out.append(f"\\echo '-- {num}. {title}'\n{sql};\n")
    sys.stdout.write("\n".join(out))


if __name__ == "__main__":
    main()

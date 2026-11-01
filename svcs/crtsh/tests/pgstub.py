"""Load the fake PKI into a real PostgreSQL database shaped like crt.sh's certwatch.

The schema copies what the service's queries use from crt.sh's
(https://github.com/crtsh/certwatch_db): the same tables, ``certificate``
partitioned by year on notAfter, the same expression and GIN indexes, and the
``certificate_and_identities`` view. libx509pq isn't available, so the ``x509_*``
functions (and ``identities()``) are SQL stubs that read a side table filled from
each certificate's parsed values. Unparsable certificates have no side table row,
so like libx509pq the stubs return null for them.

    uv run python -m tests.pgstub postgresql://postgres@127.0.0.1:5432/certwatch

The database's public schema is dropped and rebuilt.
"""

import asyncio
import datetime
import hashlib
import sys

import asyncpg

from .fakecrtsh import CA_NAMES, PKI, Pki, _derSerial, _identities, _ski, _spki


SCHEMA = """
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;
CREATE EXTENSION pgcrypto;
DROP TEXT SEARCH CONFIGURATION IF EXISTS certwatch;
CREATE TEXT SEARCH CONFIGURATION certwatch (COPY = pg_catalog.simple);

CREATE TABLE x509_info (
    SHA256 bytea PRIMARY KEY, NOTBEFORE timestamp, NOTAFTER timestamp, SERIAL bytea, SKI bytea,
    PUBKEY bytea, SUBJECT bytea, IDENTITIES tsvector
);
CREATE TABLE x509_ident (SHA256 bytea, NAME_TYPE text, NAME_VALUE text);

CREATE FUNCTION x509_notBefore(bytea) RETURNS timestamp LANGUAGE sql IMMUTABLE STRICT
    AS $$ SELECT NOTBEFORE FROM public.x509_info WHERE SHA256 = public.digest($1, 'sha256') $$;
CREATE FUNCTION x509_notAfter(bytea) RETURNS timestamp LANGUAGE sql IMMUTABLE STRICT
    AS $$ SELECT NOTAFTER FROM public.x509_info WHERE SHA256 = public.digest($1, 'sha256') $$;
CREATE FUNCTION x509_serialNumber(bytea) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT
    AS $$ SELECT SERIAL FROM public.x509_info WHERE SHA256 = public.digest($1, 'sha256') $$;
CREATE FUNCTION x509_subjectKeyIdentifier(bytea) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT
    AS $$ SELECT SKI FROM public.x509_info WHERE SHA256 = public.digest($1, 'sha256') $$;
CREATE FUNCTION x509_publicKey(bytea) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT
    AS $$ SELECT PUBKEY FROM public.x509_info WHERE SHA256 = public.digest($1, 'sha256') $$;
CREATE FUNCTION x509_name(bytea, boolean DEFAULT TRUE) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT
    AS $$ SELECT SUBJECT FROM public.x509_info WHERE SHA256 = public.digest($1, 'sha256') $$;
CREATE FUNCTION identities(bytea, boolean DEFAULT TRUE) RETURNS tsvector LANGUAGE sql IMMUTABLE STRICT
    AS $$ SELECT coalesce((SELECT IDENTITIES FROM public.x509_info
                           WHERE SHA256 = public.digest($1, 'sha256')), ''::tsvector) $$;

CREATE TABLE ca (ID serial PRIMARY KEY, NAME text NOT NULL, PUBLIC_KEY bytea NOT NULL DEFAULT '\\x00');
CREATE INDEX ca_name ON ca (lower(NAME) text_pattern_ops);

CREATE TABLE certificate (
    ID bigserial NOT NULL, ISSUER_CA_ID integer NOT NULL REFERENCES ca(ID), CERTIFICATE bytea NOT NULL
) PARTITION BY RANGE (coalesce(x509_notAfter(CERTIFICATE), 'infinity'::timestamp));
CREATE TABLE certificate_old PARTITION OF certificate FOR VALUES FROM (MINVALUE) TO ('2020-01-01');
{partitions}
CREATE TABLE certificate_future PARTITION OF certificate FOR VALUES FROM ('2060-01-01') TO (MAXVALUE);
CREATE INDEX c_id ON certificate (ID);
CREATE INDEX c_sha1 ON certificate (digest(CERTIFICATE, 'sha1'));
CREATE INDEX c_sha256 ON certificate (digest(CERTIFICATE, 'sha256'));
CREATE INDEX c_serial ON certificate (x509_serialNumber(CERTIFICATE));
CREATE INDEX c_spki_sha1 ON certificate (digest(x509_publicKey(CERTIFICATE), 'sha1'));
CREATE INDEX c_spki_sha256 ON certificate (digest(x509_publicKey(CERTIFICATE), 'sha256'));
CREATE INDEX c_ica_notbefore ON certificate (ISSUER_CA_ID, x509_notBefore(CERTIFICATE));
CREATE INDEX c_subject_sha1 ON certificate (digest(x509_name(CERTIFICATE), 'sha1'));
CREATE INDEX c_ski ON certificate (x509_subjectKeyIdentifier(CERTIFICATE));
CREATE INDEX c_identities ON certificate USING GIN (identities(CERTIFICATE));

CREATE VIEW certificate_and_identities AS
SELECT c.ID CERTIFICATE_ID, c.CERTIFICATE, i.NAME_TYPE, i.NAME_VALUE, c.ISSUER_CA_ID
    FROM certificate c LEFT JOIN x509_ident i ON i.SHA256 = digest(c.CERTIFICATE, 'sha256');

CREATE TABLE ca_certificate (CERTIFICATE_ID bigint PRIMARY KEY, CA_ID integer REFERENCES ca(ID));
CREATE INDEX cac_ca_c ON ca_certificate (CA_ID, CERTIFICATE_ID);

CREATE TABLE ct_log (ID integer PRIMARY KEY, OPERATOR text, URL text, NAME text);
CREATE TABLE ct_log_entry (
    CERTIFICATE_ID bigint NOT NULL, ENTRY_ID bigint NOT NULL, ENTRY_TIMESTAMP timestamp NOT NULL,
    CT_LOG_ID integer NOT NULL REFERENCES ct_log(ID)
);
CREATE INDEX ctle_c ON ct_log_entry (CERTIFICATE_ID);

CREATE TABLE crl_revoked (
    CA_ID integer REFERENCES ca(ID), SERIAL_NUMBER bytea, REASON_CODE smallint,
    REVOCATION_DATE timestamp, PRIMARY KEY (CA_ID, SERIAL_NUMBER)
);
"""


def identityText(cert) -> str:
    """The text identities() indexes: each identity, and every parent domain of names."""

    words = []
    for nametype, valu in _identities(cert):
        valu = valu.lower()
        words.append(valu)
        if nametype in ("2.5.4.3", "san:dNSName", "san:rfc822Name", "1.2.840.113549.1.9.1"):
            domain = valu.split("@")[-1]
            while "." in domain:
                words.append(domain)
                domain = domain.split(".", 1)[1]
    return " ".join(words)


def _naive(when: datetime.datetime) -> datetime.datetime:
    return when.astimezone(datetime.timezone.utc).replace(tzinfo=None)


def _fromMillis(ms: int) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).replace(tzinfo=None)


async def load(dsn: str, pki: Pki = PKI) -> None:
    """Rebuild the stub certwatch schema in ``dsn`` and load ``pki`` into it."""

    partitions = "\n".join(
        f"CREATE TABLE certificate_{year} PARTITION OF certificate "
        f"FOR VALUES FROM ('{year}-01-01') TO ('{year + 1}-01-01');"
        for year in range(2020, 2060)
    )
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute(SCHEMA.replace("{partitions}", partitions))

        for caid, caname in CA_NAMES.items():
            await conn.execute("INSERT INTO ca (ID, NAME) VALUES ($1, $2)", caid, caname)

        for row in pki.rows:
            cert = pki.certs.get(row["id"])
            sha256 = hashlib.sha256(row["der"]).digest()
            if cert is not None:
                await conn.execute(
                    "INSERT INTO x509_info VALUES ($1, $2, $3, $4, $5, $6, $7, to_tsvector('certwatch', $8))",
                    sha256,
                    _naive(cert.not_valid_before_utc),
                    _naive(cert.not_valid_after_utc),
                    _derSerial(cert),
                    _ski(cert),
                    _spki(cert),
                    cert.subject.public_bytes(),
                    identityText(cert),
                )
                for nametype, valu in _identities(cert):
                    await conn.execute(
                        "INSERT INTO x509_ident VALUES ($1, $2, $3)", sha256, nametype, valu
                    )
            await conn.execute(
                "INSERT INTO certificate (ID, ISSUER_CA_ID, CERTIFICATE) VALUES ($1, $2, $3)",
                row["id"],
                row["issuer_ca_id"],
                row["der"],
            )

        for certid, caid in pki.cacerts.items():
            await conn.execute("INSERT INTO ca_certificate VALUES ($1, $2)", certid, caid)

        logs: dict[str, int] = {}
        for certid, entries in pki.ctlog.items():
            for entry in entries:
                if entry["log"] not in logs:
                    logs[entry["log"]] = len(logs) + 1
                    await conn.execute(
                        "INSERT INTO ct_log VALUES ($1, $2, $3, $4)",
                        logs[entry["log"]],
                        entry["operator"],
                        entry["url"],
                        entry["log"],
                    )
                await conn.execute(
                    "INSERT INTO ct_log_entry VALUES ($1, $2, $3, $4)",
                    certid,
                    entry["index"],
                    _fromMillis(entry["time"]),
                    logs[entry["log"]],
                )

        for (caid, serial), info in pki.revoked.items():
            await conn.execute(
                "INSERT INTO crl_revoked VALUES ($1, $2, $3, $4)",
                caid,
                serial,
                info["code"],
                _fromMillis(info["time"]),
            )
        await conn.execute("ANALYZE")
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(load(sys.argv[1]))

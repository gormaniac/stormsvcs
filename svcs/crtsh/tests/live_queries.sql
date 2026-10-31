\timing on
\pset pager off
SET statement_timeout = '600s';

-- The sample certificate and the values the lookups use.
\set certid 29578180990
\set issuer 204411
\set cacert 4267304698
SELECT encode(digest(c.CERTIFICATE, 'sha256'), 'hex') AS sha256,
       encode(digest(c.CERTIFICATE, 'sha1'), 'hex') AS sha1,
       encode(x509_serialNumber(c.CERTIFICATE), 'hex') AS serial,
       '00' || encode(x509_serialNumber(c.CERTIFICATE), 'hex') AS serial00,
       encode(x509_subjectKeyIdentifier(c.CERTIFICATE), 'hex') AS ski,
       encode(digest(x509_publicKey(c.CERTIFICATE), 'sha256'), 'hex') AS spki,
       encode(digest(x509_publicKey(c.CERTIFICATE), 'sha1'), 'hex') AS spkisha1,
       encode(digest(x509_name(c.CERTIFICATE), 'sha1'), 'hex') AS subjectsha1
    FROM certificate c WHERE c.ID = :certid
\gset
\echo sha256=:sha256 serial=:serial ski=:ski

\echo '-- 1. Lookup by crt.sh ID'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE (c.ID = ANY(ARRAY[:certid]::bigint[])) LIMIT 1)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 2. Lookup by sha256'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE (digest(c.CERTIFICATE, 'sha256') = ANY(ARRAY[decode(:'sha256', 'hex')]::bytea[])) LIMIT 100)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 3. Lookup by sha1'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE (digest(c.CERTIFICATE, 'sha1') = ANY(ARRAY[decode(:'sha1', 'hex')]::bytea[])) LIMIT 100)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 4. Lookup by ski'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE (x509_subjectKeyIdentifier(c.CERTIFICATE) = ANY(ARRAY[decode(:'ski', 'hex')]::bytea[])) LIMIT 100)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 5. Lookup by spki'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE (digest(x509_publicKey(c.CERTIFICATE), 'sha256') = ANY(ARRAY[decode(:'spki', 'hex')]::bytea[])) LIMIT 100)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 6. Lookup by spkisha1'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE (digest(x509_publicKey(c.CERTIFICATE), 'sha1') = ANY(ARRAY[decode(:'spkisha1', 'hex')]::bytea[])) LIMIT 100)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 7. Lookup by subjectsha1'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE (digest(x509_name(c.CERTIFICATE), 'sha1') = ANY(ARRAY[decode(:'subjectsha1', 'hex')]::bytea[])) LIMIT 100)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 8. Lookup by serial (with and without the DER sign byte)'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE (x509_serialNumber(c.CERTIFICATE) = ANY(ARRAY[decode(:'serial', 'hex'), decode(:'serial00', 'hex')]::bytea[])) LIMIT 100)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 9. Lookup by several kinds at once (crt.sh ID and SHA-256)'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE (c.ID = ANY(ARRAY[:certid]::bigint[]) OR digest(c.CERTIFICATE, 'sha256') = ANY(ARRAY[decode(:'sha256', 'hex')]::bytea[])) LIMIT 100)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 10. Search --dns www.comodo.com'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT sub.CERTIFICATE_ID AS ID, sub.ISSUER_CA_ID, sub.CERTIFICATE FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'www.comodo.com') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '%www.comodo.com' AND c.NAME_TYPE = ANY(ARRAY['san:dNSName', '2.5.4.3']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 11. Search --cn www.comodo.com'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT sub.CERTIFICATE_ID AS ID, sub.ISSUER_CA_ID, sub.CERTIFICATE FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'www.comodo.com') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '%www.comodo.com%' AND c.NAME_TYPE = ANY(ARRAY['2.5.4.3']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 12. Search --org Sectigo Limited'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT sub.CERTIFICATE_ID AS ID, sub.ISSUER_CA_ID, sub.CERTIFICATE FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'Sectigo Limited') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '%Sectigo Limited%' AND c.NAME_TYPE = ANY(ARRAY['2.5.4.10']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 13. Search --ou Domain Control Validated'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT sub.CERTIFICATE_ID AS ID, sub.ISSUER_CA_ID, sub.CERTIFICATE FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'Domain Control Validated') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '%Domain Control Validated%' AND c.NAME_TYPE = ANY(ARRAY['2.5.4.11']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 14. Search --email comodo.com'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT sub.CERTIFICATE_ID AS ID, sub.ISSUER_CA_ID, sub.CERTIFICATE FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'comodo.com') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '%comodo.com%' AND c.NAME_TYPE = ANY(ARRAY['san:rfc822Name', '1.2.840.113549.1.9.1']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 15. Search --ip 8.8.8.8'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT sub.CERTIFICATE_ID AS ID, sub.ISSUER_CA_ID, sub.CERTIFICATE FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', '8.8.8.8') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '8.8.8.8' AND c.NAME_TYPE = ANY(ARRAY['san:iPAddress']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 16. Search --uri comodo.com'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT sub.CERTIFICATE_ID AS ID, sub.ISSUER_CA_ID, sub.CERTIFICATE FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'comodo.com') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '%comodo.com%' AND c.NAME_TYPE = ANY(ARRAY['san:uniformResourceIdentifier']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 17. Search --dns www.comodo.com --exact'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT sub.CERTIFICATE_ID AS ID, sub.ISSUER_CA_ID, sub.CERTIFICATE FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'www.comodo.com') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE 'www.comodo.com' AND c.NAME_TYPE = ANY(ARRAY['san:dNSName', '2.5.4.3']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 18. Search --ip 2606:4700:4700::1111'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT sub.CERTIFICATE_ID AS ID, sub.ISSUER_CA_ID, sub.CERTIFICATE FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', ':2606:4700:4700:0:0:0:0:1111') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE ':2606:4700:4700:0:0:0:0:1111' AND c.NAME_TYPE = ANY(ARRAY['san:iPAddress']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 19. Search --identity comodo.com'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT sub.CERTIFICATE_ID AS ID, sub.ISSUER_CA_ID, sub.CERTIFICATE FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'comodo.com') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '%comodo.com%' LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 20. Search --subject 'O=Sectigo Limited' (full text only)'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE plainto_tsquery('certwatch', 'Sectigo Limited') @@ identities(c.CERTIFICATE) LIMIT 500)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 21. Search --dns comodo.com --valid --since 2025-01-01 --until 2027-01-01 --caid'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT sub.CERTIFICATE_ID AS ID, sub.ISSUER_CA_ID, sub.CERTIFICATE FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'comodo.com') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '%comodo.com' AND c.NAME_TYPE = ANY(ARRAY['san:dNSName', '2.5.4.3']::text[]) AND c.ISSUER_CA_ID = ANY(ARRAY[:issuer]::int[]) AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) >= date_trunc('year', now() AT TIME ZONE 'UTC') AND x509_notAfter(c.CERTIFICATE) >= now() AT TIME ZONE 'UTC' AND x509_notBefore(c.CERTIFICATE) >= to_timestamp(1735689600.0) AT TIME ZONE 'UTC' AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) >= to_timestamp(1735689600.0) AT TIME ZONE 'UTC' AND x509_notBefore(c.CERTIFICATE) < to_timestamp(1798761600.0) AT TIME ZONE 'UTC' LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 22. Search --dns comodo.com --issuer 'Sectigo Public Server Authentication CA OV R36' (the CA name is a subquery)'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT sub.CERTIFICATE_ID AS ID, sub.ISSUER_CA_ID, sub.CERTIFICATE FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'comodo.com') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '%comodo.com' AND c.NAME_TYPE = ANY(ARRAY['san:dNSName', '2.5.4.3']::text[]) AND c.ISSUER_CA_ID IN (SELECT ca.ID FROM ca WHERE ca.NAME ILIKE '%Sectigo Public Server Authentication CA OV R36%' LIMIT 1000) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 23. Issued by a CA ID (ca --issued, search --caid)'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM (SELECT unnest(ARRAY[:issuer]::int[]) AS CA_ID) cas CROSS JOIN LATERAL (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE c.ISSUER_CA_ID = cas.CA_ID ORDER BY x509_notBefore(c.CERTIFICATE) DESC LIMIT 100) c)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 24. Issued by a CA ID, --valid --since'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM (SELECT unnest(ARRAY[:issuer]::int[]) AS CA_ID) cas CROSS JOIN LATERAL (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE c.ISSUER_CA_ID = cas.CA_ID AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) >= date_trunc('year', now() AT TIME ZONE 'UTC') AND x509_notAfter(c.CERTIFICATE) >= now() AT TIME ZONE 'UTC' AND x509_notBefore(c.CERTIFICATE) >= to_timestamp(1735689600.0) AT TIME ZONE 'UTC' AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) >= to_timestamp(1735689600.0) AT TIME ZONE 'UTC' ORDER BY x509_notBefore(c.CERTIFICATE) DESC LIMIT 100) c)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 25. Issued by a CA name (search --issuer)'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM (SELECT ID AS CA_ID FROM (SELECT ca.ID FROM ca WHERE ca.NAME ILIKE '%Sectigo Public Server Authentication CA OV R36%' LIMIT 1000) named) cas CROSS JOIN LATERAL (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE c.ISSUER_CA_ID = cas.CA_ID ORDER BY x509_notBefore(c.CERTIFICATE) DESC LIMIT 100) c)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 26. Issued by the CA of a CA certificate (pivot --by issued)'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM (SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = (SELECT s.ID FROM certificate s WHERE (s.ID = ANY(ARRAY[:cacert]::bigint[])) LIMIT 1)) cas CROSS JOIN LATERAL (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE c.ISSUER_CA_ID = cas.CA_ID ORDER BY x509_notBefore(c.CERTIFICATE) DESC LIMIT 100) c)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 27. Pivot --by siblings'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE c.ISSUER_CA_ID = (SELECT s.ISSUER_CA_ID FROM certificate s WHERE (s.ID = ANY(ARRAY[:certid]::bigint[])) LIMIT 1) AND NOT (c.ID = ANY(ARRAY[:certid]::bigint[])) ORDER BY x509_notBefore(c.CERTIFICATE) DESC LIMIT 100)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 28. Pivot --by key'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE digest(x509_publicKey(c.CERTIFICATE), 'sha256') = (SELECT digest(x509_publicKey(s.CERTIFICATE), 'sha256') FROM certificate s WHERE (s.ID = ANY(ARRAY[:certid]::bigint[])) LIMIT 1) AND NOT (c.ID = ANY(ARRAY[:certid]::bigint[])) LIMIT 100)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 29. Pivot --by subject'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE digest(x509_name(c.CERTIFICATE), 'sha1') = (SELECT digest(x509_name(s.CERTIFICATE), 'sha1') FROM certificate s WHERE (s.ID = ANY(ARRAY[:certid]::bigint[])) LIMIT 1) AND NOT (c.ID = ANY(ARRAY[:certid]::bigint[])) LIMIT 100)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 30. Pivot --by serial'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE x509_serialNumber(c.CERTIFICATE) = (SELECT x509_serialNumber(s.CERTIFICATE) FROM certificate s WHERE (s.ID = ANY(ARRAY[:certid]::bigint[])) LIMIT 1) AND NOT (c.ID = ANY(ARRAY[:certid]::bigint[])) LIMIT 100)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 31. Pivot --by ski'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE x509_subjectKeyIdentifier(c.CERTIFICATE) = (SELECT x509_subjectKeyIdentifier(s.CERTIFICATE) FROM certificate s WHERE (s.ID = ANY(ARRAY[:certid]::bigint[])) LIMIT 1) AND NOT (c.ID = ANY(ARRAY[:certid]::bigint[])) LIMIT 100)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 32. Chain (slib.crtsh.chain)'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH RECURSIVE chain AS ((SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE, NULL::bigint AS CHILD_ID, 0 AS DEPTH FROM certificate c WHERE (c.ID = ANY(ARRAY[:certid]::bigint[])) LIMIT 1) UNION ALL SELECT p.ID, p.ISSUER_CA_ID, p.CERTIFICATE, ch.ID, ch.DEPTH + 1 FROM chain ch JOIN ca_certificate cac ON cac.CA_ID = ch.ISSUER_CA_ID JOIN certificate p ON p.ID = cac.CERTIFICATE_ID WHERE ch.DEPTH < 10 AND NOT EXISTS (SELECT 1 FROM ca_certificate r WHERE r.CERTIFICATE_ID = ch.ID AND r.CA_ID = ch.ISSUER_CA_ID)), m AS MATERIALIZED (SELECT ID, ISSUER_CA_ID, CERTIFICATE, CHILD_ID, DEPTH FROM chain)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der, m.CHILD_ID AS child_id, m.DEPTH AS depth,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

\echo '-- 33. CAs by ID (ca --id)'
WITH cas AS MATERIALIZED (SELECT ca.ID, ca.NAME FROM ca WHERE ca.ID = ANY(ARRAY[:issuer]::int[]) ORDER BY ca.ID LIMIT 100) SELECT cas.ID AS ca_id, cas.NAME AS ca_name, cac.CERTIFICATE_ID AS id FROM cas LEFT JOIN ca_certificate cac ON cac.CA_ID = cas.ID;

\echo '-- 34. CAs by name (ca 'Sectigo Public Server Authentication CA OV R36')'
WITH cas AS MATERIALIZED (SELECT ca.ID, ca.NAME FROM ca WHERE ca.NAME ILIKE '%Sectigo Public Server Authentication CA OV R36%' ORDER BY ca.ID LIMIT 100) SELECT cas.ID AS ca_id, cas.NAME AS ca_name, cac.CERTIFICATE_ID AS id FROM cas LEFT JOIN ca_certificate cac ON cac.CA_ID = cas.ID;

\echo '-- 35. CAs with their certificates (ca --certs)'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes, count(q.ctlog) AS with_ctlog, count(q.issuer_name) AS with_issuer FROM (WITH cas AS MATERIALIZED (SELECT ca.ID, ca.NAME FROM ca WHERE ca.ID = ANY(ARRAY[:issuer]::int[]) ORDER BY ca.ID LIMIT 100), m AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE, cas.ID AS CA_ID, cas.NAME AS CA_NAME FROM cas LEFT JOIN ca_certificate cac ON cac.CA_ID = cas.ID LEFT JOIN certificate c ON c.ID = cac.CERTIFICATE_ID)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der, m.CA_ID AS ca_id, m.CA_NAME AS ca_name,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID) q;

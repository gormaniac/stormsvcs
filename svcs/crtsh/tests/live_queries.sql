\timing on
\pset pager off
SET statement_timeout = '120s';

-- The sample certificate and the values the lookups use.
\set certid 29578180990
\set issuer 204411
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
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT c.ID AS id, c.ISSUER_CA_ID AS issuer_ca_id, c.CERTIFICATE AS der FROM certificate c WHERE c.ID = ANY(ARRAY[:certid]::bigint[]) LIMIT 1) q;

\echo '-- 2. Lookup by sha256'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT c.ID AS id, c.ISSUER_CA_ID AS issuer_ca_id, c.CERTIFICATE AS der FROM certificate c WHERE digest(c.CERTIFICATE, 'sha256') = ANY(ARRAY[decode(:'sha256', 'hex')]::bytea[]) LIMIT 100) q;

\echo '-- 3. Lookup by sha1'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT c.ID AS id, c.ISSUER_CA_ID AS issuer_ca_id, c.CERTIFICATE AS der FROM certificate c WHERE digest(c.CERTIFICATE, 'sha1') = ANY(ARRAY[decode(:'sha1', 'hex')]::bytea[]) LIMIT 100) q;

\echo '-- 4. Lookup by ski'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT c.ID AS id, c.ISSUER_CA_ID AS issuer_ca_id, c.CERTIFICATE AS der FROM certificate c WHERE x509_subjectKeyIdentifier(c.CERTIFICATE) = ANY(ARRAY[decode(:'ski', 'hex')]::bytea[]) LIMIT 100) q;

\echo '-- 5. Lookup by spki'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT c.ID AS id, c.ISSUER_CA_ID AS issuer_ca_id, c.CERTIFICATE AS der FROM certificate c WHERE digest(x509_publicKey(c.CERTIFICATE), 'sha256') = ANY(ARRAY[decode(:'spki', 'hex')]::bytea[]) LIMIT 100) q;

\echo '-- 6. Lookup by spkisha1'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT c.ID AS id, c.ISSUER_CA_ID AS issuer_ca_id, c.CERTIFICATE AS der FROM certificate c WHERE digest(x509_publicKey(c.CERTIFICATE), 'sha1') = ANY(ARRAY[decode(:'spkisha1', 'hex')]::bytea[]) LIMIT 100) q;

\echo '-- 7. Lookup by subjectsha1'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT c.ID AS id, c.ISSUER_CA_ID AS issuer_ca_id, c.CERTIFICATE AS der FROM certificate c WHERE digest(x509_name(c.CERTIFICATE), 'sha1') = ANY(ARRAY[decode(:'subjectsha1', 'hex')]::bytea[]) LIMIT 100) q;

\echo '-- 8. Lookup by serial (with and without the DER sign byte)'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT c.ID AS id, c.ISSUER_CA_ID AS issuer_ca_id, c.CERTIFICATE AS der FROM certificate c WHERE x509_serialNumber(c.CERTIFICATE) = ANY(ARRAY[decode(:'serial', 'hex'), decode(:'serial00', 'hex')]::bytea[]) LIMIT 100) q;

\echo '-- 9. Search --dns www.comodo.com'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT sub.CERTIFICATE_ID AS id, sub.ISSUER_CA_ID AS issuer_ca_id, sub.CERTIFICATE AS der FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'www.comodo.com') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '%www.comodo.com' AND c.NAME_TYPE = ANY(ARRAY['san:dNSName', '2.5.4.3']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE) q;

\echo '-- 10. Search --cn www.comodo.com'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT sub.CERTIFICATE_ID AS id, sub.ISSUER_CA_ID AS issuer_ca_id, sub.CERTIFICATE AS der FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'www.comodo.com') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '%www.comodo.com%' AND c.NAME_TYPE = ANY(ARRAY['2.5.4.3']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE) q;

\echo '-- 11. Search --org Sectigo Limited'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT sub.CERTIFICATE_ID AS id, sub.ISSUER_CA_ID AS issuer_ca_id, sub.CERTIFICATE AS der FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'Sectigo Limited') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '%Sectigo Limited%' AND c.NAME_TYPE = ANY(ARRAY['2.5.4.10']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE) q;

\echo '-- 12. Search --ou Domain Control Validated'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT sub.CERTIFICATE_ID AS id, sub.ISSUER_CA_ID AS issuer_ca_id, sub.CERTIFICATE AS der FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'Domain Control Validated') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '%Domain Control Validated%' AND c.NAME_TYPE = ANY(ARRAY['2.5.4.11']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE) q;

\echo '-- 13. Search --email comodo.com'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT sub.CERTIFICATE_ID AS id, sub.ISSUER_CA_ID AS issuer_ca_id, sub.CERTIFICATE AS der FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'comodo.com') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '%comodo.com%' AND c.NAME_TYPE = ANY(ARRAY['san:rfc822Name', '1.2.840.113549.1.9.1']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE) q;

\echo '-- 14. Search --ip 8.8.8.8'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT sub.CERTIFICATE_ID AS id, sub.ISSUER_CA_ID AS issuer_ca_id, sub.CERTIFICATE AS der FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', '8.8.8.8') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '8.8.8.8' AND c.NAME_TYPE = ANY(ARRAY['san:iPAddress']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE) q;

\echo '-- 15. Search --uri comodo.com'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT sub.CERTIFICATE_ID AS id, sub.ISSUER_CA_ID AS issuer_ca_id, sub.CERTIFICATE AS der FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'comodo.com') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '%comodo.com%' AND c.NAME_TYPE = ANY(ARRAY['san:uniformResourceIdentifier']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE) q;

\echo '-- 16. Search --dns www.comodo.com --exact'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT sub.CERTIFICATE_ID AS id, sub.ISSUER_CA_ID AS issuer_ca_id, sub.CERTIFICATE AS der FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'www.comodo.com') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE 'www.comodo.com' AND c.NAME_TYPE = ANY(ARRAY['san:dNSName', '2.5.4.3']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE) q;

\echo '-- 17. Search --ip 2606:4700:4700::1111'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT sub.CERTIFICATE_ID AS id, sub.ISSUER_CA_ID AS issuer_ca_id, sub.CERTIFICATE AS der FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', ':2606:4700:4700:0:0:0:0:1111') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE ':2606:4700:4700:0:0:0:0:1111' AND c.NAME_TYPE = ANY(ARRAY['san:iPAddress']::text[]) LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE) q;

\echo '-- 18. Search --identity comodo.com'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT sub.CERTIFICATE_ID AS id, sub.ISSUER_CA_ID AS issuer_ca_id, sub.CERTIFICATE AS der FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'comodo.com') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '%comodo.com%' LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE) q;

\echo '-- 19. Search --subject (full text only)'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT c.ID AS id, c.ISSUER_CA_ID AS issuer_ca_id, c.CERTIFICATE AS der FROM certificate c WHERE plainto_tsquery('certwatch', 'Sectigo Limited') @@ identities(c.CERTIFICATE) LIMIT 500) q;

\echo '-- 20. Search --dns comodo.com --valid --since 2025-01-01 --until 2026-01-01 --caid'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT sub.CERTIFICATE_ID AS id, sub.ISSUER_CA_ID AS issuer_ca_id, sub.CERTIFICATE AS der FROM (SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c WHERE plainto_tsquery('certwatch', 'comodo.com') @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE '%comodo.com' AND c.NAME_TYPE = ANY(ARRAY['san:dNSName', '2.5.4.3']::text[]) AND c.ISSUER_CA_ID = ANY(ARRAY[:issuer]::int[]) AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) >= date_trunc('year', now() AT TIME ZONE 'UTC') AND x509_notAfter(c.CERTIFICATE) >= now() AT TIME ZONE 'UTC' AND x509_notBefore(c.CERTIFICATE) >= to_timestamp(1735689600.0) AT TIME ZONE 'UTC' AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) >= to_timestamp(1735689600.0) AT TIME ZONE 'UTC' AND x509_notBefore(c.CERTIFICATE) < to_timestamp(1767225600.0) AT TIME ZONE 'UTC' LIMIT 500) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE) q;

\echo '-- 21. CAs by name (--issuer)'
SELECT ca.ID AS id, ca.NAME AS name FROM ca WHERE ca.NAME ILIKE '%Sectigo%' ORDER BY ca.ID LIMIT 1000;

\echo '-- 22. CAs by ID'
SELECT ca.ID AS id, ca.NAME AS name FROM ca WHERE ca.ID = ANY(ARRAY[:issuer]::int[]);

\echo '-- 23. Certificates a CA issued (pivot --by issued/siblings, ca --issued)'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT c.ID AS id, c.ISSUER_CA_ID AS issuer_ca_id, c.CERTIFICATE AS der FROM certificate c WHERE c.ISSUER_CA_ID = :issuer ORDER BY x509_notBefore(c.CERTIFICATE) DESC LIMIT 100) q;

\echo '-- 24. Certificates a CA issued, --valid --since'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT c.ID AS id, c.ISSUER_CA_ID AS issuer_ca_id, c.CERTIFICATE AS der FROM certificate c WHERE c.ISSUER_CA_ID = :issuer AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) >= date_trunc('year', now() AT TIME ZONE 'UTC') AND x509_notAfter(c.CERTIFICATE) >= now() AT TIME ZONE 'UTC' AND x509_notBefore(c.CERTIFICATE) >= to_timestamp(1735689600.0) AT TIME ZONE 'UTC' AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) >= to_timestamp(1735689600.0) AT TIME ZONE 'UTC' ORDER BY x509_notBefore(c.CERTIFICATE) DESC LIMIT 100) q;

\echo '-- 25. Certificates belonging to a CA (chain building, ca --certs)'
SELECT count(*) AS certs, sum(length(q.der)) AS der_bytes FROM (SELECT c.ID AS id, c.ISSUER_CA_ID AS issuer_ca_id, c.CERTIFICATE AS der, cac.CA_ID AS ca_id FROM ca_certificate cac JOIN certificate c ON c.ID = cac.CERTIFICATE_ID WHERE cac.CA_ID = ANY(ARRAY[:issuer]::int[])) q;

\echo '-- 26. Metadata: CA membership'
SELECT cac.CERTIFICATE_ID AS certificate_id, cac.CA_ID AS ca_id FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = ANY(ARRAY[:certid]::bigint[]);

\echo '-- 27. Metadata: issuer CA names'
SELECT ca.ID AS id, ca.NAME AS name FROM ca WHERE ca.ID = ANY(ARRAY[:issuer]::int[]);

\echo '-- 28. Metadata: CT log entries'
SELECT ctle.CERTIFICATE_ID AS certificate_id, ctle.ENTRY_ID AS entry_id, ctle.ENTRY_TIMESTAMP AS entry_timestamp, ctl.NAME AS log_name, ctl.URL AS log_url, ctl.OPERATOR AS log_operator FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID WHERE ctle.CERTIFICATE_ID = ANY(ARRAY[:certid]::bigint[]) ORDER BY ctle.ENTRY_TIMESTAMP;

\echo '-- 29. Metadata: CRL revocations'
SELECT cr.CA_ID AS ca_id, cr.SERIAL_NUMBER AS serial_number, cr.REASON_CODE AS reason_code, cr.REVOCATION_DATE AS revocation_date FROM crl_revoked cr JOIN unnest(ARRAY[:issuer, :issuer]::int[], ARRAY[decode(:'serial', 'hex'), decode(:'serial00', 'hex')]::bytea[]) AS p(ca_id, serial) ON cr.CA_ID = p.ca_id AND cr.SERIAL_NUMBER = p.serial;

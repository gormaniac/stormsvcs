# Vulnerability commands

These use Shodan's free CVEDB API (`cvedb.shodan.io`), which needs no API key. Both need the
`slib.shodan.user` permission. See [model](model.md#cvedb-vulnerabilities) for what's modeled.

(shodan-cmd-cve)=
## slib.shodan.cve

Look up CVEs, GitHub Security Advisories (GHSA) and EU Vulnerability Database (EUVD) entries in
CVEDB, or search CVEDB for the CVEs affecting a product, and model them on `risk:vuln` (and
`it:sec:cve`) nodes.

```text
slib.shodan.cve [--cve <id>]... [--cpe <cpe23>] [--product <name>] [--kev] [--epss]
                [--start <date>] [--end <date>] [--limit <n>] [--count] [--cpes] [--yield]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--cve` | str, repeatable | `[]` | A CVE, GHSA or EUVD ID to look up instead of the inbound nodes. |
| `--cpe` | str | null | Search for the CVEs affecting this CPE 2.3 string (CVEDB's `cpe23`). |
| `--product` | str | null | Search for the CVEs affecting this product name (CVEDB's `product`). |
| `--kev` | flag | false | When searching, only CVEs in CISA's KEV catalog (`is_kev=true`). |
| `--epss` | flag | false | When searching, sort by EPSS (`sort_by_epss=true`). Not used with `--count`. |
| `--start` | str | null | When searching, only CVEs published on or after this date, `YYYY-MM-DD` (`start_date`). |
| `--end` | str | null | When searching, only CVEs published on or before this date (`end_date`). |
| `--limit` | int | `100` | When searching, the most CVEs to return (`limit`, with `skip=0`). Not used with `--count`. |
| `--count` | flag | false | When searching, only print `slib.shodan.cve: <n> matching CVEs.` (`count=true`). |
| `--cpes` | flag | false | Also model each CVE's affected CPEs as `it:prod:softver` nodes with `:cves`. Can make many nodes. |
| `--yield` | flag | false | Yield the `risk:vuln` nodes instead of the inbound nodes. |

`--cve`, `--cpe` and `--product` ignore and drop the inbound nodes. Each `--cve` ID is
upper-cased, and the service picks the endpoint by its prefix:

| ID | Request |
| --- | --- |
| `GHSA-...` | `GET /ghsa/{ID}` |
| `EUVD-...` | `GET /euvd/{ID}` |
| anything else | `GET /cve/{ID}` |

A search (`--cpe` or `--product`) calls `GET /cves`, prints `slib.shodan.cve: Found <n> CVEs.`,
and models each one. `--cve` and a search can be combined.

Inbound nodes:

| Form | Lookup |
| --- | --- |
| `risk:vuln` | `:cve` (nodes without one model nothing) |
| `it:sec:cve` | The CVE |
| `it:sec:cpe` | A `GET /cves?cpe23=<the CPE>` search, with `--kev`, `--epss`, `--limit`, `--start`, `--end` and `--cpes` |

Other forms are warned about. Without `--yield`, inbound nodes pass through. Each CVE ID is
looked up once per run. A failed lookup warns, ex. `CVEDB lookup of CVE-2099-0001 failed: ...`.

```text
// Enrich existing vulns.
risk:vuln:cve | slib.shodan.cve

// A CVE, a GitHub advisory and an EUVD entry.
slib.shodan.cve --cve CVE-2021-44228 --cve GHSA-jfh8-c2jp-5v3q --cve EUVD-2021-1252 --yield

// Known exploited vulns for a product, by EPSS, or just their number.
slib.shodan.cve --product log4j --kev --epss --yield
slib.shodan.cve --product log4j --kev --count
```

(shodan-cmd-cpe)=
## slib.shodan.cpe

Search CVEDB for a product's CPEs (`GET /cpes`).

```text
slib.shodan.cpe <product> [--limit <n>] [--count] [--yield]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `product` | str | required | The product name to search for. |
| `--limit` | int | `100` | The most CPEs to return (`limit`, with `skip=0`). |
| `--count` | flag | false | Only print `Total CPEs: <n>` (`count=true`). |
| `--yield` | flag | false | Make and yield an `it:sec:cpe` node for each CPE. |

CVEDB returns shortened CPE 2.3 strings (ex. `cpe:2.3:a:f5:nginx:1.25.3`). The service pads
them to all 13 components with `*` so Synapse accepts them, and the command prints one per
line. With `--yield`, each is made as an `it:sec:cpe` linked to the `meta:source` (values
Synapse rejects are skipped). Inbound nodes are dropped.

```text
slib.shodan.cpe nginx
slib.shodan.cpe exchange_server --yield | slib.shodan.cve
```

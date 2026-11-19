# Hurricane Electric BGP Toolkit

`slib.bgphe` is a Storm Service (a Synapse Advanced Power-Up) for Hurricane Electric's BGP
Toolkit, [bgp.he.net](https://bgp.he.net). It queries the JSON endpoints behind bgp.he.net's
own web pages and models the results in a Synapse Cortex:

- **Certificates** from Certificate Transparency (CT) logs, by domain, by a domain's
  subdomains, or by IP/CIDR. bgp.he.net returns each certificate's DER, so the service parses
  every detail itself and models it as a `crypto:x509:cert` (plus its public key as a
  `crypto:key`).
- **Domain whois**, from RDAP when bgp.he.net has it and from the whois text otherwise, as an
  `inet:whois:rec` with its nameservers, contacts, and emails.
- **ASN whois**, from the ASN's Regional Internet Registry (RIR): the AS name and the
  organization (`ou:org`) responsible for it.
- **Originated prefixes** of an ASN, from HE's Super Looking Glass, as
  `inet:asnet4`/`inet:asnet6`.

bgp.he.net needs no account or API key. It also has no documented API: the endpoints the
service uses are undocumented and may change without notice.

| | |
| --- | --- |
| Service name | `slib.bgphe` |
| Storm package | `slib.bgphe` |
| Python package | `bgphesvc` (cell class `bgphesvc.BgpHeSvc`) |
| Image | `ghcr.io/gormaniac/stormsvcs/bgphe` |
| Permission | `slib.bgphe.user` |
| Synapse | `>=2.234.0,<3.0.0` (the package's `synapse_version`) |

## Features

| Command | Looks up | Inbound forms | Models |
| --- | --- | --- | --- |
| [`slib.bgphe.certs`](commands.md#slibbgphecerts) | CT log certificates for a domain | `inet:fqdn` | `crypto:x509:cert`, `crypto:key` |
| [`slib.bgphe.certs.subdomains`](commands.md#slibbgphecertssubdomains) | A domain's subdomains with certificates | `inet:fqdn` | `inet:fqdn` |
| [`slib.bgphe.certs.ip`](commands.md#slibbgphecertsip) | Certificate hostnames that resolve to an IP or CIDR | `inet:ipv4`, `inet:ipv6`, `inet:cidr4`, `inet:cidr6` | `inet:dns:a`, `inet:dns:aaaa` |
| [`slib.bgphe.whois`](commands.md#slibbgphewhois) | A domain's whois (RDAP or text) | `inet:fqdn` | `inet:whois:rec`, `inet:whois:recns`, `inet:whois:contact`, `inet:whois:email` |
| [`slib.bgphe.asn`](commands.md#slibbgpheasn) | An ASN's RIR whois | `inet:asn` | `inet:asn` (`:name`, `:owner`), `ou:org` |
| [`slib.bgphe.asn.prefixes`](commands.md#slibbgpheasnprefixes) | The prefixes an ASN originates | `inet:asn` | `inet:asnet4`, `inet:asnet6` |

Every node the service models is linked to the `slib.bgphe` `meta:source` node with a
`-(seen)>` edge. The same functionality is available to Storm code through the
`slib.bgphe.lib` module (see [the API reference](api.md#the-slibbgphelib-module)).

The service stores nothing: every call is a fresh query to bgp.he.net.

## Architecture

```text
 Storm user / automation
        |
        v
 slib.bgphe.* commands  ->  slib.bgphe.lib  ->  slib.bgphe.model (node edits, as the user)
                                 |
                                 v
                      slib.bgphe.priv (asroot)  --$lib.service.get("slib.bgphe")-->
                                 |
                          Telepath (TelepathRetn)
                                 |
                                 v
             BgpHeSvc cell (BgpHeCellApi, a stormlibpp RetnApi)
               certs.py / rdap.py / whois.py / norm.py   (parsing, normalization)
               client.py BgpHeClient  (throttled, retried HTTPS)
                                 |
                                 v
                           https://bgp.he.net
```

- The **cell** (`BgpHeSvc`, a `synapse.lib.cell.Cell`) owns the HTTP client and all of the
  parsing: certificate DER, RDAP JSON, and whois text are all turned into plain dicts.
- The **Telepath API** (`BgpHeCellApi`) wraps every result in a `TelepathRetn`
  (`{"status", "mesg", "data"}`) and never raises to Storm.
- The **Storm package** calls the service from one privileged module (`slib.bgphe.priv`),
  so users need only `slib.bgphe.user`, not `service.get`. All node edits happen in
  `slib.bgphe.model`, which runs as the calling user.

See [Internals](internals.md) for a module-by-module walkthrough.

## Quick start

Run the service (see [Deployment](deployment.md) for the full options):

```bash
docker run -d --name bgphe \
    -v bgphe-storage:/vertex/storage \
    -e SYN_BGPHESVC_DMON_LISTEN=tcp://0.0.0.0:27492/ \
    -e SYN_BGPHESVC_AUTH_PASSWD=secret \
    ghcr.io/gormaniac/stormsvcs/bgphe:latest
```

Add it to a Cortex, as an admin, and wait for the package to load:

```text
service.add slib.bgphe tcp://root:secret@bgphe:27492/*
service.list
```

Grant analysts the package permission (they also need permission to make the node edits):

```text
auth.user.addrule analyst slib.bgphe.user
```

Run a first command:

```text
slib.bgphe.certs vertex.link --valid
inet:fqdn=vertex.link | slib.bgphe.whois --yield
slib.bgphe.asn 15169 --print
```

```{toctree}
:maxdepth: 2

deployment
commands
model
api
internals
```

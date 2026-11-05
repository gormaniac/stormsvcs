# ip_api

A Synapse Advanced Power-Up (Storm Service) that enriches IPv4 and IPv6 addresses with the
[ip-api.com](https://ip-api.com) JSON API: geolocation, ASN, ISP, WHOIS org, reverse DNS, and
whether the IP is a hosting, mobile, or proxy/VPN/Tor address.

The service registers the `slib.ipapi` Storm package.

## Free tier terms and limits

No API key is needed. ip-api.com's free endpoints are:

- **For non-commercial use only.** Commercial use needs an
  [ip-api.com pro](https://members.ip-api.com/) key, see [Configuration](#configuration).
- **Plain HTTP only.** HTTPS is only available on the pro endpoints.
- **Rate limited per source IP:** 45 requests/minute for single IPs (`/json`) and
  15 requests/minute for batches of up to 100 IPs (`/batch`). Going over a limit gets HTTP 429s
  until the window resets, and repeatedly going over it gets the source IP banned for an hour.

The service queues every request and works them one at a time, so every Storm user and
command shares the limits. It reads ip-api.com's `X-Rl` (requests left) and `X-Ttl` (seconds
until the window resets) headers and waits for the window to reset when no requests are left.
An HTTP 429 is retried up to 3 times, after waiting out the window, before the query fails.
Every request times out after 30 seconds.

The pro endpoints (`https://pro.ip-api.com`) have no rate limit.

## Deploying

```bash
docker run -d --name slib-ipapi \
    -v /srv/slib-ipapi:/vertex/storage \
    -e SYN_IPAPISVC_IPAPI_APIKEY=<optional pro key> \
    -p 27492:27492 \
    ghcr.io/gormaniac/stormsvcs/ip_api:latest
```

Then add it to a Cortex:

```
service.add slib.ipapi tcp://<user>:<passwd>@<host>:27492/*
```

The host needs outbound access to `ip-api.com` on TCP 80 (or `pro.ip-api.com` on TCP 443 with
an API key).

Adding the service creates its `meta:source` node (`c177b2a9c0eff5c2984946d439de23ea`) and the
default tag settings. Re-adding the service never resets tag settings made with the admin
commands.

### Configuration

| Option | Env var | Default | Description |
|---|---|---|---|
| `ipapi:apikey` | `SYN_IPAPISVC_IPAPI_APIKEY` | none | An ip-api.com pro key. When set, queries use the HTTPS pro endpoints (no rate limit, commercial use allowed). |

## Permissions

| Permission | Grants |
|---|---|
| `slib.ipapi.user` | `slib.ipapi.query` and the `slib.ipapi.lib` module. |
| `slib.ipapi.admin` | The `slib.ipapi.admin.*` commands and the `slib.ipapi.admin` module. |

Users also need the built-in `service.get` permission and permission to make the nodes the
query models (ex. `node`).

## Commands

### slib.ipapi.query

Query ip-api.com for the inbound `inet:ipv4`/`inet:ipv6` nodes, or for one IP string with
`--query`.

```
// Lift some inet:ipv4 nodes and query ip-api.com for information.
inet:ipv4 | limit 5 | slib.ipapi.query

// Query a specific IPv4 or IPv6 address, yielding its node.
slib.ipapi.query --query 8.8.8.8 --yield
slib.ipapi.query --query "2001:4860:4860::8888" --yield
```

- Inbound nodes are queued and sent in batches of up to 100 with ip-api.com's `/batch`
  endpoint, so each node is yielded once its batch is done. A single inbound node uses the
  `/json` endpoint instead, saving the smaller batch budget.
- Inbound nodes that aren't `inet:ipv4` or `inet:ipv6` are passed through with a warning, they
  are never sent to ip-api.com (which answers an empty query with the service host's own IP).
- `--query` ignores inbound nodes. A string that isn't a valid IPv4 or IPv6 address is warned
  about and never sent. `--yield` yields the queried IP's node.
- A failed query (ex. a private or reserved IP, an HTTP error, or a timeout) is a warning, not
  an error, and the inbound node passes through unchanged.

### Admin commands

| Command | Description |
|---|---|
| `slib.ipapi.admin.settag <prefix>` | Set the tag prefix. It must be a valid tag, and is normalized (ex. `Rep.MyOrg` becomes `rep.myorg`). |
| `slib.ipapi.admin.disabletag` | Stop tagging IPs. |
| `slib.ipapi.admin.enabletag` | Start tagging IPs again. Warns if no tag prefix is set. |

## Tags

When ip-api.com reports an IP as one of these, the IP node is tagged with the tag prefix
(default `rep.ipapi.infra`) plus:

| Tag | ip-api.com field |
|---|---|
| `#<prefix>.hosting` | `hosting` - a hosting, colocated, or data center IP. |
| `#<prefix>.mobile` | `mobile` - a mobile (cellular) connection. |
| `#<prefix>.proxy` | `proxy` - a proxy, VPN, or Tor exit address. |

If tags are enabled but the prefix is missing or invalid, `slib.ipapi.query` warns and still
models the results, just without tags.

## Model

For each successful result, `slib.ipapi.query` models:

| Node | From |
|---|---|
| `inet:ipv4`/`inet:ipv6` | `:latlong`, `:place`, `:loc` (ex. `us.va.ashburn`), `:asn`, and `:dns:rev` (from `reverse`). |
| `geo:place` | The city: `:name` (ex. `ashburn, virginia, united states`), `:latlong`, `:loc`, `:type=ip.geoloc.city`. |
| `geo:telem` | One per IP and place, with `:place:*` props, `:place:country` (a `pol:country` with that `:iso2`, reused if one exists), and `:time` (when the IP was first seen there). |
| `inet:asn` | Parsed from `as` (ex. `AS15169 Google LLC`), with `:name` from `asname` and `:owner`. |
| `ou:org` (AS owner) | The org name after the AS number (falling back to `isp`), with `asname` in `:names`. `:orgtype=company.isp` when it's also the ISP. |
| `ou:org` (WHOIS) | The IP's WHOIS `org`, with an `-(owns)>` edge to the IP. |

The service's `meta:source` gets a `-(seen)>` edge to each IP, `inet:asn`, and `geo:telem`.
IPs with no ASN (ip-api.com's empty `as`) are modeled without an `inet:asn` or AS owner, and
empty names never make an `ou:org`.

## IPv6

IPv6 addresses work the same as IPv4, both as inbound `inet:ipv6` nodes and `--query` strings.
Synapse also parses IPv4 strings as IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`), so a
`--query` string is only treated as IPv6 when it isn't a valid IPv4 address. Inbound nodes are
always modeled on the node that was queried.

## Development

```bash
cd svcs/ip_api
uv sync --all-extras --dev
uv run pytest tests
uv run python -m synapse.tools.storm.lint --v3-ready src/
```

The tests never call ip-api.com: HTTP is replayed from the VCR cassettes in
`tests/vcr_cassettes/`, and the Storm tests mock the service's requests.

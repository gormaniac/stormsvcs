# slib.ipapi

A Synapse Rapid Power-Up that enriches IPv4 and IPv6 addresses using the ip-api.com JSON API:
geolocation, ASN, ISP, WHOIS org, reverse DNS, and hosting/mobile/proxy flags.

No API token is required. ip-api.com's free endpoints are for non-commercial use only and are
limited to 45 requests per minute (single IPs) and 15 batch requests of up to 100 IPs per minute
per source IP. The `slib.ipapi` service queues and throttles every request to stay within those
limits. A service admin can configure an ip-api.com pro key (`ipapi:apikey`), which uses the
HTTPS pro endpoints with no rate limit.

## Examples

```
// Lift some inet:ipv4 nodes and query ip-api.com for information.
// Inbound nodes are queried in batches of up to 100.
inet:ipv4 | limit 5 | slib.ipapi.query

// Use a string argument to query for a specific IPv4 or IPv6 address.
slib.ipapi.query --query 8.8.8.8 --yield
```

## Permissions

- `slib.ipapi.user` - run `slib.ipapi.query`.
- `slib.ipapi.admin` - run the `slib.ipapi.admin.*` commands.

## Tags

IPs that ip-api.com reports as hosting, mobile, or proxy addresses are tagged
`#<prefix>.hosting`, `#<prefix>.mobile`, and `#<prefix>.proxy`. The default prefix is
`rep.ipapi.infra`.

- `slib.ipapi.admin.settag <prefix>` - set the prefix, which must be a valid tag.
- `slib.ipapi.admin.disabletag` - stop tagging.
- `slib.ipapi.admin.enabletag` - start tagging again.

## Model

Each result models the IP's `:latlong`, `:place`, `:loc`, `:asn`, and `:dns:rev`, a `geo:place`
for its city, a `geo:telem` for the IP at that place (with `:place:country`), the `inet:asn` and
its owner `ou:org`, and the IP's WHOIS `ou:org` with an `-(owns)>` edge to the IP. The service's
`meta:source` gets a `-(seen)>` edge to the IP, `inet:asn`, and `geo:telem`.

# ipapi

A Synapse Rapid Power-Up that enriches IPs using the free ip-api.com JSON API.

No API token is required. Note that ip-api.com's free endpoint is limited to
45 requests per minute per source IP; the `ipapi` service queues and throttles
requests to stay within that limit.

## Examples
```
// Lift some inet:ipv4 nodes and query ip-api.com for information.
inet:ipv4 | limit 5 | slib.ipapi.query

// Use a string argument to query for a specific IP address.
slib.ipapi.query --query 8.8.8.8
```

"""A fake Shodan HTTP server for tests.

Serves canned responses for every Shodan API under a per-API path prefix (ex.
``/api/shodan/host/8.8.8.8``, ``/cvedb/cve/CVE-2021-44228``) and records every
request so tests can assert exactly what the service sent.
"""


import contextlib
import json
from typing import Any

from aiohttp import web


HOST_8888 = {
    "ip_str": "8.8.8.8",
    "asn": "AS15169",
    "org": "Google LLC",
    "isp": "Google LLC",
    "os": None,
    "last_update": "2026-10-01T12:00:00.000000",
    "hostnames": ["dns.google"],
    "domains": ["dns.google"],
    "tags": ["cloud"],
    "ports": [53, 443],
    "vulns": ["CVE-2021-44228"],
    "country_code": "US",
    "country_name": "United States",
    "city": "Mountain View",
    "region_code": "CA",
    "latitude": 37.4056,
    "longitude": -122.0775,
    "data": [
        {
            "ip_str": "8.8.8.8",
            "port": 443,
            "transport": "tcp",
            "timestamp": "2026-10-01T12:00:00.000000",
            "product": "nginx",
            "version": "1.25.3",
            "cpe23": ["cpe:2.3:a:f5:nginx:1.25.3"],
            "data": "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
            "hostnames": ["dns.google"],
            "domains": ["dns.google"],
            "tags": ["cdn"],
            "asn": "AS15169",
            "org": "Google LLC",
            "vulns": {
                "CVE-2021-44228": {"cvss": 10.0, "verified": False, "summary": "Log4Shell"},
            },
            "location": {
                "city": "Mountain View", "region_code": "CA", "country_code": "US",
                "country_name": "United States", "latitude": 37.4056, "longitude": -122.0775,
            },
            "http": {"title": "Google DNS", "server": "nginx", "status": 200},
            "ssl": {
                "cert": {
                    "fingerprint": {
                        "sha256": "a" * 64,
                        "sha1": "b" * 40,
                    },
                    "serial": 1234567890,
                    "subject": {"CN": "dns.google"},
                    "issuer": {"CN": "GTS CA 1C3", "O": "Google Trust Services"},
                    "issued": "20260901000000Z",
                    "expires": "20261201000000Z",
                    "sig_alg": "sha256WithRSAEncryption",
                    "version": 2,
                },
                "versions": ["TLSv1.2", "TLSv1.3"],
                "jarm": "29d29d00029d29d00041d41d0000005",
            },
            "_shodan": {"module": "https", "id": "abc", "crawler": "xyz"},
        },
        {
            "ip_str": "8.8.8.8",
            "port": 53,
            "transport": "udp",
            "timestamp": "2026-09-30T12:00:00.000000",
            "data": "Recursion: enabled",
            "tags": [],
            "_shodan": {"module": "dns-udp"},
        },
    ],
}

INTERNETDB_1111 = {
    "ip": "1.1.1.1",
    "ports": [53, 80],
    "hostnames": ["one.one.one.one"],
    "cpes": ["cpe:/a:cloudflare:cloudflare"],
    "vulns": ["CVE-2023-44487"],
    "tags": ["cdn"],
}

CVE_LOG4SHELL = {
    "cve_id": "CVE-2021-44228",
    "summary": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
    "cvss": 10.0,
    "cvss_version": 3.1,
    "cvss_v2": 9.3,
    "cvss_v3": 10.0,
    "epss": 0.97,
    "ranking_epss": 0.99,
    "kev": True,
    "propose_action": "Apply updates per vendor instructions.",
    "ransomware_campaign": "Known",
    "references": ["https://logging.apache.org/log4j/2.x/security.html"],
    "published_time": "2021-12-10T10:15:09",
    "cpes": ["cpe:2.3:a:apache:log4j:2.0:-:*:*:*:*:*:*"],
}

SEARCH_PAGE = {
    "total": 2,
    "matches": [
        dict(HOST_8888["data"][0]),
        {
            "ip_str": "2001:4860:4860::8888",
            "port": 443,
            "transport": "tcp",
            "timestamp": "2026-10-01T12:00:00.000000",
            "data": "HTTP/1.1 200 OK",
            "_shodan": {"module": "https"},
        },
    ],
    "facets": {"country": [{"value": "US", "count": 2}]},
}

DNS_DOMAIN = {
    "domain": "vertex.link",
    "tags": ["ipv6"],
    "subdomains": ["www", "api"],
    "more": False,
    "data": [
        {"subdomain": "", "type": "A", "value": "1.2.3.4", "last_seen": "2026-10-01T00:00:00.000000"},
        {"subdomain": "www", "type": "CNAME", "value": "vertex.link", "last_seen": "2026-10-01T00:00:00.000000"},
        {"subdomain": "", "type": "MX", "value": "mx.vertex.link", "last_seen": "2026-10-01T00:00:00.000000"},
        {"subdomain": "", "type": "NS", "value": "ns1.vertex.link", "last_seen": "2026-10-01T00:00:00.000000"},
        {"subdomain": "", "type": "TXT", "value": "v=spf1 -all", "last_seen": "2026-10-01T00:00:00.000000"},
        {"subdomain": "api", "type": "AAAA", "value": "2001:db8::1", "last_seen": "2026-10-01T00:00:00.000000"},
    ],
}

API_INFO = {
    "plan": "dev", "query_credits": 99, "scan_credits": 98, "monitored_ips": 1,
    "unlocked": True, "unlocked_left": 99, "https": True, "telnet": False,
    "usage_limits": {"query_credits": 100, "scan_credits": 100, "monitored_ips": 16},
}

ALERT = {
    "id": "ALERT1", "name": "corp", "created": "2026-10-01T00:00:00", "expires": 0, "expired": False,
    "filters": {"ip": ["1.2.3.0/24"]}, "triggers": {"new_service": {}}, "notifiers": [{"id": "default"}],
}

# Canned responses keyed by (method, path). Values are (status, body) or a callable(request) -> (status, body).
ROUTES: dict[tuple[str, str], Any] = {
    ("GET", "/api/shodan/host/8.8.8.8"): (200, HOST_8888),
    ("GET", "/api/shodan/host/10.0.0.1"): (404, {"error": "No information available for that IP."}),
    ("GET", "/api/shodan/host/count"): (200, {"total": 1234, "facets": {"port": [{"value": 443, "count": 1000}]}}),
    ("GET", "/api/shodan/host/search"): (200, SEARCH_PAGE),
    ("GET", "/api/shodan/host/search/facets"): (200, ["country", "port"]),
    ("GET", "/api/shodan/host/search/filters"): (200, ["port", "product"]),
    ("GET", "/api/shodan/host/search/tokens"): (200, {"filters": ["port"], "string": "nginx", "attributes": {"ports": [80]}}),
    ("GET", "/api/shodan/ports"): (200, [22, 80, 443]),
    ("GET", "/api/shodan/protocols"): (200, {"https": "HTTPS banner grabber"}),
    ("GET", "/api/shodan/services"): (200, {"22": "SSH", "443": "HTTPS"}),
    ("POST", "/api/shodan/scan"): (200, {"id": "SCAN1", "count": 1, "credits_left": 97}),
    ("POST", "/api/shodan/scan/internet"): (200, {"id": "ISCAN1"}),
    ("GET", "/api/shodan/scans"): (200, {"total": 1, "matches": [{"id": "SCAN1", "status": "DONE", "size": 1, "credits_left": 97, "created": "2026-10-01"}]}),
    ("GET", "/api/shodan/scan/SCAN1"): (200, {"id": "SCAN1", "status": "DONE", "size": 1, "created": "2026-10-01"}),
    ("POST", "/api/shodan/alert"): (200, ALERT),
    ("POST", "/api/shodan/alert/ALERT1"): (200, ALERT),
    ("GET", "/api/shodan/alert/info"): (200, [ALERT]),
    ("GET", "/api/shodan/alert/ALERT1/info"): (200, ALERT),
    ("DELETE", "/api/shodan/alert/ALERT1"): (200, {"success": True}),
    ("GET", "/api/shodan/alert/triggers"): (200, [{"name": "new_service", "rule": "*", "description": "New service"}]),
    ("PUT", "/api/shodan/alert/ALERT1/trigger/new_service"): (200, {"success": True}),
    ("PUT", "/api/shodan/alert/ALERT1/trigger/malware"): (200, {"success": True}),
    ("DELETE", "/api/shodan/alert/ALERT1/trigger/new_service"): (200, {"success": True}),
    ("PUT", "/api/shodan/alert/ALERT1/trigger/open_database/ignore/1.2.3.4:9200"): (200, {"success": True}),
    ("DELETE", "/api/shodan/alert/ALERT1/trigger/open_database/ignore/1.2.3.4:9200"): (200, {"success": True}),
    ("PUT", "/api/shodan/alert/ALERT1/notifier/default"): (200, {"success": True}),
    ("DELETE", "/api/shodan/alert/ALERT1/notifier/default"): (200, {"success": True}),
    ("GET", "/api/notifier"): (200, {"total": 1, "matches": [{"id": "default", "provider": "email", "description": None}]}),
    ("GET", "/api/notifier/provider"): (200, {"slack": {"required": ["webhook_url"]}}),
    ("POST", "/api/notifier"): (200, {"success": True, "id": "NOTIF1"}),
    ("GET", "/api/notifier/NOTIF1"): (200, {"id": "NOTIF1", "provider": "slack", "args": {}}),
    ("PUT", "/api/notifier/NOTIF1"): (200, {"success": True, "id": "NOTIF1"}),
    ("DELETE", "/api/notifier/NOTIF1"): (200, {"success": True}),
    ("GET", "/api/shodan/query"): (200, {"total": 1, "matches": [{"votes": 5, "title": "Webcams", "query": "webcam"}]}),
    ("GET", "/api/shodan/query/search"): (200, {"total": 1, "matches": [{"votes": 5, "title": "Webcams", "query": "webcam"}]}),
    ("GET", "/api/shodan/query/tags"): (200, {"total": 1, "matches": [{"value": "webcam", "count": 10}]}),
    ("GET", "/api/shodan/data"): (200, [{"name": "raw-daily", "description": "Daily data"}]),
    ("GET", "/api/shodan/data/raw-daily"): (200, [{"name": "2026-10-01.json.gz", "size": 1, "timestamp": 1, "url": "https://example.com/f"}]),
    ("GET", "/api/org"): (200, {"id": "ORG1", "name": "Vertex", "upgrade_type": "corp", "domains": ["vertex.link"], "admins": [], "members": []}),
    ("PUT", "/api/org/member/visi"): (200, {"success": True}),
    ("DELETE", "/api/org/member/visi"): (200, {"success": True}),
    ("GET", "/api/account/profile"): (200, {"member": True, "credits": 0, "display_name": "visi", "created": "2020-01-01"}),
    ("GET", "/api/api-info"): (200, API_INFO),
    ("GET", "/api/tools/myip"): (200, "5.6.7.8"),
    ("GET", "/api/tools/httpheaders"): (200, {"User-Agent": "test"}),
    ("GET", "/api/labs/honeyscore/8.8.8.8"): (200, 0.8),
    ("GET", "/api/dns/domain/vertex.link"): (200, DNS_DOMAIN),
    ("GET", "/api/dns/resolve"): (200, {"vertex.link": "1.2.3.4"}),
    ("GET", "/api/dns/reverse"): (200, {"8.8.8.8": ["dns.google"]}),
    ("GET", "/exploits/api/search"): (200, {"total": 1, "matches": [{"source": "ExploitDB", "_id": 1, "date": "2021-12-10", "description": "Log4j RCE"}]}),
    ("GET", "/exploits/api/count"): (200, {"total": 7, "facets": {"source": [{"value": "ExploitDB", "count": 7}]}}),
    ("GET", "/trends/api/v1/search"): (200, {"total": 10, "matches": [{"month": "2026-09", "count": 10}], "facets": {"version": [{"key": "2026-09", "values": [{"value": "9.6", "count": 10}]}]}}),
    ("GET", "/trends/api/v1/search/facets"): (200, ["version"]),
    ("GET", "/trends/api/v1/search/filters"): (200, ["product"]),
    ("GET", "/internetdb/1.1.1.1"): (200, INTERNETDB_1111),
    ("GET", "/internetdb/10.0.0.1"): (404, {"detail": "No information available"}),
    ("GET", "/cvedb/cve/CVE-2021-44228"): (200, CVE_LOG4SHELL),
    ("GET", "/cvedb/cves"): (200, {"cves": [CVE_LOG4SHELL]}),
    ("GET", "/cvedb/cpes"): (200, {"cpes": ["cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"]}),
}

STREAM_BANNERS = [HOST_8888["data"][0], HOST_8888["data"][1]]


class FakeShodan:
    """Run with ``async with FakeShodan() as fake:`` and pass ``fake.urls`` as ``shodan:urls``."""

    def __init__(self):
        self.requests: list[dict] = []
        self.routes = dict(ROUTES)
        self.urls: dict[str, str] = {}

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        body = None
        if request.can_read_body:
            raw = await request.read()
            try:
                body = json.loads(raw)
            except ValueError:
                body = raw.decode()

        self.requests.append({
            "method": request.method,
            "path": request.path,
            "query": dict(request.query),
            "json": body,
        })

        if request.path.startswith("/stream/"):
            return await self._stream(request)

        if request.query.get("key") == "badkey":
            return web.json_response({"error": "Invalid API key"}, status=401)

        route = self.routes.get((request.method, request.path))
        if route is None:
            return web.json_response({"error": f"No fake route for {request.method} {request.path}"}, status=404)
        if callable(route):
            route = route(request)

        status, data = route
        return web.json_response(data, status=status)

    async def _stream(self, request: web.Request) -> web.StreamResponse:
        resp = web.StreamResponse(status=200)
        await resp.prepare(request)
        for banner in STREAM_BANNERS:
            await resp.write(json.dumps(banner).encode() + b"\n")
            # Heartbeats are blank lines.
            await resp.write(b"\n")
        await resp.write_eof()
        return resp

    async def __aenter__(self):
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", self._handle)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await site.start()
        port = self._runner.addresses[0][1]
        base = f"http://127.0.0.1:{port}"
        self.urls = {name: f"{base}/{name}" for name in ("api", "stream", "exploits", "trends", "internetdb", "cvedb")}
        return self

    async def __aexit__(self, *args):
        await self._runner.cleanup()

    def last(self, path: str | None = None, method: str | None = None) -> dict:
        """The most recent request (to ``path``, with ``method``, if given)."""

        for req in reversed(self.requests):
            if (path is None or req["path"] == path) and (method is None or req["method"] == method):
                return req
        raise AssertionError(f"No request was made to {path}")


@contextlib.asynccontextmanager
async def shodanSvc(test, apikey: str | None = "testkey"):
    """Yield (core, svc, fake) - a Cortex with slib.shodan added, pointed at a FakeShodan."""

    from shodansvc import ShodanSvc

    async with FakeShodan() as fake:
        conf = {"shodan:urls": fake.urls, "shodan:ratelimit": 0, "shodan:apikey": apikey}
        async with test.getTestCoreProxSvc(ShodanSvc, ssvc_conf=conf) as (core, prox, svc):
            yield core, svc, fake

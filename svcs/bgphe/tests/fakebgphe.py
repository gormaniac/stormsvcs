"""A fake bgp.he.net for tests.

Serves the endpoints the service uses from mutable state, filled with (trimmed) copies of real
bgp.he.net responses from ``tests/data``, and records every request so tests can assert exactly
what the service asked for. Certificates are paginated like bgp.he.net does, ``pagesize`` makes
the pages small enough to test paging with a few certificates.
"""

import contextlib
import copy
import ipaddress
import json
import math
import pathlib

from aiohttp import web

DATA = pathlib.Path(__file__).parent / "data"


def load(name: str):
    """Load a fixture from tests/data."""
    with (DATA / name).open(encoding="utf-8") as fd:
        return json.load(fd)


def initialState() -> dict:
    """The fake's default state, keyed by endpoint then query."""

    gormo = load("certs_gormo.co.json")
    google = load("certs_google.com.json")
    return {
        "pagesize": 200,
        # domain -> the certificate entries, before pagination.
        "certs": {
            "gormo.co": gormo["certificates"],
            "google.com": google["certificates"],
        },
        # domain -> the /certs/api/list response.
        "certlist": {"gormo.co": load("certlist_gormo.co.json")},
        # "addr/len" -> the by-prefix response.
        "prefix": {
            "2001:4860:4860::8888/128": load("prefix_2001-4860-4860--8888.json"),
            "8.8.8.0/24": load("prefix_8.8.8.0-24.json"),
        },
        "whoisdns": {
            name: load(f"whois_{name}.json")["data"]
            for name in ("microsoft.com", "bbc.co.uk", "google.de", "example.org", "vertex.link")
        },
        "whoisasn": {
            asn: load(f"whois_as{asn}.json")["data"]
            for asn in (15169, 3333, 4608, 28000, 37100, 8075)
        },
        "prefixes": {15169: load("prefixes_15169.json")["prefixes"]},
        # path -> a list of HTTP codes (or (code, Retry-After) tuples) to fail with first.
        "errors": {},
    }


class FakeBgpHe:
    """A fake bgp.he.net on localhost."""

    def __init__(self):
        self.state = initialState()
        self.requests: list[str] = []
        self.headers: list[dict] = []
        self.runner = None
        self.url = None

    def count(self, prefix: str) -> int:
        """How many requests went to paths starting with prefix."""
        return sum(1 for path in self.requests if path.startswith(prefix))

    async def handle(self, request: web.Request) -> web.StreamResponse:
        path = request.path
        self.requests.append(request.path_qs)
        self.headers.append(dict(request.headers))

        errs = self.state["errors"].get(path)
        if errs:
            code = errs.pop(0)
            headers = {}
            if isinstance(code, tuple):
                code, headers["Retry-After"] = code
            if code == "html":
                return web.Response(text="<html>oops</html>", content_type="text/html")
            return web.json_response({"error": f"fake error {code}"}, status=code, headers=headers)

        state = self.state
        query = request.query

        def js(data, status=200):
            return web.json_response(copy.deepcopy(data), status=status)

        if path == "/certs/api/domain":
            return self.certsPage(query.get("domain", ""), int(query.get("page", "1")))

        if path == "/certs/api/list":
            domain = query.get("domain", "")
            if domain in state["certlist"]:
                return js(state["certlist"][domain])
            return js(
                {
                    "domains": [],
                    "duration": "1ms",
                    "shard_timings": [],
                    "total_before_limit": None,
                    "total_certificates": 0,
                    "total_domains": 0,
                    "truncated": False,
                }
            )

        if path == "/certs/api/certificates/by-prefix":
            addr = query.get("prefix", "")
            try:
                ipaddress.ip_address(addr)
            except ValueError:
                return js({"error": "Invalid IP address format"}, status=400)
            key = f"{addr}/{query.get('len')}"
            if key in state["prefix"]:
                return js(state["prefix"][key])
            return js(
                {
                    "duration": "1ms",
                    "entries": [],
                    "has_more": False,
                    "next_page": None,
                    "prefix": key,
                    "success": True,
                    "total_hostnames": 0,
                    "total_ips": 0,
                }
            )

        if path.startswith("/whois/dns/"):
            name = path.removeprefix("/whois/dns/")
            if name in state["whoisdns"]:
                return js({"data": state["whoisdns"][name]})
            return js({"error": "whois unavailable"}, status=400)

        if path.startswith("/whois/as"):
            num = path.removeprefix("/whois/as")
            if num.isdigit() and int(num) in state["whoisasn"]:
                return js({"data": state["whoisasn"][int(num)]})
            return js({"error": "unallocated asn"}, status=400)

        if path.startswith("/super-lg/report/api/v1/prefixes/originated/"):
            num = path.rsplit("/", 1)[-1]
            rows = state["prefixes"].get(int(num), []) if num.isdigit() else []
            return js({"prefixes": rows})

        return web.Response(text="<html>Not Found</html>", status=404, content_type="text/html")

    def certsPage(self, domain: str, page: int) -> web.Response:
        """A page of certificates, paginated like bgp.he.net."""

        items = self.state["certs"].get(domain, [])
        size = self.state["pagesize"]
        total = len(items)
        pages = math.ceil(total / size) if total else 0
        chunk = items[(page - 1) * size : page * size] if page >= 1 else []
        return web.json_response(
            {
                "certificates": copy.deepcopy(chunk),
                "duration": "1ms",
                "pagination": {
                    "certificates_not_returned": max(total - page * size, 0),
                    "page": page,
                    "page_size": size,
                    "returned_certificates": len(chunk),
                    "total_certificates": total,
                    "total_pages": pages,
                },
                "shard_timings": [],
            }
        )

    async def __aenter__(self):
        app = web.Application()
        app.router.add_route("GET", "/{tail:.*}", self.handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{port}"
        return self

    async def __aexit__(self, *args):
        await self.runner.cleanup()


def svcConf(fake: FakeBgpHe, **kwargs) -> dict:
    """The service config for tests: fast, and pointed at the fake."""
    conf = {
        "bgphe:url": fake.url,
        "bgphe:interval": 0,
        "bgphe:backoff": 0,
        "bgphe:timeout": 30,
    }
    conf.update(kwargs)
    return conf


@contextlib.asynccontextmanager
async def bgpheSvc(test, **conf):
    """Yield (core, svc, fake) - a Cortex with slib.bgphe added, pointed at a FakeBgpHe."""

    from bgphesvc import BgpHeSvc

    async with FakeBgpHe() as fake:
        sconf = svcConf(fake, **conf)
        async with test.getTestCoreProxSvc(BgpHeSvc, ssvc_conf=sconf) as (core, prox, svc):
            yield core, svc, fake

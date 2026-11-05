"""A fake VirusTotal API v3 server for tests.

Serves real (trimmed) VirusTotal responses captured from the Public API (tests/data), from
mutable state, and records every request so tests can assert exactly what (and how much) the
service asked for.
"""

import base64
import contextlib
import copy
import json
import pathlib

from aiohttp import web

DATA = pathlib.Path(__file__).parent / "data"

APIKEY = "a" * 64
OTHERKEY = "b" * 64

WANNACRY = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
WANNACRY_MD5 = "db349b97c37d22f5ea1d1841e3c89eb4"
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_URL = "http://www.eicar.org/download/eicar.com.txt"
ANALYSIS_ID = "u-275a021b-1793698573"
FILE_ANALYSIS_ID = "ZGIzNDliOTdjMzdkMjJmNWVhMWQxODQxZTNjODllYjQ6MTc5MzY5ODU3Mw=="


def urlId(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def load(name: str):
    with (DATA / f"{name}.json").open() as fd:
        return json.load(fd)


def err(code: int, name: str, mesg: str) -> web.Response:
    return web.json_response({"error": {"code": name, "message": mesg}}, status=code)


class FakeVt:
    """An aiohttp server that looks like https://www.virustotal.com/api/v3."""

    def __init__(self):
        self.requests: list[tuple[str, str, dict]] = []
        self.bodies: list = []
        self.keys: list[str] = []
        self.status: dict[str, int] = {}
        self.analysisPolls = 0
        self.votes: set = set()

        files = {}
        for name in ("file_wannacry", "file_eicar"):
            obj = load(name)
            attrs = obj["data"]["attributes"]
            for h in (attrs["sha256"], attrs["md5"], attrs["sha1"]):
                files[h] = obj
        self.objects = {
            "files": files,
            "domains": {"example.com": load("domain")},
            "ip_addresses": {"8.8.8.8": load("ip")},
            "urls": {},
        }
        url = load("url")
        self.objects["urls"][url["data"]["id"]] = url
        self.objects["urls"][urlId(url["data"]["attributes"]["url"])] = url

        comments = load("file_comments")
        self.rels = {
            ("domains", "example.com", "resolutions"): load("domain_resolutions"),
            ("ip_addresses", "8.8.8.8", "resolutions"): load("ip_resolutions"),
            ("files", WANNACRY, "comments"): comments,
            ("files", WANNACRY, "contacted_domains"): load("file_contacted_domains"),
            ("domains", "example.com", "historical_whois"): {
                "meta": {"count": 1},
                "data": [
                    {
                        "id": "whois-1",
                        "type": "whois",
                        "attributes": {
                            "first_seen_date": 1700000000,
                            "last_updated": 1750000000,
                            "whois_map": {
                                "Domain Name": "EXAMPLE.COM",
                                "Registrar": "RESERVED-Internet Assigned Numbers Authority",
                                "Creation Date": "1995-08-14T04:00:00Z",
                                "Registry Expiry Date": "2027-08-13T04:00:00Z",
                            },
                        },
                    }
                ],
            },
            ("domains", "example.com", "votes"): {
                "meta": {"count": 1},
                "data": [{"id": "d-example.com-1", "type": "vote", "attributes": {"verdict": "harmless"}}],
            },
        }

        self.app = web.Application()
        self.app.router.add_route("*", "/api/v3/{path:.*}", self.handle)
        self.app.router.add_post("/upload/{token}", self.upload)
        self.runner = None
        self.url = None

    async def __aenter__(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"
        self.url = f"{self.base}/api/v3"
        return self

    async def __aexit__(self, *exc):
        await self.runner.cleanup()

    def paths(self) -> list[str]:
        return [f"{m} {p}" for m, p, _ in self.requests]

    async def upload(self, request: web.Request) -> web.Response:
        self.requests.append((request.method, request.path, dict(request.query)))
        post = await request.post()
        self.bodies.append({k: (v.filename, v.file.read()) for k, v in post.items()})
        return web.json_response({"data": {"type": "analysis", "id": FILE_ANALYSIS_ID}})

    async def handle(self, request: web.Request) -> web.Response:
        path = "/" + request.match_info["path"]
        self.requests.append((request.method, path, dict(request.query)))
        key = request.headers.get("x-apikey")
        self.keys.append(key)

        if path in self.status:
            return err(self.status[path], "TransientError", "Fake failure")
        if key == "429":
            return err(429, "QuotaExceededError", "Quota exceeded")
        if key not in (APIKEY, OTHERKEY):
            return err(401, "WrongCredentialsError", "Wrong API key")

        parts = [p for p in path.split("/") if p]
        method = request.method

        if parts == ["popular_threat_categories"]:
            return web.json_response(load("popular_threat_categories"))
        if parts == ["search"]:
            if request.query.get("query") == "8.8.8.8":
                return web.json_response(load("search_ip"))
            return web.json_response({"data": [], "meta": {"count": 0}})
        if len(parts) == 3 and parts[0] == "users" and parts[2] == "overall_quotas":
            return web.json_response(load("quotas"))
        if parts == ["files", "upload_url"]:
            return web.json_response({"data": f"{self.base}/upload/token123"})
        if parts == ["files"] and method == "POST":
            post = await request.post()
            self.bodies.append({k: (getattr(v, "filename", None), getattr(v, "file", None) and v.file.read()) for k, v in post.items()})
            return web.json_response({"data": {"type": "analysis", "id": FILE_ANALYSIS_ID}})
        if parts == ["urls"] and method == "POST":
            post = await request.post()
            self.bodies.append(dict(post))
            return web.json_response({"data": {"type": "analysis", "id": ANALYSIS_ID}})
        if len(parts) == 2 and parts[0] == "analyses":
            return self.analysis(parts[1])

        if len(parts) >= 2 and parts[0] in self.objects:
            coll, ident = parts[0], parts[1]
            if len(parts) == 2:
                obj = self.objects[coll].get(ident)
                if obj is None:
                    return err(404, "NotFoundError", f'"{ident}" not found')
                return web.json_response(obj)
            rel = parts[2]
            if rel == "analyse" and method == "POST":
                return web.json_response({"data": {"type": "analysis", "id": ANALYSIS_ID}})
            if rel == "comments" and method == "POST":
                body = await request.json()
                self.bodies.append(body)
                text = body["data"]["attributes"]["text"]
                return web.json_response(
                    {"data": {"id": f"x-{ident}-1", "type": "comment",
                              "attributes": {"text": text, "date": 1793700000, "tags": []}}}
                )
            if rel == "votes" and method == "POST":
                body = await request.json()
                self.bodies.append(body)
                if (coll, ident) in self.votes:
                    return err(409, "AlreadyExistsError", "Already voted")
                self.votes.add((coll, ident))
                return web.json_response({"data": {"type": "vote", "id": "v-1", "attributes": body["data"]["attributes"]}})
            if rel == "behaviour_summary":
                if ident in (WANNACRY, WANNACRY_MD5):
                    return web.json_response(load("file_behaviour_summary"))
                return web.json_response({"data": {}})
            return self.related(coll, ident, rel, request)

        return err(404, "NotFoundError", f"Unknown path {path}")

    def related(self, coll: str, ident: str, rel: str, request: web.Request) -> web.Response:
        if coll == "files" and ident == WANNACRY_MD5:
            ident = WANNACRY
        data = self.rels.get((coll, ident, rel))
        if data is None:
            if self.objects[coll].get(ident) is None:
                return err(404, "NotFoundError", f'"{ident}" not found')
            return web.json_response({"data": [], "meta": {"count": 0}, "links": {}})
        data = copy.deepcopy(data)
        items = data["data"]
        limit = int(request.query.get("limit", 10))
        offs = int(request.query.get("cursor", 0))
        page = items[offs : offs + limit]
        meta = {"count": data.get("meta", {}).get("count", len(items))}
        if offs + limit < len(items):
            meta["cursor"] = str(offs + limit)
        return web.json_response({"data": page, "meta": meta, "links": {}})

    def analysis(self, aid: str) -> web.Response:
        if aid not in (ANALYSIS_ID, FILE_ANALYSIS_ID):
            return err(404, "NotFoundError", f'Analysis "{aid}" not found')
        self.analysisPolls += 1
        status = "queued" if self.analysisPolls == 1 else "completed"
        url = load("url")["data"]["attributes"]
        attrs = {"status": status, "date": 1793698573, "stats": {}, "results": {}}
        if status == "completed":
            attrs["stats"] = url["last_analysis_stats"]
            attrs["results"] = url["last_analysis_results"]
        if aid == ANALYSIS_ID:
            meta = {"url_info": {"id": url["url"], "url": url["url"]}}
        else:
            meta = {"file_info": {"sha256": EICAR, "md5": "44d88612fea8a8f36de82e1278abb02f",
                                  "sha1": "3395856ce81f2b7382dee72602f798b642f14140", "size": 68}}
        return web.json_response(
            {"data": {"id": aid, "type": "analysis", "attributes": attrs}, "meta": meta}
        )


def svcConf(fake: FakeVt, **conf) -> dict:
    """The service config to use with a FakeVt. Limits are off unless a test turns them on."""

    ret = {"vt:url": fake.url, "vt:apikey": APIKEY, "vt:community": True,
           "vt:limit:minute": 0, "vt:limit:day": 0, "vt:limit:month": 0}
    ret.update(conf)
    return ret


@contextlib.asynccontextmanager
async def vtSvc(test, **conf):
    """Yield (core, svc, fake) - a Cortex with slib.vt added, pointed at a FakeVt."""

    from vtsvc import VtSvc

    async with FakeVt() as fake:
        sconf = svcConf(fake, **conf)
        async with test.getTestCoreProxSvc(VtSvc, ssvc_conf=sconf) as (core, prox, svc):
            yield core, svc, fake

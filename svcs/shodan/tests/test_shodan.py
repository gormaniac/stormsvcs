"""Pytests for the slib.shodan service's HTTP client, normalization, and Cell/Telepath methods."""

import asyncio

import aiohttp
import synapse.tests.utils as s_tests

from shodansvc import norm
from shodansvc.client import (
    NoApiKeyError,
    RateLimiter,
    ShodanApiError,
    ShodanClient,
    errMesg,
    normParam,
    normParams,
)

from .fakeshodan import CVE_LOG4SHELL, DNS_DOMAIN, HOST_8888, INTERNETDB_1111, FakeShodan, shodanSvc


# (ShodanSvc method, args, kwargs, HTTP method, path, expected query params)
ENDPOINTS = (
    ("host", ("8.8.8.8",), {"history": True}, "GET", "/api/shodan/host/8.8.8.8", {"history": "true", "minify": "false"}),
    ("count", ("nginx",), {"facets": "port,country:5"}, "GET", "/api/shodan/host/count", {"query": "nginx", "facets": "port,country:5"}),
    ("search", ("nginx",), {"page": 2, "fields": ["ip_str", "port"]}, "GET", "/api/shodan/host/search", {"query": "nginx", "page": "2", "fields": "ip_str,port"}),
    ("searchFacets", (), {}, "GET", "/api/shodan/host/search/facets", {}),
    ("searchFilters", (), {}, "GET", "/api/shodan/host/search/filters", {}),
    ("searchTokens", ("nginx port:80",), {}, "GET", "/api/shodan/host/search/tokens", {"query": "nginx port:80"}),
    ("ports", (), {}, "GET", "/api/shodan/ports", {}),
    ("protocols", (), {}, "GET", "/api/shodan/protocols", {}),
    ("services", (), {}, "GET", "/api/shodan/services", {}),
    ("scan", (["1.2.3.4", "5.6.7.0/24"],), {"force": True}, "POST", "/api/shodan/scan", {"ips": "1.2.3.4,5.6.7.0/24", "force": "true"}),
    ("scan", ({"1.2.3.4": [[443, "https"]]},), {}, "POST", "/api/shodan/scan", {"ips": '{"1.2.3.4": [[443, "https"]]}'}),
    ("scanInternet", (8443, "https"), {}, "POST", "/api/shodan/scan/internet", {"port": "8443", "protocol": "https"}),
    ("scans", (), {"page": 3}, "GET", "/api/shodan/scans", {"page": "3"}),
    ("scanStatus", ("SCAN1",), {}, "GET", "/api/shodan/scan/SCAN1", {}),
    ("alertCreate", ("corp", ["1.2.3.0/24"]), {"expires": 60}, "POST", "/api/shodan/alert", {}),
    ("alertEdit", ("ALERT1", ["1.2.3.0/24"]), {}, "POST", "/api/shodan/alert/ALERT1", {}),
    ("alertInfo", (), {}, "GET", "/api/shodan/alert/info", {"include_expired": "true"}),
    ("alertInfo", (), {"aid": "ALERT1"}, "GET", "/api/shodan/alert/ALERT1/info", {}),
    ("alertDelete", ("ALERT1",), {}, "DELETE", "/api/shodan/alert/ALERT1", {}),
    ("alertTriggers", (), {}, "GET", "/api/shodan/alert/triggers", {}),
    ("alertTriggerEnable", ("ALERT1", "new_service"), {}, "PUT", "/api/shodan/alert/ALERT1/trigger/new_service", {}),
    ("alertTriggerDisable", ("ALERT1", "new_service"), {}, "DELETE", "/api/shodan/alert/ALERT1/trigger/new_service", {}),
    ("alertTriggerIgnore", ("ALERT1", "open_database", "1.2.3.4:9200"), {}, "PUT", "/api/shodan/alert/ALERT1/trigger/open_database/ignore/1.2.3.4:9200", {}),
    ("alertTriggerUnignore", ("ALERT1", "open_database", "1.2.3.4:9200"), {}, "DELETE", "/api/shodan/alert/ALERT1/trigger/open_database/ignore/1.2.3.4:9200", {}),
    ("alertNotifierAdd", ("ALERT1", "default"), {}, "PUT", "/api/shodan/alert/ALERT1/notifier/default", {}),
    ("alertNotifierDel", ("ALERT1", "default"), {}, "DELETE", "/api/shodan/alert/ALERT1/notifier/default", {}),
    ("notifiers", (), {}, "GET", "/api/notifier", {}),
    ("notifierProviders", (), {}, "GET", "/api/notifier/provider", {}),
    ("notifierCreate", ("slack", {"webhook_url": "https://x"}), {"desc": "soc"}, "POST", "/api/notifier", {"provider": "slack", "description": "soc", "webhook_url": "https://x"}),
    ("notifierGet", ("NOTIF1",), {}, "GET", "/api/notifier/NOTIF1", {}),
    ("notifierEdit", ("NOTIF1", {"to": "a@b.c"}), {}, "PUT", "/api/notifier/NOTIF1", {"to": "a@b.c"}),
    ("notifierDelete", ("NOTIF1",), {}, "DELETE", "/api/notifier/NOTIF1", {}),
    ("queries", (), {"sort": "votes", "order": "asc"}, "GET", "/api/shodan/query", {"page": "1", "sort": "votes", "order": "asc"}),
    ("queriesSearch", ("webcam",), {}, "GET", "/api/shodan/query/search", {"query": "webcam", "page": "1"}),
    ("queriesTags", (), {"size": 5}, "GET", "/api/shodan/query/tags", {"size": "5"}),
    ("datasets", (), {}, "GET", "/api/shodan/data", {}),
    ("datasetFiles", ("raw-daily",), {}, "GET", "/api/shodan/data/raw-daily", {}),
    ("org", (), {}, "GET", "/api/org", {}),
    ("orgMemberAdd", ("visi",), {"notify": False}, "PUT", "/api/org/member/visi", {"notify": "false"}),
    ("orgMemberDel", ("visi",), {}, "DELETE", "/api/org/member/visi", {}),
    ("profile", (), {}, "GET", "/api/account/profile", {}),
    ("apiInfo", (), {}, "GET", "/api/api-info", {}),
    ("myip", (), {}, "GET", "/api/tools/myip", {}),
    ("httpHeaders", (), {}, "GET", "/api/tools/httpheaders", {}),
    ("honeyscore", ("8.8.8.8",), {}, "GET", "/api/labs/honeyscore/8.8.8.8", {}),
    ("dnsDomain", ("vertex.link",), {"history": True, "rtype": "A"}, "GET", "/api/dns/domain/vertex.link", {"history": "true", "type": "A", "page": "1"}),
    ("dnsResolve", (["vertex.link", "google.com"],), {}, "GET", "/api/dns/resolve", {"hostnames": "vertex.link,google.com"}),
    ("dnsReverse", (["8.8.8.8"],), {}, "GET", "/api/dns/reverse", {"ips": "8.8.8.8"}),
    ("exploitsSearch", ("cve:CVE-2021-44228",), {"facets": "source"}, "GET", "/exploits/api/search", {"query": "cve:CVE-2021-44228", "facets": "source", "page": "1"}),
    ("exploitsCount", ("type:remote",), {}, "GET", "/exploits/api/count", {"query": "type:remote"}),
    ("trendsSearch", ("product:openssh",), {"facets": "version"}, "GET", "/trends/api/v1/search", {"query": "product:openssh", "facets": "version"}),
    ("trendsFacets", (), {}, "GET", "/trends/api/v1/search/facets", {}),
    ("trendsFilters", (), {}, "GET", "/trends/api/v1/search/filters", {}),
    ("internetdb", ("1.1.1.1",), {}, "GET", "/internetdb/1.1.1.1", {}),
    ("cve", ("cve-2021-44228",), {}, "GET", "/cvedb/cve/CVE-2021-44228", {}),
    ("cves", (), {"product": "log4j", "is_kev": True, "sort_by_epss": True}, "GET", "/cvedb/cves", {"product": "log4j", "is_kev": "true", "sort_by_epss": "true"}),
    ("cpes", ("nginx",), {"limit": 5}, "GET", "/cvedb/cpes", {"product": "nginx", "limit": "5"}),
    ("rawRequest", ("get", "shodan/ports"), {}, "GET", "/api/shodan/ports", {}),
)

# APIs that don't take an API key.
KEYLESS = ("/internetdb/", "/cvedb/")


class TestNorm(s_tests.SynTest):
    """Tests for shodansvc.norm."""

    def test_norm_cpe(self):
        assert norm.normCpe("cpe:2.3:a:f5:nginx:1.25.3") == "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"
        full = "cpe:2.3:a:apache:log4j:2.0:-:*:*:*:*:*:*"
        assert norm.normCpe(full) == full
        assert norm.normCpe("cpe:/a:cloudflare:cloudflare") == "cpe:/a:cloudflare:cloudflare"

    def test_norm_vulns(self):
        vulns = norm.normVulns({"cve-2021-44228": {"cvss": 10.0, "verified": True, "summary": "x"}, "bad": {}})
        assert vulns == [{"cve": "CVE-2021-44228", "cvss": 10.0, "verified": True, "summary": "x"}]
        assert norm.normVulns(["CVE-2023-44487"])[0]["cve"] == "CVE-2023-44487"
        assert norm.normVulns(None) == []

    def test_norm_host(self):
        host = norm.normHost(HOST_8888)
        assert host["ip"] == "8.8.8.8"
        assert host["ports"] == [53, 443]
        assert host["location"]["country_code"] == "us"
        assert host["location"]["latlong"] == (37.4056, -122.0775)
        # The banner's detailed vuln replaces the host's bare CVE ID.
        assert host["vulns"] == [{"cve": "CVE-2021-44228", "cvss": 10.0, "verified": False, "summary": "Log4Shell"}]
        assert len(host["banners"]) == 2

        https, dns = host["banners"]
        assert https["cpes"] == ["cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"]
        assert https["module"] == "https"
        assert https["http"]["title"] == "Google DNS"
        assert https["cert"]["sha256"] == "a" * 64
        assert https["cert"]["serial"] == format(1234567890, "x")
        assert https["cert"]["notbefore"] == "2026/09/01 00:00:00"
        assert https["cert"]["selfsigned"] is False
        assert dns["transport"] == "udp"
        assert dns["cert"] is None
        assert dns["http"] is None

    def test_norm_banner_truncates(self):
        banner = norm.normBanner({"ip_str": "1.2.3.4", "port": 1, "data": "x" * (norm.MAX_BANNER_LEN + 10)})
        assert len(banner["data"]) == norm.MAX_BANNER_LEN
        assert banner["transport"] == "tcp"

    def test_norm_internetdb(self):
        host = norm.normInternetDb(INTERNETDB_1111)
        assert host["ip"] == "1.1.1.1"
        assert host["banners"] == []
        assert host["cpes"] == ["cpe:/a:cloudflare:cloudflare"]
        assert host["vulns"][0]["cve"] == "CVE-2023-44487"

    def test_norm_dns(self):
        recs = norm.normDnsRecords(DNS_DOMAIN)
        assert recs[0] == {"fqdn": "vertex.link", "type": "A", "value": "1.2.3.4", "seen": "2026-10-01T00:00:00.000000"}
        assert recs[1]["fqdn"] == "www.vertex.link"

    def test_norm_cve(self):
        cve = norm.normCve(CVE_LOG4SHELL)
        assert cve["cve"] == "CVE-2021-44228"
        assert cve["kev"] is True
        assert cve["cpes"] == ["cpe:2.3:a:apache:log4j:2.0:-:*:*:*:*:*:*"]


class TestClient(s_tests.SynTest):
    """Tests for shodansvc.client."""

    def test_norm_params(self):
        assert normParam(True) == "true"
        assert normParam(False) == "false"
        assert normParam(["a", 1]) == "a,1"
        assert normParam(3) == "3"
        assert normParams({"a": None, "b": True}) == {"b": "true"}
        assert normParams(None) == {}

    def test_err_mesg(self):
        assert errMesg(404, {"error": "nope"}, "") == "nope"
        assert errMesg(404, {"detail": "Not Found"}, "") == "Not Found"
        assert errMesg(401, None, "<html>") == "Invalid Shodan API key"
        assert errMesg(500, None, "") == "HTTP 500"
        assert errMesg(500, None, "plain error") == "plain error"

    async def test_rate_limiter(self):
        limiter = RateLimiter(20)
        loop = asyncio.get_running_loop()
        start = loop.time()
        for _ in range(3):
            await limiter.wait()
        assert loop.time() - start >= 0.09

        # A rate of 0 disables limiting.
        await RateLimiter(0).wait()

    async def test_client_errors(self):
        async with FakeShodan() as fake, aiohttp.ClientSession() as sess:
            client = ShodanClient(sess, urls=fake.urls, rate=0)

            with self.raises(NoApiKeyError):
                await client.request("get", "/shodan/ports")

            with self.raises(ShodanApiError) as cm:
                await client.request("get", "/shodan/ports", apikey="badkey")
            assert cm.exception.code == 401
            assert cm.exception.mesg == "Invalid API key"

            with self.raises(ShodanApiError) as cm:
                await client.request("get", "/shodan/host/10.0.0.1", apikey="key")
            assert cm.exception.code == 404
            assert "No information" in cm.exception.mesg

            with self.raises(ShodanApiError):
                await client.request("get", "/nope", base="nope")

            # Keyless APIs never send the key.
            await client.request("get", "/1.1.1.1", base="internetdb", apikey="key")
            assert "key" not in fake.last()["query"]

            # A 200 that contains an error is still an error.
            fake.routes[("GET", "/api/shodan/ports")] = (200, {"error": "Something broke"})
            with self.raises(ShodanApiError) as cm:
                await client.request("get", "/shodan/ports", apikey="key")
            assert cm.exception.mesg == "Something broke"

    async def test_client_retries_429(self):
        async with FakeShodan() as fake, aiohttp.ClientSession() as sess:
            client = ShodanClient(sess, urls=fake.urls, rate=0)

            calls = []

            def flaky(request):
                calls.append(1)
                if len(calls) == 1:
                    return (429, {"error": "Rate limit reached"})
                return (200, [22])

            fake.routes[("GET", "/api/shodan/ports")] = flaky
            assert await client.request("get", "/shodan/ports", apikey="key") == [22]
            assert len(calls) == 2

    async def test_client_connect_error(self):
        async with aiohttp.ClientSession() as sess:
            client = ShodanClient(sess, urls={"api": "http://127.0.0.1:1"}, rate=0)
            with self.raises(ShodanApiError) as cm:
                await client.request("get", "/shodan/ports", apikey="key")
            assert "Unable to connect" in cm.exception.mesg

    async def test_client_stream(self):
        async with FakeShodan() as fake, aiohttp.ClientSession() as sess:
            client = ShodanClient(sess, urls=fake.urls, rate=0)

            banners = [b async for b in client.stream("/shodan/banners", apikey="key", limit=0, timeout=5)]
            assert [b["port"] for b in banners] == [443, 53]
            assert fake.last()["query"]["heartbeat"] == "false"

            banners = [b async for b in client.stream("/shodan/banners", apikey="key", limit=1, timeout=5)]
            assert len(banners) == 1


class TestShodanSvc(s_tests.SynTest):
    """Tests for the ShodanSvc Cell and its Telepath API."""

    async def test_endpoints(self):
        async with shodanSvc(self) as (core, svc, fake):
            for name, args, kwargs, method, path, query in ENDPOINTS:
                await getattr(svc, name)(*args, **kwargs)

                req = fake.last()
                assert (req["method"], req["path"]) == (method, path), name
                for key, valu in query.items():
                    assert req["query"].get(key) == valu, (name, key, req["query"])

                if path.startswith(KEYLESS):
                    assert "key" not in req["query"], name
                else:
                    assert req["query"]["key"] == "testkey", name

            assert fake.last("/api/shodan/alert")["json"] == {"name": "corp", "filters": {"ip": ["1.2.3.0/24"]}, "expires": 60}
            assert fake.last("/api/shodan/alert/ALERT1", "POST")["json"] == {"filters": {"ip": ["1.2.3.0/24"]}}

    async def test_apikey_precedence(self):
        async with shodanSvc(self, apikey="confkey") as (core, svc, fake):
            await svc.ports()
            assert fake.last()["query"]["key"] == "confkey"

            await svc.setApiKey("storedkey")
            assert await svc.hasApiKey()
            await svc.ports()
            assert fake.last()["query"]["key"] == "storedkey"

            await svc.ports(apikey="userkey")
            assert fake.last()["query"]["key"] == "userkey"

            await svc.setApiKey(None)
            await svc.ports()
            assert fake.last()["query"]["key"] == "confkey"

        async with shodanSvc(self, apikey=None) as (core, svc, fake):
            assert not await svc.hasApiKey()
            with self.raises(NoApiKeyError):
                await svc.ports()

    async def test_search_genr_pages(self):
        async with shodanSvc(self) as (core, svc, fake):

            def paged(request):
                page = int(request.query["page"])
                matches = [{"ip_str": f"1.1.1.{page}{i}", "port": 80} for i in range(100 if page < 3 else 5)]
                return (200, {"total": 205, "matches": matches})

            fake.routes[("GET", "/api/shodan/host/search")] = paged

            banners = [b async for b in svc.searchGenr("nginx", limit=0)]
            assert len(banners) == 205
            assert banners[0]["ip"] == "1.1.1.10"

            fake.requests.clear()
            banners = [b async for b in svc.searchGenr("nginx", limit=150)]
            assert len(banners) == 150
            assert len(fake.requests) == 2

    async def test_dns_domain_all_pages(self):
        async with shodanSvc(self) as (core, svc, fake):

            def paged(request):
                page = int(request.query["page"])
                return (200, {
                    "domain": "vertex.link", "tags": [], "subdomains": [f"s{page}"], "more": page < 3,
                    "data": [{"subdomain": f"s{page}", "type": "A", "value": "1.2.3.4"}],
                })

            fake.routes[("GET", "/api/dns/domain/vertex.link")] = paged

            data = await svc.dnsDomainAll("vertex.link", maxpages=0)
            assert data["subdomains"] == ["s1", "s2", "s3"]
            assert len(data["records"]) == 3
            assert data["more"] is False

            data = await svc.dnsDomainAll("vertex.link", maxpages=2)
            assert data["more"] is True

    async def test_stream_kinds(self):
        async with shodanSvc(self) as (core, svc, fake):
            banners = [b async for b in svc.stream("asn", values=["AS15169", "13335"], limit=0, timeout=5)]
            assert len(banners) == 2
            assert fake.last()["path"] == "/stream/shodan/asn/AS15169,13335"

            [b async for b in svc.stream("custom", query="port:22", limit=1)]
            assert fake.last()["path"] == "/stream/shodan/custom"
            assert fake.last()["query"]["query"] == "port:22"

            [b async for b in svc.stream("alert", aid="ALERT1", limit=1)]
            assert fake.last()["path"] == "/stream/shodan/alert/ALERT1"

            for kwargs in ({"kind": "nope"}, {"kind": "ports"}, {"kind": "custom"}):
                with self.raises(ShodanApiError):
                    [b async for b in svc.stream(**kwargs)]

    async def test_telepath_retn(self):
        async with shodanSvc(self) as (core, svc, fake):
            async with svc.getLocalProxy() as prox:
                retn = await prox.ports()
                # Telepath (msgpack) returns lists as tuples.
                assert retn == {"status": True, "mesg": "", "data": (22, 80, 443)}

                retn = await prox.host("10.0.0.1")
                assert retn["status"] is False
                assert "No information" in retn["mesg"]

                retn = await prox.setApiKey("newkey")
                assert retn["status"] is True
                assert (await prox.hasApiKey())["data"] is True

                items = [i async for i in prox.searchGenr("nginx")]
                assert [i["status"] for i in items] == [True, True]

                fake.routes[("GET", "/api/shodan/host/search")] = (401, {"error": "Invalid API key"})
                items = [i async for i in prox.searchGenr("nginx")]
                assert items == [{"status": False, "mesg": "Invalid API key", "data": None}]

                items = [i async for i in prox.stream("banners", limit=1)]
                assert items[0]["data"]["port"] == 443

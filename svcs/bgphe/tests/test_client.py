"""Tests for the bgp.he.net client: requests, retries, and errors."""

import asyncio
import datetime
import email.utils

import aiohttp
import pytest

from bgphesvc import client as c_client
from bgphesvc.client import BgpHeApiError, BgpHeClient

from .fakebgphe import FakeBgpHe


async def withClient(fake, **kwargs):
    session = aiohttp.ClientSession()
    kwargs.setdefault("interval", 0)
    kwargs.setdefault("backoff", 0)
    return session, BgpHeClient(session, url=fake.url, **kwargs)


async def test_endpoints():
    async with FakeBgpHe() as fake:
        session, cli = await withClient(fake)
        async with session:
            data = await cli.certsByDomain("gormo.co")
            assert len(data["certificates"]) == 12
            data = await cli.certsByDomain("gormo.co", page=2)
            assert data["certificates"] == []
            assert len((await cli.certDomains("gormo.co"))["domains"]) == 5
            assert (await cli.certsByPrefix("8.8.8.0", 24))["has_more"] is True
            assert "MICROSOFT.COM" in await cli.whoisDomain("microsoft.com")
            assert "ASName:         GOOGLE" in await cli.whoisAsn(15169)
            assert len(await cli.prefixesOriginated(15169)) == 8
            assert await cli.prefixesOriginated(99) == []

        assert fake.requests == [
            "/certs/api/domain?domain=gormo.co",
            "/certs/api/domain?domain=gormo.co&page=2",
            "/certs/api/list?domain=gormo.co",
            "/certs/api/certificates/by-prefix?prefix=8.8.8.0&len=24",
            "/whois/dns/microsoft.com",
            "/whois/as15169",
            "/super-lg/report/api/v1/prefixes/originated/15169",
            "/super-lg/report/api/v1/prefixes/originated/99",
        ]
        assert cli.count == 8
        assert all(h["User-Agent"] == c_client.USER_AGENT for h in fake.headers)


async def test_errors():
    async with FakeBgpHe() as fake:
        session, cli = await withClient(fake)
        async with session:
            with pytest.raises(BgpHeApiError) as exc:
                await cli.whoisDomain("nope.com")
            assert exc.value.code == 400
            assert exc.value.mesg == (
                "bgp.he.net returned HTTP 400 for /whois/dns/nope.com: whois unavailable"
            )

            with pytest.raises(BgpHeApiError, match="unallocated asn"):
                await cli.whoisAsn(99)

            with pytest.raises(BgpHeApiError, match="Invalid IP address format"):
                await cli.certsByPrefix("bad", 32)

            # 200s that aren't the expected JSON.
            fake.state["errors"]["/certs/api/list"] = ["html"]
            with pytest.raises(BgpHeApiError, match="expected a JSON object"):
                await cli.certDomains("gormo.co")

            fake.state["certlist"]["x.com"] = {"domains": "nope"}
            with pytest.raises(BgpHeApiError, match="no domains"):
                await cli.certDomains("x.com")

            fake.state["certlist"]["y.com"] = {"error": "nope", "domains": []}
            with pytest.raises(BgpHeApiError, match="returned an error for /certs/api/list: nope"):
                await cli.certDomains("y.com")

            fake.state["prefix"]["1.1.1.1/32"] = {"success": False, "entries": []}
            with pytest.raises(BgpHeApiError, match="reported the request"):
                await cli.certsByPrefix("1.1.1.1", 32)

            fake.state["prefix"]["1.1.1.2/32"] = {"success": True}
            with pytest.raises(BgpHeApiError, match="by-prefix"):
                await cli.certsByPrefix("1.1.1.2", 32)

            fake.state["certs"]["z.com"] = None
            fake.state["certs"].pop("z.com")
            fake.state["errors"]["/certs/api/domain"] = [404]
            with pytest.raises(BgpHeApiError, match="fake error 404"):
                await cli.certsByDomain("z.com")

            fake.state["whoisdns"]["w.com"] = 5
            with pytest.raises(BgpHeApiError, match="no whois data"):
                await cli.whoisDomain("w.com")

            fake.state["prefixes"][5] = "nope"
            with pytest.raises(BgpHeApiError, match="prefixes isn't a list"):
                await cli.prefixesOriginated(5)

            with pytest.raises(BgpHeApiError, match="HTTP 404 for /nope: not found"):
                await cli.getJson("/nope")


async def test_retries():
    async with FakeBgpHe() as fake:
        session, cli = await withClient(fake)
        async with session:
            fake.state["errors"]["/whois/as15169"] = [503, (429, "0"), 502]
            assert "GOOGLE" in await cli.whoisAsn(15169)
            assert fake.count("/whois/as15169") == 4

            # Gives up after MAX_RETRIES retries.
            fake.state["errors"]["/whois/as15169"] = [503] * 4
            with pytest.raises(BgpHeApiError, match="HTTP 503"):
                await cli.whoisAsn(15169)

            # A Retry-After longer than MAX_RETRY_AFTER isn't waited for.
            fake.state["errors"]["/whois/as15169"] = [(429, "3600")]
            with pytest.raises(BgpHeApiError, match="asked to wait 3600 seconds"):
                await cli.whoisAsn(15169)

    # Connection errors are retried, then raised.
    session = aiohttp.ClientSession()
    async with session:
        cli = BgpHeClient(session, url="http://127.0.0.1:1", interval=0, backoff=0)
        with pytest.raises(BgpHeApiError, match="Unable to connect to bgp.he.net"):
            await cli.whoisAsn(15169)
        assert cli.count == c_client.MAX_RETRIES + 1


async def test_body_limit(monkeypatch):
    monkeypatch.setattr(c_client, "MAX_BODY", 100)
    async with FakeBgpHe() as fake:
        session, cli = await withClient(fake)
        async with session:
            with pytest.raises(BgpHeApiError, match="too large"):
                await cli.whoisDomain("microsoft.com")


async def test_throttle():
    throttle = c_client.Throttle(0.05)
    loop = asyncio.get_running_loop()
    start = loop.time()
    for _ in range(3):
        await throttle.wait()
    assert loop.time() - start >= 0.1
    assert c_client.Throttle(None).interval == 0.0


def test_helpers():
    assert c_client.retryAfter(None) is None
    assert c_client.retryAfter("5") == 5.0
    assert c_client.retryAfter("-5") == 0.0
    assert c_client.retryAfter("nope") is None
    when = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=60)
    assert 50 < c_client.retryAfter(email.utils.format_datetime(when)) <= 60
    assert c_client.retryAfter("Wed, 21 Oct 2015 07:28:00") == 0.0

    assert c_client.errMesg("/x", 500, None, "plain text") == (
        "bgp.he.net returned HTTP 500 for /x: plain text"
    )
    assert c_client.errMesg("/x", 500, None, "<html>") == "bgp.he.net returned HTTP 500 for /x."
    assert c_client.errMesg("/x", 400, {"message": "m"}, "") == (
        "bgp.he.net returned HTTP 400 for /x: m"
    )
    assert c_client.seg("a/b c") == "a%2Fb%20c"

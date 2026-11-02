"""Tests for the Malpedia API client."""

import asyncio
import datetime
import email.utils
import io
import zipfile

import aiohttp
import pytest

from malpediasvc import client as m_client
from malpediasvc.client import MalpediaApiError, MalpediaClient

from . import fakemalpedia as fm


async def _client(fake, **kwargs):
    session = aiohttp.ClientSession()
    opts = {"interval": 0, "backoff": 0, "timeout": 10}
    opts.update(kwargs)
    return session, MalpediaClient(session, url=fake.url, **opts)


async def test_endpoints():
    async with fm.FakeMalpedia() as fake:
        session, cli = await _client(fake)
        async with session:
            assert await cli.version() == {"version": 26601, "date": "2026-10-30T16:25:07Z"}
            assert "apt28" in await cli.listActors()
            assert "win.xagent" in await cli.listFamilies()
            assert "APT28" in await cli.getActors()
            assert "win.xagent" in await cli.getFamilies()
            assert (await cli.getActor("apt28"))["value"] == "APT28"
            assert (await cli.getFamily("win.xagent"))["common_name"] == "X-Agent"
            assert fm.URL_SEDNIT in (await cli.getReferences())["references"]
            assert "@online{" in await cli.getBib()
            assert "sednit" in await cli.getBibActor("apt28")
            assert "fireeye" in await cli.getBibFamily("win.xagent")
            assert (await cli.findActor("fancy"))[0]["name"] == "apt28"
            assert (await cli.findFamily("wcry"))[0]["name"] == "win.wannacryptor"
            assert "win.xagent" in await cli.listYara()
            assert "win.xagent_w0.yar" in (await cli.getYaraFamily("win.xagent"))["tlp_white"]
            assert await cli.getYaraAfter("2026-10-01") == {}
            rules = await cli.getYaraTlp("tlp_white")
            assert set(rules) == {"win.xagent_w0.yar", "win.xagent_auto.yar", "win.wannacryptor_w0.yar"}

            with pytest.raises(MalpediaApiError, match="Unknown YARA TLP"):
                await cli.getYaraTlp("tlp_red")

            # Path segments are quoted, so IDs can't change the endpoint.
            with pytest.raises(MalpediaApiError, match="HTTP 404"):
                await cli.getActor("../get/misp")
            assert "/api/get/actor/..%2Fget%2Fmisp" in fake.requests

            assert cli.count == len(fake.requests)
            # Every request identifies the service.
            assert all(h.get("User-Agent") == m_client.USER_AGENT for h in fake.headers)
            # No API token is ever sent.
            assert not any("Authorization" in h for h in fake.headers)


async def test_errors_and_retries():
    async with fm.FakeMalpedia() as fake:
        session, cli = await _client(fake)
        async with session:
            # Retried until it works.
            fake.state["errors"]["/api/get/version"] = [503, 429, 500]
            assert (await cli.version())["version"] == 26601
            assert fake.countPaths("/api/get/version") == 4

            # Gives up after MAX_RETRIES retries.
            fake.state["errors"]["/api/get/version"] = [502] * 10
            with pytest.raises(MalpediaApiError, match="HTTP 502 for /get/version: fake error 502") as exc:
                await cli.version()
            assert exc.value.code == 502
            assert fake.countPaths("/api/get/version") == 4 + m_client.MAX_RETRIES + 1

            # Client errors aren't retried.
            fake.state["errors"]["/api/get/family/win.nope"] = []
            before = len(fake.requests)
            with pytest.raises(MalpediaApiError, match="HTTP 404") as exc:
                await cli.getFamily("win.nope")
            assert exc.value.code == 404
            assert len(fake.requests) == before + 1

        # Unexpected shapes.
        fake.state["errors"].clear()
        session, cli = await _client(fake)
        async with session:
            fake.state["version"] = {"nope": 1}
            with pytest.raises(MalpediaApiError, match="Unexpected response from /get/version"):
                await cli.version()
            fake.state["actorids"] = {"not": "a list"}
            with pytest.raises(MalpediaApiError, match="expected a list"):
                await cli.listActors()
            fake.state["families"] = ["not", "a dict"]
            with pytest.raises(MalpediaApiError, match="expected an object"):
                await cli.getFamilies()
            fake.state["references"] = None
            with pytest.raises(MalpediaApiError, match="no references"):
                await cli.getReferences()


async def test_retry_after():
    async with fm.FakeMalpedia() as fake:
        session, cli = await _client(fake)
        async with session:
            loop = asyncio.get_running_loop()
            fake.state["errors"]["/api/get/version"] = [(429, "1")]
            start = loop.time()
            assert (await cli.version())["version"] == 26601
            # The backoff is 0, but Malpedia asked for a second.
            assert loop.time() - start >= 0.9

            # Asking for too long a wait isn't retried at all.
            fake.state["errors"]["/api/get/version"] = [(503, "86400")]
            before = len(fake.requests)
            with pytest.raises(MalpediaApiError, match="asked to wait 86400.0 seconds"):
                await cli.version()
            assert len(fake.requests) == before + 1

    assert m_client.retryAfter(None) is None
    assert m_client.retryAfter("") is None
    assert m_client.retryAfter("garbage") is None
    assert m_client.retryAfter("-5") == 0.0
    assert m_client.retryAfter(" 30 ") == 30.0
    assert m_client.retryAfter("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0
    assert 3500 < m_client.retryAfter(email.utils.format_datetime(
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1), usegmt=True)) <= 3600


async def test_connection_errors():
    session = aiohttp.ClientSession()
    async with session:
        cli = MalpediaClient(session, url="http://127.0.0.1:1/api", interval=0, backoff=0, timeout=5)
        with pytest.raises(MalpediaApiError, match="Unable to connect to Malpedia"):
            await cli.version()
        assert cli.count == m_client.MAX_RETRIES + 1


async def test_bad_json_and_size(monkeypatch):
    async with fm.FakeMalpedia() as fake:
        session, cli = await _client(fake)
        async with session:
            with pytest.raises(MalpediaApiError, match="Unable to parse the JSON"):
                await cli.getJson("/get/bib")
            monkeypatch.setattr(m_client, "MAX_BODY", 10)
            with pytest.raises(MalpediaApiError, match="too large"):
                await cli.getBib()


async def test_large_bodies():
    # Bodies far bigger than one network read come back whole.
    async with fm.FakeMalpedia() as fake:
        fake.state["bib"] = [
            ("online", f"key:{i}", "Author", "Title " + "x" * 200, "2020", "Org", f"https://example.com/{i}")
            for i in range(20000)
        ]
        session, cli = await _client(fake)
        async with session:
            text = await cli.getBib()
            assert len(text) > 5 * 1024 * 1024
            assert text == fake.bibText()


async def test_throttle():
    throttle = m_client.Throttle(0.2)
    loop = asyncio.get_running_loop()
    start = loop.time()
    for _ in range(3):
        await throttle.wait()
    assert loop.time() - start >= 0.39

    # No interval, no waiting.
    throttle = m_client.Throttle(0)
    start = loop.time()
    for _ in range(50):
        await throttle.wait()
    assert loop.time() - start < 0.2


def test_unzip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zfd:
        zfd.writestr("dir/", "")
        zfd.writestr("dir/win.a_w0.yar", "rule a { condition: true }")
        zfd.writestr("README.txt", "not a rule")
    assert m_client.unzipRules(buf.getvalue()) == {"win.a_w0.yar": "rule a { condition: true }"}
    assert m_client.unzipRules(b"") == {}
    with pytest.raises(MalpediaApiError, match="invalid YARA zip"):
        m_client.unzipRules(b"not a zip")


def test_errmesg():
    assert m_client.errMesg("/x", 403, b'{"detail": "No token provided."}') == (
        "Malpedia returned HTTP 403 for /x: No token provided."
    )
    assert m_client.errMesg("/x", 404, b"<html>") == "Malpedia returned HTTP 404 for /x: not found."
    assert m_client.errMesg("/x", 500, b"oops") == "Malpedia returned HTTP 500 for /x: oops"
    assert m_client.errMesg("/x", 500, b"<html>") == "Malpedia returned HTTP 500 for /x."
    assert m_client.errMesg("/x", 500, b"") == "Malpedia returned HTTP 500 for /x."

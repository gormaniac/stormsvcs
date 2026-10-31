"""A fake rule feed server and the fixtures the tests share.

Tests that run Snort are marked with ``needsnort``, they skip when the snort binary isn't on the
PATH (ex. the CI host test job), unless SLIB_SNORT_REQUIRE=1 (the test image), where they fail.
"""

import contextlib
import io
import os
import shutil
import tarfile
from typing import Self

import pytest
from aiohttp import web

REQUIRE = os.environ.get("SLIB_SNORT_REQUIRE") == "1"
HAVE_SNORT = bool(shutil.which("snort") and shutil.which("snort2lua"))

needsnort = pytest.mark.skipif(
    not HAVE_SNORT and not REQUIRE,
    reason="Snort 3 isn't installed, these run in the service's test image.",
)

# Snort 3 rules that match pcaps.samplePcap(), plus one Snort refuses to load.
SNORT3_RULES = """\
# A Snort 3 test feed.
alert http any any -> any any ( msg:"SLIB TEST beacon URI"; http_uri; content:"/malware/beacon.php"; reference:cve,2021-44228; reference:url,example.com/beacon; classtype:trojan-activity; sid:1000001; rev:2; )
alert tcp any any -> any 80 ( msg:"SLIB TEST evil host"; flow:established,to_server; content:"evil.example.com"; sid:1000002; rev:1; )
alert udp any any -> any 9999 ( msg:"SLIB TEST UDP ping"; content:"SLIBSNORT-UDP"; sid:1000003; rev:1; )
# alert tcp any any -> any any ( msg:"SLIB TEST disabled"; content:"slibsnorttest"; sid:1000004; rev:1; )
alert tcp any any -> any any ( msg:"SLIB TEST bad keyword"; foobar:1; sid:1000005; rev:1; )
alert tcp any any -> any any ( msg:"SLIB TEST never matches"; content:"this is not in the pcap"; sid:1000006; rev:3; )
"""

# Snort 2.9 (ET style) rules, converted by snort2lua. The first matches the sample PCAP's HTTP response.
SNORT2_RULES = """\
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET SLIB TEST Response Body"; flow:established,from_server; file_data; content:"slibsnorttest"; reference:md5,662002d61f1aebd64fc204ce40fd65f2; classtype:trojan-activity; sid:2000001; rev:4; metadata:created_at 2021_11_01, malware_family SlibTest, updated_at 2024_03_05;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET SLIB TEST User-Agent"; flow:established,to_server; content:"SlibSnortTest"; http_header; sid:2000002; rev:1;)
#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET SLIB TEST Disabled"; content:"nope"; sid:2000003; rev:1;)
"""

SNORT2_DELETED = """\
#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET DELETED SLIB"; content:"gone"; sid:2000099; rev:1;)
"""


def tarGz(files: dict[str, str]) -> bytes:
    """A .tar.gz of {name: text}."""

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tfd:
        for name, text in files.items():
            byts = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(byts)
            tfd.addfile(info, io.BytesIO(byts))
    return buf.getvalue()


class FakeFeeds:
    """Serve rule feeds from localhost. Set ``files`` (path -> bytes) to change what's served."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {
            "/snort3.tar.gz": tarGz(
                {"rules/snort3-test.rules": SNORT3_RULES, "rules/LICENSE": "test"}
            ),
            "/et.tar.gz": tarGz(
                {
                    "rules/emerging-test.rules": SNORT2_RULES,
                    "rules/emerging-deleted.rules": SNORT2_DELETED,
                }
            ),
        }
        self.requests: list[tuple[str, str | None]] = []
        self.runner: web.AppRunner | None = None
        self.url = ""

    async def handle(self, request: web.Request) -> web.Response:
        self.requests.append((request.path, request.headers.get("If-None-Match")))
        byts = self.files.get(request.path)
        if byts is None:
            return web.Response(status=404, text="nope")
        etag = f'"{hash(byts) & 0xFFFFFFFF:x}"'
        if request.headers.get("If-None-Match") == etag:
            return web.Response(status=304)
        return web.Response(body=byts, headers={"ETag": etag})

    async def __aenter__(self) -> Self:
        app = web.Application()
        app.router.add_get("/{path:.*}", self.handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{port}"
        return self

    async def __aexit__(self, *args) -> None:
        await self.runner.cleanup()

    def feeds(self) -> list[dict]:
        """Feed definitions pointed at this server."""

        return [
            {
                "name": "test-snort3",
                "url": f"{self.url}/snort3.tar.gz",
                "engine": 3,
                "desc": "A Snort 3 test feed.",
            },
            {
                "name": "test-et",
                "url": f"{self.url}/et.tar.gz",
                "engine": 2,
                "exclude": ["emerging-deleted.rules"],
            },
        ]


@contextlib.asynccontextmanager
async def snortSvc(test, conf: dict | None = None):
    """Yield (core, svc, feeds) - a Cortex with slib.snort added, its feeds pointed at a FakeFeeds."""

    from snortsvc import SnortSvc

    async with FakeFeeds() as feeds:
        sconf = {"snort:feeds": feeds.feeds()}
        sconf.update(conf or {})
        async with test.getTestCoreProxSvc(SnortSvc, ssvc_conf=sconf) as (core, prox, svc):
            yield core, svc, feeds

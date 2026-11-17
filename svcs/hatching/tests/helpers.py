"""Test helpers: a Cortex with slib.hatching added, pointed at a fake Hatching Triage API."""

import contextlib

from aiohttp import web
from pyhatching import testing as ft


class FakeTriage(ft.FakeTriage):
    """pyhatching's ``FakeTriage``, plus what the real API does that it doesn't.

    - ``PUT /v0/yara/{name}`` with a new ``name`` renames the rule.
    """

    async def updateRule(self, request: web.Request) -> web.Response:
        name = request.match_info["name"]
        body = request[ft.RECORD]["json"] or {}
        newname = body.get("name") or name
        resp = await super().updateRule(request)
        if resp.status < 400 and newname != name:
            rule = self.rules.pop(name)
            rule["name"] = newname
            self.rules[newname] = rule
        return resp


@contextlib.asynccontextmanager
async def hatchingSvc(test, apikey: str | None = ft.APIKEY, conf: dict | None = None):
    """Yield (core, svc, fake) - a Cortex with slib.hatching added, pointed at a FakeTriage."""

    from hatchingsvc import HatchingSvc

    async with FakeTriage() as fake:
        sconf = {"hatching:url": fake.url, "hatching:apikey": apikey}
        sconf.update(conf or {})
        async with test.getTestCoreProxSvc(HatchingSvc, ssvc_conf=sconf) as (core, prox, svc):
            yield core, svc, fake

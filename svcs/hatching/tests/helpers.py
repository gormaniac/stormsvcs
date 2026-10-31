"""Test helpers: a Cortex with slib.hatching added, pointed at pyhatching's FakeTriage."""

import contextlib

from pyhatching import testing as ft


@contextlib.asynccontextmanager
async def hatchingSvc(test, apikey: str | None = ft.APIKEY, conf: dict | None = None):
    """Yield (core, svc, fake) - a Cortex with slib.hatching added, pointed at a FakeTriage."""

    from hatchingsvc import HatchingSvc

    async with ft.FakeTriage() as fake:
        sconf = {"hatching:url": fake.url, "hatching:apikey": apikey}
        sconf.update(conf or {})
        async with test.getTestCoreProxSvc(HatchingSvc, ssvc_conf=sconf) as (core, prox, svc):
            yield core, svc, fake

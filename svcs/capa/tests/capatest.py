"""Shared fixtures for the slib.capa tests.

The tests run the real capa against a tiny 64-bit shellcode sample (``SAMPLE``) with
the test rules in ``data/rules`` (``RULES``), which takes a couple seconds per scan.
"""

import asyncio
import contextlib
import hashlib
import os

from capasvc import CapaSvc


RULES = os.path.join(os.path.dirname(__file__), "data", "rules")
"""The test capa rules directory."""

RULES_VERSION = "vtest"

SAMPLE = (
    bytes.fromhex("4831c04831dbc3")  # xor rax, rax; xor rbx, rbx; ret
    + b"\x00" * 16
    + b"slib-capa-test-marker\x00"
    + b"\x00" * 16
)
"""A 64-bit shellcode sample that matches the test rules (with --format sc64)."""

SAMPLE_SHA256 = hashlib.sha256(SAMPLE).hexdigest()

MATCHED = [
    "contain marker without a namespace",
    "contain slib-capa test marker",
    "contain xor",
    "return from a function",
]
"""The test rules capa reports for SAMPLE, sorted by name (no lib rules)."""


def svcConf(axon=None, **conf) -> dict:
    """The slib.capa service config for the tests, keys set to None are left out."""

    base = {
        "capa:rules": RULES,
        "capa:rules:version": RULES_VERSION,
        "capa:rules:url": "https://example.com/rules/{version}/{path}",
    }
    if axon is not None:
        base["axon:url"] = axon.getLocalUrl()
    base.update(conf)
    return {k: v for k, v in base.items() if v is not None}


@contextlib.asynccontextmanager
async def capaSvc(test, conf: dict | None = None, onload: bool = True):
    """Yield (core, svc, axon) - a Cortex with slib.capa added, sharing an Axon with the service.

    Waits for the package's onload (the rule import) to finish, unless onload is False.
    """

    async with test.getTestAxon() as axon:
        core_conf = {"axon": axon.getLocalUrl()}
        async with test.getTestCoreAndProxy(core_conf) as (core, prox):
            async with test.getTestCell(CapaSvc, svcConf(axon, **(conf or {}))) as svc:
                loaded = asyncio.Event()

                async def onPkgLoad(event):
                    if event[1].get("pkg") == "slib.capa":
                        loaded.set()

                with core.onWith("core:pkg:onload:complete", onPkgLoad):
                    await test.addSvcToCore(svc, core)
                    if onload:
                        await asyncio.wait_for(loaded.wait(), timeout=300)

                yield core, svc, axon


async def putSample(core, axon, byts: bytes = SAMPLE) -> str:
    """Save bytes to the Axon and make their file:bytes node. Returns the SHA256."""

    sha256 = hashlib.sha256(byts).hexdigest()
    await axon.put(byts)
    await core.nodes(f"[ file:bytes=sha256:{sha256} :sha256={sha256} ]")
    return sha256

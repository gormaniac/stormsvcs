"""Tests against the full capa-rules release, skipped unless SYN_CAPASVC_CAPA_RULES is set.

The service's container image sets it to the bundled rules, so these run in the test image.
Locally, point it at a checkout of mandiant/capa-rules (at the tag in capasvc.defs.RULES_VERSION):

    SYN_CAPASVC_CAPA_RULES=/path/to/capa-rules uv run pytest tests/test_live.py
"""

import os

import pytest
import synapse.tests.utils as s_tests

from capasvc.defs import RULES_URL, RULES_VERSION
from capasvc.rules import CapaRules

from .capatest import SAMPLE_SHA256, capaSvc, putSample


LIVE_RULES = os.getenv("SYN_CAPASVC_CAPA_RULES")
LIVE_SIGS = os.getenv("SYN_CAPASVC_CAPA_SIGS")

pytestmark = pytest.mark.skipif(not LIVE_RULES, reason="SYN_CAPASVC_CAPA_RULES is not set")


def liveConf() -> dict:
    return {
        "capa:rules": LIVE_RULES,
        "capa:rules:version": RULES_VERSION,
        "capa:rules:url": RULES_URL,
        "capa:sigs": LIVE_SIGS,
        "capa:timeout": 600,
    }


class TestLiveRules(s_tests.SynTest):
    def test_load(self):
        rules = CapaRules(LIVE_RULES, RULES_VERSION, RULES_URL)
        info = rules.info()
        assert info["rules"] > 900
        assert info["lib"] > 0
        assert info["namespaces"] > 300

        rec = rules.rules["create process on Windows"]
        assert rec["tag"] == "host_interaction.process.create"
        assert rec["url"] == (
            f"https://github.com/mandiant/capa-rules/blob/{RULES_VERSION}/"
            "host-interaction/process/create/create-process-on-windows.yml"
        )

        tags = {t["tag"] for t in rules.tagRecords()}
        assert "anti_analysis.anti_debugging.debugger_detection" in tags

    async def test_import_scan(self):
        async with capaSvc(self, conf=liveConf()) as (core, svc, axon):
            info = svc.capaRules.info()
            assert len(await core.nodes("meta:rule")) == info["rules"]
            assert len(await core.nodes("meta:rule:type=capa.lib")) == info["lib"]
            assert len(await core.nodes("syn:tag^=rep.capa.host_interaction +:doc")) > 10
            assert len(await core.nodes("meta:rule -(refs)> it:mitre:attack:technique")) > 100

            await putSample(core, axon)
            msgs = await core.stormlist(
                f"file:bytes:sha256={SAMPLE_SHA256} | slib.capa.scan --format sc64"
            )
            self.stormHasNoWarnErr(msgs)
            node = (await core.nodes(f"file:bytes:sha256={SAMPLE_SHA256}"))[0]
            data = await node.getData("slib:capa")
            assert data["rules"]["sha256"] == info["sha256"]

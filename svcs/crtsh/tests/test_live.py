"""Live tests against crt.sh's real database. Skipped unless explicitly enabled.

    SLIB_CRTSH_LIVE=1 uv run pytest tests/test_live.py -v

crt.sh allows one connection per client IP, so close other connections (psql)
from this IP first. Everything runs through one service, so one connection, and
crt.sh is slow: expect this to take a few minutes.

These assert on known, stable facts (a www.comodo.com certificate and its
issuing CA) and on the shape of results, since crt.sh's data grows constantly.
"""

import os

import pytest
import synapse.tests.utils as s_tests

from crtshsvc import CrtshSvc, norm


LIVE = os.environ.get("SLIB_CRTSH_LIVE") == "1"

pytestmark = pytest.mark.skipif(not LIVE, reason="Set SLIB_CRTSH_LIVE=1 to run live crt.sh tests.")

CERTID = 29578180990
"""A www.comodo.com certificate."""

ISSUER = 204411
"""Its issuing CA, C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA OV R36."""

ISSUER_CERT = 4267304698
"""The certificate of CA 204411."""


class TestLive(s_tests.SynTest):
    async def test_live(self):
        conf = {"crtsh:connect:timeout": 600}
        async with self.getTestCoreProxSvc(CrtshSvc, ssvc_conf=conf) as (core, prox, svc):
            # ---- Lookups by every identifier ----
            cert = await svc.get(CERTID)
            assert cert is not None and "error" not in cert
            assert cert["crtsh"]["issuer"]["id"] == ISSUER
            assert "Sectigo" in cert["crtsh"]["issuer"]["name"]
            assert cert["crtsh"]["ctlog"], "Every certificate in crt.sh was logged somewhere."
            assert cert["crtsh"]["logged"]
            # crt.sh found it searching for www.comodo.com, a DNS SAN or CN, or a subdomain of it.
            names = norm.fieldValues(cert, "dns")
            assert norm.matches(cert, "dns", "www.comodo.com", "suffix"), names

            for kind, valu in (
                ("sha256", cert["sha256"]),
                ("sha1", cert["sha1"]),
                ("serial", cert["serial"]),
                ("ski", cert["ski"]),
                ("spki", cert["pubkey"]["sha256"]),
                ("spkisha1", cert["pubkey"]["sha1"]),
                ("subjectsha1", cert["subject"]["sha1"]),
            ):
                found = await svc.lookup(kind, valu, limit=50)
                assert CERTID in [c["crtsh"]["id"] for c in found], kind

            # ---- Search ----
            ids = [d["crtsh"]["id"] async for d in svc.searchGenr(dns="www.comodo.com", limit=500)]
            assert CERTID in ids
            async for details in svc.searchGenr(
                dns="comodo.com", valid=True, precerts=False, limit=20
            ):
                assert not details["precert"]
                assert norm.matches(details, "dns", "comodo.com", "suffix"), norm.fieldValues(
                    details, "dns"
                )

            # ---- CAs, issued, and chains ----
            cas = await svc.cas(name="Sectigo Public Server Authentication CA OV R36")
            ca = next(ca for ca in cas if ca["id"] == ISSUER)
            assert ISSUER_CERT in ca["certs"]

            issued = [d async for d in svc.issuedGenr(caids=[ISSUER], valid=True, limit=5)]
            assert len(issued) == 5
            assert all(d["crtsh"]["issuer"]["id"] == ISSUER for d in issued)
            times = [d["notbefore"] for d in issued]
            assert times == sorted(times, reverse=True)

            siblings = [d async for d in svc.pivotGenr(CERTID, "siblings", limit=3)]
            assert len(siblings) == 3 and CERTID not in [d["crtsh"]["id"] for d in siblings]

            chain = await svc.chain(CERTID)
            ids = [c["crtsh"]["id"] for c in chain["certs"]]
            assert ids[0] == CERTID and ISSUER_CERT in ids
            for path in chain["paths"]:
                root = next(c for c in chain["certs"] if c["sha256"] == path[-1])
                assert root["selfsigned"], "Every chain ends at a root."

            # ---- Storm, end to end ----
            msgs = await core.stormlist(f"slib.crtsh.cert {CERTID} --chain --yield")
            self.stormHasNoWarnErr(msgs)
            nodes = await core.nodes(
                f"crypto:x509:cert:sha256={cert['sha256']} :issuer:cert -> crypto:x509:cert"
            )
            assert len(nodes) == 1
            fqdns = (await core.nodes(f"crypto:x509:cert:sha256={cert['sha256']}"))[0].get(
                "identities:fqdns"
            )
            assert any(f == "comodo.com" or f.endswith(".comodo.com") for f in fqdns), fqdns

            msgs = await core.stormlist(
                "slib.crtsh.search --dns www.comodo.com --exact --valid --limit 5"
            )
            self.stormHasNoWarnErr(msgs)

            msgs = await core.stormlist(
                f"slib.crtsh.admin.sql 'SELECT ID, NAME FROM ca WHERE ID = $1' --args (({ISSUER}),)"
            )
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("Sectigo Public Server Authentication CA OV R36", msgs)

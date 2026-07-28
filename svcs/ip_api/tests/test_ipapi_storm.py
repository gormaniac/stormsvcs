"""Pytests for the slib.ipapi Storm package (commands, modules, and perms)."""

from unittest import mock

import synapse.tests.utils as s_tests

from ipapi import __version__
from ipapi.svc import IpApiSvc
from ipapi.defs import SVC_NAME


CMDS = (
    f"{SVC_NAME}.query",
    f"{SVC_NAME}.admin.settag",
    f"{SVC_NAME}.admin.disabletag",
    f"{SVC_NAME}.admin.enabletag",
)
MODS = (
    f"{SVC_NAME}.lib",
    f"{SVC_NAME}.admin",
)

# A canned successful ip-api.com result, already shaped the way IpApiSvc._query()
# returns it (i.e. with the "as" key already renamed to "as_").
SUCCESS_DATA = {
    "query": "8.8.8.8",
    "status": "success",
    "country": "United States",
    "countryCode": "US",
    "region": "VA",
    "regionName": "Virginia",
    "city": "Ashburn",
    "zip": "20149",
    "lat": 39.03,
    "lon": -77.5,
    "timezone": "America/New_York",
    "isp": "Google LLC",
    "org": "Google Public DNS",
    "as_": "AS15169 Google LLC",
    "asname": "GOOGLE",
    "mobile": False,
    "proxy": False,
    "hosting": True,
}


class TestIpApiStorm(s_tests.SynTest):
    """Test suite for the slib.ipapi Storm package's commands and modules."""

    async def test_svc_starts(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            msgs = await core.stormlist("service.list")
            self.stormIsInPrint(f"true (svc) ({SVC_NAME} @ {__version__})", msgs)

    async def test_pkg_cmds_exist(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            for cmd in CMDS:
                assert cmd in core.stormcmds

    async def test_pkg_mods_exist(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            for mod in MODS:
                assert mod in core.stormmods

    async def test_pkg_mods_import(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            for mod in MODS:
                msgs = await core.stormlist(f"$mod = $lib.import({mod})")
                self.stormHasNoErr(msgs)

    async def test_svc_import(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            msgs = await core.stormlist(f"$svc = $lib.service.get({SVC_NAME})")
            self.stormHasNoErr(msgs)

    async def test_tag_global_default_enabled(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            msgs = await core.stormlist('$lib.print($lib.globals.get("slib:ipapi:tag:enabled"))')
            self.stormIsInPrint("true", msgs)

    async def test_cmd_query_string_success(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):

            async def fake_query(ipaddr):
                return dict(SUCCESS_DATA), {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8 --yield")
                self.stormHasNoErr(msgs)

            nodes = await core.nodes("inet:ipv4=8.8.8.8")
            assert len(nodes) == 1
            assert nodes[0].get("asn") is not None

    async def test_cmd_query_node_input(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            await core.nodes("[ inet:ipv4=8.8.8.8 ]")

            async def fake_query(ipaddr):
                return dict(SUCCESS_DATA), {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(f"inet:ipv4=8.8.8.8 | {SVC_NAME}.query --yield")
                self.stormHasNoErr(msgs)

            nodes = await core.nodes("inet:ipv4=8.8.8.8")
            assert len(nodes) == 1
            assert nodes[0].get("asn") is not None

    async def test_cmd_query_business_failure(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):

            async def fake_query(ipaddr):
                return {"status": "fail", "message": "reserved range"}, {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 10.0.0.1")
                self.stormHasNoErr(msgs)
                self.stormIsInWarn("There was an error querying the IPAPI service", msgs)

    async def test_cmd_query_unsupported_node_form(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            await core.nodes("[ inet:fqdn=example.com ]")

            with self.getLoggerStream("synapse.storm.log") as stream:
                msgs = await core.stormlist(f"inet:fqdn=example.com | {SVC_NAME}.query")
                self.stormHasNoErr(msgs)

                # LoggerStream.expect() raises AssertionError on timeout (it doesn't
                # reliably return a truthy value on success), so just await it.
                await stream.expect("is not supported")


class TestIpApiStormPerms(s_tests.SynTest):
    """Test suite proving the slib.ipapi Storm package's perms are correctly enforced."""

    async def _addPermUsers(self, core):
        """Add "admin" and "user" test users, each granted exactly one slib.ipapi perm rule.

        Both also need the built-in "service.get" perm, since the slib.ipapi.lib/admin
        Storm modules call $lib.service.get() internally, which Synapse gates separately
        from any custom perms defined by the package. The "user" user additionally needs
        a generic "node" perm, since running slib.ipapi.query creates/edits nodes
        (geo:place, ou:org, inet:asn, inet:ipv4/ipv6) - a separate Synapse-level concern
        from the package's own custom perms.
        """

        adminInfo = await core.addUser("admin")
        adminIden = adminInfo.get("iden")
        await core.addUserRule(adminIden, (True, ("service", "get")))
        await core.addUserRule(adminIden, (True, ("slib", "ipapi", "admin")))

        userInfo = await core.addUser("user")
        userIden = userInfo.get("iden")
        await core.addUserRule(userIden, (True, ("service", "get")))
        await core.addUserRule(userIden, (True, ("node",)))
        await core.addUserRule(userIden, (True, ("slib", "ipapi", "user")))

        return adminIden, userIden

    async def test_cmd_admin_settag_as_admin_user(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            adminIden, _userIden = await self._addPermUsers(core)

            msgs = await core.stormlist(
                f"{SVC_NAME}.admin.settag myprefix", opts={"user": adminIden}
            )
            self.stormHasNoErr(msgs)

            msgs = await core.stormlist('$lib.print($lib.globals.get("slib:ipapi:tag:prefix"))')
            self.stormIsInPrint("myprefix", msgs)

    async def test_cmd_admin_disabletag_as_admin_user(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            adminIden, _userIden = await self._addPermUsers(core)

            msgs = await core.stormlist(
                f"{SVC_NAME}.admin.disabletag", opts={"user": adminIden}
            )
            self.stormHasNoErr(msgs)

            msgs = await core.stormlist('$lib.print($lib.globals.get("slib:ipapi:tag:enabled"))')
            self.stormIsInPrint("false", msgs)

    async def test_cmd_admin_enabletag_as_admin_user(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            adminIden, _userIden = await self._addPermUsers(core)

            await core.stormlist(f"{SVC_NAME}.admin.disabletag", opts={"user": adminIden})

            msgs = await core.stormlist(
                f"{SVC_NAME}.admin.enabletag", opts={"user": adminIden}
            )
            self.stormHasNoErr(msgs)

            msgs = await core.stormlist('$lib.print($lib.globals.get("slib:ipapi:tag:enabled"))')
            self.stormIsInPrint("true", msgs)

    async def test_cmd_query_as_user_user(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            _adminIden, userIden = await self._addPermUsers(core)

            async def fake_query(ipaddr):
                return dict(SUCCESS_DATA), {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(
                    f"{SVC_NAME}.query --query 8.8.8.8 --yield", opts={"user": userIden}
                )
                self.stormHasNoErr(msgs)

            nodes = await core.nodes("inet:ipv4=8.8.8.8")
            assert len(nodes) == 1

    async def test_user_cannot_run_admin_cmd(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            _adminIden, userIden = await self._addPermUsers(core)

            msgs = await core.stormlist(
                f"{SVC_NAME}.admin.settag someprefix", opts={"user": userIden}
            )
            self.stormIsInErr("requires permission: slib.ipapi.admin", msgs)

            msgs = await core.stormlist('$lib.print($lib.globals.get("slib:ipapi:tag:prefix"))')
            self.stormNotInPrint("someprefix", msgs)

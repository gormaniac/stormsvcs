"""Pytests for the slib.ipapi Storm package (commands, modules, and perms)."""

import pathlib
import tomllib
from unittest import mock

import synapse.tests.utils as s_tests

from ipapi import __version__
from ipapi.svc import IpApiSvc, shapeData
from ipapi.defs import PKGDEFS, SVC_GUID, SVC_NAME

SVC_DIR = pathlib.Path(__file__).parent.parent


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

# A canned successful ip-api.com result, as ip-api.com returns it.
RAW_DATA = {
    "query": "8.8.8.8",
    "status": "success",
    "country": "United States",
    "countryCode": "US",
    "region": "VA",
    "regionName": "Virginia",
    "city": "Ashburn",
    "lat": 39.03,
    "lon": -77.5,
    "isp": "Google LLC",
    "org": "Google Public DNS",
    "as": "AS15169 Google LLC",
    "asname": "GOOGLE",
    "reverse": "dns.google",
    "mobile": False,
    "proxy": False,
    "hosting": True,
}


def shaped(**kwargs) -> dict:
    """RAW_DATA, updated with kwargs, shaped the way IpApiSvc._query() returns it
    (i.e. with the "as" key renamed to "as_" and parsed into asnum/asorg)."""
    return shapeData({**RAW_DATA, **kwargs})


SUCCESS_DATA = shaped()


class TestIpApiStorm(s_tests.SynTest):
    """Test suite for the slib.ipapi Storm package's commands and modules."""

    def test_versions_match(self):
        # The version lives in pyproject.toml (the image tag), __init__.py, the package yaml,
        # and the service's own uv.lock entry.
        with (SVC_DIR / "pyproject.toml").open("rb") as fd:
            assert tomllib.load(fd)["project"]["version"] == __version__
        assert PKGDEFS[0]["version"] == __version__

        with (SVC_DIR / "uv.lock").open("rb") as fd:
            pkgs = {p["name"]: p for p in tomllib.load(fd)["package"]}
        assert pkgs["ipapi"]["version"] == __version__

    def test_lib_source_guid(self):
        # slib.ipapi.lib hardcodes the service's meta:source guid for its -(seen)> edges.
        lib = SVC_DIR / "src/ipapi/pkgproto/storm/modules/slib.ipapi.lib.storm"
        assert f'$srcGuid = "{SVC_GUID}"' in lib.read_text()

    async def test_svc_starts(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            msgs = await core.stormlist("service.list")
            self.stormIsInPrint(f"true (svc) ({SVC_NAME} @ {__version__})", msgs)

    async def test_pkg_cmds_exist(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            for cmd in CMDS:
                assert cmd in core.stormcmds

    async def test_pkg_cmd_inputs(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            for cdef in PKGDEFS[0]["commands"]:
                # The "forms" key is deprecated and removed in Synapse 3.0.0, use "cmdinputs".
                assert "forms" not in cdef, cdef["name"]
                for cmdinput in cdef.get("cmdinputs", ()):
                    assert core.model.form(cmdinput["form"]) is not None, (cdef["name"], cmdinput)

            msgs = await core.stormlist(f"{SVC_NAME}.query --help")
            self.stormIsInPrint("IPs to query ip-api.com for", msgs)

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

    async def test_cmd_query_place_names(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):

            async def fake_query(ipaddr):
                return dict(SUCCESS_DATA), {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8")
                self.stormHasNoErr(msgs)

            places = await core.nodes("geo:place")
            assert len(places) == 1
            assert places[0].get("name") == "ashburn, virginia, united states"

            telems = await core.nodes("inet:ipv4=8.8.8.8 -> geo:telem:node")
            assert len(telems) == 1
            assert telems[0].get("place:name") == "ashburn, virginia, united states"

    async def test_cmd_query_place_name_skips_empty_parts(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            data = dict(SUCCESS_DATA)
            data["city"] = ""

            async def fake_query(ipaddr):
                return data, {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8")
                self.stormHasNoErr(msgs)

            places = await core.nodes("geo:place")
            assert len(places) == 1
            assert places[0].get("name") == "virginia, united states"

    async def test_cmd_query_node_input(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            await core.nodes("[ inet:ipv4=8.8.8.8 ]")

            async def fake_query(ipaddr):
                # The command must send the printable address, not the
                # normalized integer value (134744072) of the inet:ipv4 node.
                assert ipaddr == "8.8.8.8"
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

            async def fake_query(ipaddr):
                # Unsupported forms must never reach the API - an empty query
                # would return data about the service host's own IP.
                raise AssertionError(f"_query was called with {ipaddr!r}")

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(f"inet:fqdn=example.com | {SVC_NAME}.query")
                self.stormHasNoErr(msgs)
                self.stormIsInWarn("is not supported by the slib.ipapi.query command", msgs)

    async def test_cmd_query_mixed_supported_unsupported_forms(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            await core.nodes("[ inet:ipv4=8.8.8.8 ] [ inet:fqdn=example.com ]")

            async def fake_query(ipaddr):
                return dict(SUCCESS_DATA), {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(
                    f"inet:ipv4=8.8.8.8 inet:fqdn=example.com | {SVC_NAME}.query"
                )
                self.stormHasNoErr(msgs)
                self.stormIsInWarn("is not supported by the slib.ipapi.query command", msgs)

            nodes = await core.nodes("inet:ipv4=8.8.8.8")
            assert nodes[0].get("asn") is not None

    async def test_cmd_query_no_yield_by_default(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            await core.nodes("[ inet:ipv4=8.8.8.8 ]")

            async def fake_query(ipaddr):
                return dict(SUCCESS_DATA), {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(f"inet:ipv4=8.8.8.8 | {SVC_NAME}.query")
                self.stormHasNoErr(msgs)

                nodeMsgs = [m for m in msgs if m[0] == "node"]
                assert len(nodeMsgs) == 1
                assert nodeMsgs[0][1][0] == ("inet:ipv4", 134744072)

    async def test_cmd_query_ipv4_creates_no_ipv6(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):

            async def fake_query(ipaddr):
                return dict(SUCCESS_DATA), {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8 --yield")
                self.stormHasNoErr(msgs)

            # Synapse also parses "8.8.8.8" as inet:ipv6=::ffff:8.8.8.8, which must not be made.
            assert len(await core.nodes("inet:ipv4=8.8.8.8")) == 1
            assert len(await core.nodes("inet:ipv6")) == 0

            telems = await core.nodes("geo:telem")
            assert len(telems) == 1
            assert telems[0].get("node") == ("inet:ipv4", 134744072)

    async def test_cmd_query_sets_ip_geo_props(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):

            async def fake_query(ipaddr):
                return dict(SUCCESS_DATA), {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8")
                self.stormHasNoErr(msgs)

            places = await core.nodes("geo:place")
            assert len(places) == 1

            nodes = await core.nodes("inet:ipv4=8.8.8.8")
            assert len(nodes) == 1
            assert nodes[0].get("latlong") == (39.03, -77.5)
            assert nodes[0].get("place") == places[0].ndef[1]
            assert nodes[0].get("loc") == "us.va.ashburn"

    async def test_cmd_query_sets_ipv6_geo_props(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            data = dict(SUCCESS_DATA)
            data["query"] = "2001:4860:4860::8888"

            async def fake_query(ipaddr):
                return data, {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(f'{SVC_NAME}.query --query "2001:4860:4860::8888"')
                self.stormHasNoErr(msgs)

            places = await core.nodes("geo:place")
            nodes = await core.nodes("inet:ipv6=2001:4860:4860::8888")
            assert len(nodes) == 1
            assert nodes[0].get("latlong") == (39.03, -77.5)
            assert nodes[0].get("place") == places[0].ndef[1]
            assert nodes[0].get("loc") == "us.va.ashburn"

    async def test_cmd_query_loc_partial(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            data = dict(SUCCESS_DATA)
            # Each loc part must be under the one before it, so a missing region drops the city.
            data["region"] = ""
            data["city"] = "St. Louis"

            async def fake_query(ipaddr):
                return data, {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8")
                self.stormHasNoErr(msgs)

            nodes = await core.nodes("inet:ipv4=8.8.8.8")
            assert nodes[0].get("loc") == "us"

            data["region"] = "MO"
            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8")
                self.stormHasNoErr(msgs)

            nodes = await core.nodes("inet:ipv4=8.8.8.8")
            assert nodes[0].get("loc") == "us.mo.st louis"

    async def test_cmd_query_loc_missing(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            data = dict(SUCCESS_DATA)
            data["countryCode"] = ""

            async def fake_query(ipaddr):
                return data, {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8")
                self.stormHasNoErr(msgs)

            nodes = await core.nodes("inet:ipv4=8.8.8.8")
            assert nodes[0].get("loc") is None
            assert nodes[0].get("latlong") == (39.03, -77.5)

    async def test_cmd_query_ipv6_node_input(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            await core.nodes("[ inet:ipv6=2001:4860:4860::8888 ]")

            data = dict(SUCCESS_DATA)
            data["query"] = "2001:4860:4860::8888"

            async def fake_query(ipaddr):
                assert ipaddr == "2001:4860:4860::8888"
                return data, {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(
                    f"inet:ipv6=2001:4860:4860::8888 | {SVC_NAME}.query --yield"
                )
                self.stormHasNoErr(msgs)

            nodes = await core.nodes("inet:ipv6=2001:4860:4860::8888")
            assert len(nodes) == 1
            assert nodes[0].get("asn") is not None

    async def test_cmd_query_ipv6_string(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            data = dict(SUCCESS_DATA)
            data["query"] = "2001:4860:4860::8888"

            async def fake_query(ipaddr):
                return data, {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(
                    f'{SVC_NAME}.query --query "2001:4860:4860::8888" --yield'
                )
                self.stormHasNoErr(msgs)

            nodes = await core.nodes("inet:ipv6=2001:4860:4860::8888")
            assert len(nodes) == 1

    async def test_cmd_query_malformed_asn_does_not_error(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            data = shaped(**{"as": "not-a-valid-asn-format"})

            async def fake_query(ipaddr):
                return data, {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8 --yield")
                self.stormHasNoErr(msgs)

            nodes = await core.nodes("inet:ipv4=8.8.8.8")
            assert len(nodes) == 1
            assert nodes[0].get("asn") is None
            assert len(await core.nodes("inet:asn")) == 0

    async def test_cmd_query_applies_default_tags(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):

            async def fake_query(ipaddr):
                return dict(SUCCESS_DATA), {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8 --yield")
                self.stormHasNoErr(msgs)

            nodes = await core.nodes("inet:ipv4=8.8.8.8")
            assert len(nodes) == 1
            assert "rep.ipapi.infra.hosting" in nodes[0].tags
            assert "rep.ipapi.infra.mobile" not in nodes[0].tags
            assert "rep.ipapi.infra.proxy" not in nodes[0].tags

    async def test_cmd_query_applies_custom_tag_prefix(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            msgs = await core.stormlist(f"{SVC_NAME}.admin.settag myorg")
            self.stormHasNoErr(msgs)

            async def fake_query(ipaddr):
                return dict(SUCCESS_DATA), {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8 --yield")
                self.stormHasNoErr(msgs)

            nodes = await core.nodes("inet:ipv4=8.8.8.8")
            assert "myorg.hosting" in nodes[0].tags

    async def test_cmd_admin_settag_empty_prefix_raises(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            msgs = await core.stormlist(f"{SVC_NAME}.admin.settag ''")
            self.stormIsInErr("non-empty tag prefix", msgs)

            msgs = await core.stormlist('$lib.print($lib.globals.get("slib:ipapi:tag:prefix"))')
            self.stormIsInPrint("rep.ipapi.infra", msgs)

    async def test_cmd_query_no_tags_when_disabled(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            msgs = await core.stormlist(f"{SVC_NAME}.admin.disabletag")
            self.stormHasNoErr(msgs)

            async def fake_query(ipaddr):
                return dict(SUCCESS_DATA), {}

            with mock.patch.object(svc, "_query", fake_query):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8 --yield")
                self.stormHasNoErr(msgs)

            nodes = await core.nodes("inet:ipv4=8.8.8.8")
            assert len(nodes[0].tags) == 0


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

            msgs = await core.stormlist(f"{SVC_NAME}.admin.disabletag", opts={"user": adminIden})
            self.stormHasNoErr(msgs)

            msgs = await core.stormlist('$lib.print($lib.globals.get("slib:ipapi:tag:enabled"))')
            self.stormIsInPrint("false", msgs)

    async def test_cmd_admin_enabletag_as_admin_user(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            adminIden, _userIden = await self._addPermUsers(core)

            await core.stormlist(f"{SVC_NAME}.admin.disabletag", opts={"user": adminIden})

            msgs = await core.stormlist(f"{SVC_NAME}.admin.enabletag", opts={"user": adminIden})
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


def fakeQuery(data: dict):
    """A fake IpApiSvc._query that always returns a copy of data, recording each IP."""

    calls = []

    async def fake_query(ipaddr):
        calls.append(ipaddr)
        return dict(data), {}

    fake_query.calls = calls
    return fake_query


class TestIpApiStormModel(s_tests.SynTest):
    """Test suite for how slib.ipapi.lib models ip-api.com results."""

    async def test_no_asn(self):
        """IPs with no ASN ("as", "asname", and "isp" are all "") must still be modeled."""

        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            data = shaped(**{"as": "", "asname": "", "isp": "", "org": ""})
            assert data["asnum"] is None

            with mock.patch.object(svc, "_query", fakeQuery(data)):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8 --yield")
                self.stormHasNoErr(msgs)
                self.stormHasNoWarnErr(msgs)

            nodes = await core.nodes("inet:ipv4=8.8.8.8")
            assert len(nodes) == 1
            assert nodes[0].get("asn") is None
            assert nodes[0].get("latlong") == (39.03, -77.5)
            assert len(await core.nodes("inet:asn")) == 0
            assert len(await core.nodes("ou:org")) == 0
            assert len(await core.nodes("geo:telem")) == 1

    async def test_asn_and_orgs(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            with mock.patch.object(svc, "_query", fakeQuery(SUCCESS_DATA)):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8")
                self.stormHasNoWarnErr(msgs)

            asns = await core.nodes("inet:asn")
            assert len(asns) == 1
            assert asns[0].ndef == ("inet:asn", 15169)
            assert asns[0].get("name") == "google"

            # The AS's org, from the name after the AS number. It's also the ISP.
            owners = await core.nodes("inet:asn=15169 -> ou:org")
            assert len(owners) == 1
            assert owners[0].get("name") == "google llc"
            assert owners[0].get("names") == ("google",)
            assert owners[0].get("orgtype") == "company.isp."

            # The IP's WHOIS org owns the IP.
            whois = await core.nodes("inet:ipv4=8.8.8.8 <(owns)- ou:org")
            assert len(whois) == 1
            assert whois[0].get("name") == "google public dns"
            assert whois[0].get("orgtype") is None

            nodes = await core.nodes("inet:ipv4=8.8.8.8")
            assert nodes[0].get("asn") == 15169
            assert nodes[0].get("dns:rev") == "dns.google"

    async def test_asn_owner_falls_back_to_isp(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            data = shaped(**{"as": "AS64512", "asname": "", "org": "", "reverse": ""})

            with mock.patch.object(svc, "_query", fakeQuery(data)):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8")
                self.stormHasNoWarnErr(msgs)

            asns = await core.nodes("inet:asn=64512")
            assert len(asns) == 1
            assert asns[0].get("name") is None

            owners = await core.nodes("inet:asn=64512 -> ou:org")
            assert owners[0].get("name") == "google llc"
            assert owners[0].get("names") is None
            assert len(await core.nodes("inet:ipv4=8.8.8.8 <(owns)- ou:org")) == 0
            assert (await core.nodes("inet:ipv4=8.8.8.8"))[0].get("dns:rev") is None

    async def test_asn_owner_not_isp(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            data = shaped(isp="Some Reseller")

            with mock.patch.object(svc, "_query", fakeQuery(data)):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8")
                self.stormHasNoWarnErr(msgs)

            owners = await core.nodes("inet:asn=15169 -> ou:org")
            assert owners[0].get("name") == "google llc"
            assert owners[0].get("orgtype") is None

    async def test_place_and_telem(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            # An existing pol:country is reused, not duplicated.
            await core.nodes("[ pol:country=* :iso2=us :name='united states' ]")

            with mock.patch.object(svc, "_query", fakeQuery(SUCCESS_DATA)):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8")
                self.stormHasNoWarnErr(msgs)

            places = await core.nodes("geo:place")
            assert len(places) == 1
            assert places[0].get("loc") == "us.va.ashburn"

            telems = await core.nodes("geo:telem")
            assert len(telems) == 1
            telem = telems[0]
            assert telem.get("node") == ("inet:ipv4", 134744072)
            assert telem.get("place") == places[0].ndef[1]
            assert telem.get("place:loc") == "us.va.ashburn"
            assert telem.get("place:country:code") == "us"
            first = telem.get("time")
            assert first is not None

            countries = await core.nodes("pol:country")
            assert len(countries) == 1
            assert telem.get("place:country") == countries[0].ndef[1]

            # Re-querying the same IP at the same place reuses the telem and keeps its :time.
            with mock.patch.object(svc, "_query", fakeQuery(SUCCESS_DATA)):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8")
                self.stormHasNoWarnErr(msgs)

            telems = await core.nodes("geo:telem")
            assert len(telems) == 1
            assert telems[0].get("time") == first

    async def test_telem_new_country(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            with mock.patch.object(svc, "_query", fakeQuery(SUCCESS_DATA)):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8")
                self.stormHasNoWarnErr(msgs)

            countries = await core.nodes("pol:country")
            assert len(countries) == 1
            assert countries[0].get("iso2") == "us"

    async def test_telem_bad_country_code(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            data = shaped(countryCode="USA")

            with mock.patch.object(svc, "_query", fakeQuery(data)):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8")
                self.stormHasNoWarnErr(msgs)

            telems = await core.nodes("geo:telem")
            assert len(telems) == 1
            assert telems[0].get("place:country") is None
            assert telems[0].get("place:country:code") is None
            assert len(await core.nodes("pol:country")) == 0

    async def test_source_edges(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            with mock.patch.object(svc, "_query", fakeQuery(SUCCESS_DATA)):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8")
                self.stormHasNoWarnErr(msgs)

            seen = await core.nodes(f"meta:source={SVC_GUID} -(seen)> *")
            forms = sorted(n.ndef[0] for n in seen)
            assert forms == ["geo:telem", "inet:asn", "inet:ipv4"]

    async def test_all_tags(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            data = shaped(hosting=False, proxy=True, mobile=True)

            with mock.patch.object(svc, "_query", fakeQuery(data)):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8")
                self.stormHasNoWarnErr(msgs)

            nodes = await core.nodes("inet:ipv4=8.8.8.8")
            assert "rep.ipapi.infra.proxy" in nodes[0].tags
            assert "rep.ipapi.infra.mobile" in nodes[0].tags
            assert "rep.ipapi.infra.hosting" not in nodes[0].tags

    async def test_modelresult_invalid_ip(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            q = f"$lib.import({SVC_NAME}.lib).modelResult(({{'query': 'nope'}}), (null))"
            msgs = await core.stormlist(f"yield {q}")
            self.stormIsInWarn("ip-api.com returned an invalid IP address: nope", msgs)
            assert len(await core.nodes("inet:ipv4")) == 0


class TestIpApiStormQuery(s_tests.SynTest):
    """Test suite for slib.ipapi.query's --query validation and batching of inbound nodes."""

    async def test_query_invalid_ip(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            fake = fakeQuery(SUCCESS_DATA)

            with mock.patch.object(svc, "_query", fake):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query not-an-ip --yield")
                self.stormHasNoErr(msgs)
                self.stormIsInWarn("was given an invalid IP address: not-an-ip", msgs)

            assert fake.calls == []
            assert len([m for m in msgs if m[0] == "node"]) == 0

    async def test_query_ignores_inbound_nodes(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            await core.nodes("[ inet:ipv4=1.1.1.1 inet:ipv4=2.2.2.2 ]")
            fake = fakeQuery(SUCCESS_DATA)

            with mock.patch.object(svc, "_query", fake):
                msgs = await core.stormlist(f"inet:ipv4 | {SVC_NAME}.query --query 8.8.8.8")
                self.stormHasNoWarnErr(msgs)

            assert fake.calls == ["8.8.8.8"]
            assert len([m for m in msgs if m[0] == "node"]) == 0

    async def test_batch_inbound_nodes(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
            await core.nodes("[ inet:ipv4=1.1.1.1 inet:ipv4=2.2.2.2 inet:ipv4=3.3.3.3 ]")
            calls = []

            async def fake_batch(ipaddrs):
                calls.append(list(ipaddrs))
                results = []
                for ip in ipaddrs:
                    if ip == "2.2.2.2":
                        results.append({"status": "fail", "message": "reserved range"})
                    else:
                        results.append(shaped(query=ip))
                return results, {}

            fake = fakeQuery(SUCCESS_DATA)
            with (
                mock.patch.object(svc, "_queryBatch", fake_batch),
                mock.patch.object(svc, "_query", fake),
            ):
                msgs = await core.stormlist(f"inet:ipv4 | {SVC_NAME}.query")
                self.stormHasNoErr(msgs)
                self.stormIsInWarn("error querying the IPAPI service for '2.2.2.2'", msgs)

            assert fake.calls == []
            assert len(calls) == 1
            assert sorted(calls[0]) == ips

            # Every inbound node comes back out, including the failed one.
            nodeMsgs = [m for m in msgs if m[0] == "node"]
            assert sorted(m[1][0][1] for m in nodeMsgs) == [16843009, 33686018, 50529027]

            assert len(await core.nodes("inet:ipv4=1.1.1.1 +:asn")) == 1
            assert len(await core.nodes("inet:ipv4=3.3.3.3 +:asn")) == 1
            assert len(await core.nodes("inet:ipv4=2.2.2.2 +:asn")) == 0

    async def test_batch_chunks(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            await core.nodes("for $i in $lib.range(150) { [ inet:ipv4=`10.0.0.{$i}` ] }")
            sizes = []

            async def fake_batch(ipaddrs):
                sizes.append(len(ipaddrs))
                return [shaped(query=ip) for ip in ipaddrs], {}

            with mock.patch.object(svc, "_queryBatch", fake_batch):
                msgs = await core.stormlist(f"inet:ipv4 | {SVC_NAME}.query")
                self.stormHasNoWarnErr(msgs)

            assert sizes == [100, 50]
            assert len([m for m in msgs if m[0] == "node"]) == 150

    async def test_batch_through_lib(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):

            async def fake_batch(ipaddrs):
                return [shaped(query=ip) for ip in ipaddrs], {}

            with mock.patch.object(svc, "_queryBatch", fake_batch):
                msgs = await core.stormlist(
                    f"$retn = $lib.import({SVC_NAME}.lib).queryBatch((1.1.1.1, 2.2.2.2)) "
                    "$lib.print(`{$retn.status} {$retn.data.1.data.query}`)"
                )
                self.stormIsInPrint("true 2.2.2.2", msgs)

    async def test_batch_service_error(self):
        """A status=False batch retn fails each node instead of erroring the command."""

        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            await core.nodes("[ inet:ipv4=1.1.1.1 inet:ipv4=2.2.2.2 ]")

            async def fake_queryips(ipaddrs):
                return {"status": False, "mesg": "batch broke", "data": None}

            with mock.patch.object(svc, "queryIps", fake_queryips):
                msgs = await core.stormlist(f"inet:ipv4 | {SVC_NAME}.query")
                self.stormHasNoErr(msgs)
                self.stormIsInWarn("batch broke", msgs)

            assert len([m for m in msgs if m[0] == "node"]) == 2


class TestIpApiStormTags(s_tests.SynTest):
    """Test suite for the slib.ipapi tag settings and their validation."""

    async def test_settag_invalid(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            msgs = await core.stormlist(f'{SVC_NAME}.admin.settag "not a..tag"')
            self.stormIsInErr("requires a valid tag prefix", msgs)

            msgs = await core.stormlist('$lib.print($lib.globals.get("slib:ipapi:tag:prefix"))')
            self.stormIsInPrint("rep.ipapi.infra", msgs)

    async def test_settag_normalizes(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            msgs = await core.stormlist(f"{SVC_NAME}.admin.settag Rep.MyOrg")
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("#rep.myorg.hosting", msgs)

            msgs = await core.stormlist('$lib.print($lib.globals.get("slib:ipapi:tag:prefix"))')
            self.stormIsInPrint("rep.myorg", msgs)

    async def test_enabletag_without_prefix_warns(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            await core.nodes('$lib.globals.pop("slib:ipapi:tag:prefix")')

            msgs = await core.stormlist(f"{SVC_NAME}.admin.enabletag")
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("no tag prefix is set", msgs)

            msgs = await core.stormlist(f"{SVC_NAME}.admin.settag rep.ipapi")
            msgs = await core.stormlist(f"{SVC_NAME}.admin.enabletag")
            self.stormHasNoWarnErr(msgs)

    async def test_getipapitag(self):
        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            q = f"$lib.print($lib.import({SVC_NAME}.privsep).getIpApiTag())"

            msgs = await core.stormlist(q)
            self.stormIsInPrint("rep.ipapi.infra", msgs)

            await core.nodes(f"{SVC_NAME}.admin.disabletag")
            msgs = await core.stormlist(q)
            self.stormIsInPrint("$lib.null", msgs)

            await core.nodes(f"{SVC_NAME}.admin.enabletag")
            await core.nodes('$lib.globals.pop("slib:ipapi:tag:prefix")')
            msgs = await core.stormlist(q)
            self.stormIsInErr("tag prefix is not set", msgs)

            await core.nodes('$lib.globals.set("slib:ipapi:tag:prefix", "bad..tag")')
            msgs = await core.stormlist(q)
            self.stormIsInErr('tag prefix "bad..tag" is not a valid tag', msgs)

    async def test_query_bad_tag_config_warns(self):
        """A bad tag setting only means untagged results, the query still runs."""

        async with self.getTestCoreProxSvc(IpApiSvc) as (core, prox, svc):
            await core.nodes('$lib.globals.pop("slib:ipapi:tag:prefix")')

            with mock.patch.object(svc, "_query", fakeQuery(SUCCESS_DATA)):
                msgs = await core.stormlist(f"{SVC_NAME}.query --query 8.8.8.8 --yield")
                self.stormHasNoErr(msgs)
                self.stormIsInWarn("Querying without tags", msgs)

            nodes = await core.nodes("inet:ipv4=8.8.8.8")
            assert len(nodes) == 1
            assert nodes[0].get("asn") == 15169
            assert len(nodes[0].tags) == 0

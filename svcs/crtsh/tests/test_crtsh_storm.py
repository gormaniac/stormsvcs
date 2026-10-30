"""Pytests for the slib.crtsh Storm package (commands, modules, modeling, and perms).

Every command option, inbound form, and error path is exercised against a FakeCrtshDb.
"""

import hashlib

import synapse.common as s_common
import synapse.tests.utils as s_tests

from crtshsvc.defs import SVC_GUID

from .fakecrtsh import CRL_URL, PKI, crtshSvc


SHA = {cid: PKI.sha256(cid) for cid in (1, 2, 3, 4, 9, 10, 11, 12, 13, 14, 15)}
CERT = {cid: f"crypto:x509:cert:sha256={sha}" for cid, sha in SHA.items()}
USER_PERM = ("slib", "crtsh", "user")


async def crtshIds(nodes) -> list[int]:
    return [(await n.getData("slib:crtsh"))["crtsh"]["id"] for n in nodes]


async def certIds(core, query, opts=None) -> list[int]:
    """The crt.sh IDs of the crypto:x509:cert nodes a query yields, in order."""

    nodes = await core.nodes(query, opts=opts)
    assert all(n.form.name == "crypto:x509:cert" for n in nodes)
    return [(await n.getData("slib:crtsh"))["crtsh"]["id"] for n in nodes]


class TestCrtshStormCert(s_tests.SynTest):

    async def test_model(self):
        async with crtshSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.crtsh.cert 10 --yield")
            self.stormHasNoErr(msgs)
            self.stormHasNoWarnErr(msgs)

            leaf = (await core.nodes(CERT[10]))[0]
            details = await leaf.getData("slib:crtsh")
            assert details["crtsh"]["id"] == 10
            assert details["crtsh"]["issuer"]["name"] == "C=US, O=Test Trust, CN=Test Issuing CA 1"
            assert len(details["scts"]) == 2

            assert leaf.get("sha1") == hashlib.sha1(PKI.row(10)["der"]).hexdigest()
            assert leaf.get("md5") == hashlib.md5(PKI.row(10)["der"]).hexdigest()
            assert leaf.get("file") == f"sha256:{SHA[10]}"
            assert int(leaf.get("serial"), 16) == 0x5a0b1c2d3e4f  # Synapse zero pads serials.
            assert leaf.get("version") == 2
            assert leaf.get("subject") == "CN=www.vertex.link,OU=Engineering,O=The Vertex Project,C=US"
            assert leaf.get("issuer") == "CN=Test Issuing CA 1,O=Test Trust,C=US"
            assert leaf.get("validity:notbefore") == details["notbefore"]
            assert leaf.get("validity:notafter") == details["notafter"]
            assert leaf.get("algo") == "1.2.840.10045.4.3.2"
            assert leaf.get("signature") == details["signature"]
            assert leaf.get("selfsigned") == 0
            assert leaf.get("rsa:key") is None
            assert ("dns", "*.vertex.link") in leaf.get("ext:sans")
            assert ("ip", "2001:db8::1") in leaf.get("ext:sans")
            assert leaf.get("crl:urls") == (CRL_URL,)
            assert leaf.get("ext:crls") == (("uri", CRL_URL),)
            assert leaf.get("identities:fqdns") == ("vertex.link", "www.vertex.link")
            assert leaf.get("identities:emails") == ("visi@vertex.link",)
            assert leaf.get("identities:ipv4s") == (0x01020304,)
            assert len(leaf.get("identities:ipv6s")) == 1
            assert leaf.get("identities:urls") == ("https://vertex.link/",)
            # .seen covers its CT log entries.
            first, last = details["crtsh"]["logged"]
            assert leaf.get(".seen") == (first, last + 1)
            assert not leaf.tags

            assert len(await core.nodes(f"meta:source={SVC_GUID} -(seen)> crypto:x509:cert")) == 1
            keys = await core.nodes(f"{CERT[10]} -(refs)> crypto:key")
            assert len(keys) == 1
            assert keys[0].get("public:sha256") == details["pubkey"]["sha256"]
            assert keys[0].get("public:sha1") == details["pubkey"]["sha1"]
            assert keys[0].get("public") == details["pubkey"]["spki"]
            assert keys[0].get("algorithm") == "ec"
            assert len(await core.nodes(f"meta:source={SVC_GUID} -(seen)> crypto:key")) == 1

            # Running it again doesn't duplicate anything.
            await core.nodes("slib.crtsh.cert 10")
            assert len(await core.nodes("crypto:x509:cert")) == 1
            assert len(await core.nodes("crypto:key")) == 1

    async def test_model_tags(self):
        async with crtshSvc(self) as (core, svc, fake):
            await core.nodes("slib.crtsh.cert 1 2 9 11 12")

            root = (await core.nodes(CERT[1]))[0]
            assert {"rep.crtsh.ca", "rep.crtsh.root"} <= set(root.tags)
            assert root.get("selfsigned") == 1
            assert root.get("rsa:key")[1] == 65537

            inter = (await core.nodes(CERT[2]))[0]
            assert "rep.crtsh.ca" in inter.tags and "rep.crtsh.root" not in inter.tags

            assert "rep.crtsh.precert" in (await core.nodes(CERT[9]))[0].tags

            revoked = (await core.nodes(CERT[11]))[0]
            assert "rep.crtsh.revoked" in revoked.tags
            nodes = await core.nodes(f"crypto:x509:revoked:cert={revoked.ndef[1]} :crl -> crypto:x509:crl")
            assert len(nodes) == 1 and nodes[0].get("url") == CRL_URL
            assert len(await core.nodes(f"meta:source={SVC_GUID} -(seen)> crypto:x509:revoked")) == 1

            expired = (await core.nodes(CERT[12]))[0]
            assert not expired.tags and expired.get(".seen") is None

            # Tags can be renamed or turned off.
            await core.nodes("slib.crtsh.admin.tags --prefix my.crtsh")
            await core.nodes("slib.crtsh.cert 4")
            assert "my.crtsh.ca" in (await core.nodes(CERT[4]))[0].tags
            await core.nodes("slib.crtsh.admin.tags --disable")
            await core.nodes("slib.crtsh.cert 3")
            assert not (await core.nodes(CERT[3]))[0].tags

    async def test_model_unparsed(self):
        async with crtshSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.crtsh.cert 13 --chain")
            self.stormHasNoWarnErr(msgs)
            junk = (await core.nodes(CERT[13]))[0]
            assert junk.get("sha1") and junk.get("file")
            assert junk.get("subject") is None and junk.get("serial") is None
            assert (await junk.getData("slib:crtsh"))["error"]
            # Unparsed certificates have no chain to build.
            assert fake.called("caCerts") == 0

    async def test_model_edges(self):
        async with crtshSvc(self) as (core, svc, fake):
            # A key cryptography couldn't load has no hashes to deconflict on.
            msgs = await core.stormlist("$lib.print($lib.import(slib.crtsh.model).keyNode(({})))")
            self.stormIsInPrint("null", msgs)

            # A revoked certificate without a CRL distribution point is on its issuer's CRL.
            q = '''$model = $lib.import(slib.crtsh.model)
                $crl = $model.crlNode(({"crls": [], "crtsh": {"issuer": {"id": 2}}}))
                $lib.print($crl.value())'''
            msgs = await core.stormlist(q)
            self.stormHasNoErr(msgs)
            self.stormIsInPrint(s_common.guid(("slib.crtsh", "crl", 2)), msgs)

    async def test_cert(self):
        async with crtshSvc(self) as (core, svc, fake):
            # By crt.sh ID, SHA-256, and SHA-1, newest first.
            sha1 = hashlib.sha1(PKI.row(2)["der"]).hexdigest()
            assert await certIds(core, f"slib.crtsh.cert 10 {SHA[1]} {sha1} --yield") == [10, 2, 1]
            # Any identifier type.
            # crt.sh applies the limit, the precert and cert tie so either may be returned.
            assert len(await certIds(core, "slib.crtsh.cert 5a0b1c2d3e4f --type serial --limit 1 --yield")) == 1
            assert fake.last("certs") == {"kind": "serial", "valus": [b"\x5a\x0b\x1c\x2d\x3e\x4f"], "limit": 1}

            msgs = await core.stormlist("slib.crtsh.cert 999")
            self.stormIsInWarn("crt.sh has no certificates for: 999", msgs)
            msgs = await core.stormlist("slib.crtsh.cert nope")
            self.stormIsInWarn("slib.crtsh: Lookup failed: Unable to tell what kind of identifier nope", msgs)

            # Inbound nodes pass through, unless --yield.
            await core.nodes(f"[ hash:sha256={SHA[2]} hash:sha1={sha1} inet:fqdn=vertex.link ]")
            msgs = await core.stormlist(f"hash:sha256={SHA[2]} hash:sha1={sha1} inet:fqdn=vertex.link | slib.crtsh.cert")
            self.stormIsInWarn("Unable to look up inet:fqdn vertex.link", msgs)
            assert [m[1][0][0] for m in msgs if m[0] == "node"] == ["hash:sha256", "hash:sha1"]
            assert await certIds(core, f"hash:sha256={SHA[2]} | slib.crtsh.cert --yield") == [2]
            assert await certIds(core, f"hash:sha1={sha1} | slib.crtsh.cert --yield") == [2]

            # crypto:x509:cert nodes are looked up by :sha256, or :sha1.
            assert await certIds(core, f"{CERT[2]} | slib.crtsh.cert --yield") == [2]
            await core.nodes(f"[ crypto:x509:cert=* :sha1={hashlib.sha1(PKI.row(4)['der']).hexdigest()} ]")
            assert await certIds(core, "crypto:x509:cert:sha1 -:sha256 | slib.crtsh.cert --yield") == [4]
            await core.nodes("[ crypto:x509:cert=* :serial=00 ]")
            msgs = await core.stormlist("crypto:x509:cert:serial=00 | slib.crtsh.cert")
            self.stormIsInWarn("it needs a SHA-256 or SHA-1", msgs)

            # --chain models the chain and sets :issuer:cert.
            await core.nodes("slib.crtsh.cert 10 --chain")
            nodes = await core.nodes(f"{CERT[10]} :issuer:cert -> crypto:x509:cert")
            assert await crtshIds(nodes) == [2]

    async def test_cert_failure(self):
        async with crtshSvc(self) as (core, svc, fake):
            fake.fail = "crt.sh is down"
            msgs = await core.stormlist("slib.crtsh.cert 10")
            self.stormIsInWarn("slib.crtsh: Lookup failed: crt.sh is down", msgs)
            assert not await core.nodes("crypto:x509:cert")


class TestCrtshStormSearch(s_tests.SynTest):

    async def test_search(self):
        async with crtshSvc(self) as (core, svc, fake):
            assert await certIds(core, "slib.crtsh.search --dns vertex.link") == [10, 9, 15, 11, 12]
            assert await certIds(core, "slib.crtsh.search --dns www.vertex.link --exact --no-precerts") == [10, 15]
            assert await certIds(core, "slib.crtsh.search --dns vertex.link --valid --limit 2") == [10, 9]
            assert await certIds(core, "slib.crtsh.search --cn old --org vertex --ou '' ") == [11]
            assert await certIds(core, "slib.crtsh.search --ou Engineering") == [10, 9, 15]
            assert await certIds(core, "slib.crtsh.search --email visi") == [10, 9]
            assert await certIds(core, "slib.crtsh.search --ip 1.2.3.4") == [10, 9]
            assert await certIds(core, "slib.crtsh.search --uri vertex.link/") == [10, 9]
            assert await certIds(core, "slib.crtsh.search --subject 'O=Example Inc'") == [14]
            assert await certIds(core, "slib.crtsh.search --identity shop") == [14]

            # Issuers, by name or crt.sh CA ID.
            assert await certIds(core, "slib.crtsh.search --issuer 'Root R1'") == [2, 1]
            assert await certIds(core, "slib.crtsh.search --caid 1 --caid 3") == [4, 2, 3, 1]
            assert await certIds(core, "slib.crtsh.search --dns vertex.link --caid 1") == []

            # Times are anything Synapse can parse.
            await core.nodes("slib.crtsh.search --dns vertex.link --since 2000-01-01 --until '+1 day'")
            call = fake.last("certsByIdentity")
            assert call["since"] == 946684800000 and call["until"] > call["since"]
            await core.nodes("slib.crtsh.search --dns vertex.link --since ''")
            assert fake.last("certsByIdentity")["since"] is None

            # --chain models each result's chain.
            await core.nodes("slib.crtsh.search --dns old.vertex.link --chain")
            assert await crtshIds(await core.nodes(f"{CERT[11]} :issuer:cert -> *")) == [2]

    async def test_search_inbound(self):
        async with crtshSvc(self) as (core, svc, fake):
            q = """[ inet:fqdn=old.vertex.link inet:email=visi@vertex.link inet:ipv4=1.2.3.4
                     inet:ipv6=2001:db8::1 inet:url=https://vertex.link/ ou:name="example inc"
                     (ou:org=* :name="the vertex project") (ou:org=*) inet:asn=1 ]"""
            await core.nodes(q)

            assert await certIds(core, "inet:fqdn=old.vertex.link | slib.crtsh.search") == [11]
            assert await certIds(core, "inet:email | slib.crtsh.search") == [10, 9]
            assert await certIds(core, "inet:ipv4 | slib.crtsh.search") == [10, 9]
            assert await certIds(core, "inet:ipv6 | slib.crtsh.search") == [10, 9]
            assert await certIds(core, "inet:url | slib.crtsh.search") == [10, 9]
            assert await certIds(core, "ou:name='example inc' | slib.crtsh.search") == [14]
            assert await certIds(core, "ou:org:name | slib.crtsh.search --valid --no-precerts") == [10, 11]

            msgs = await core.stormlist("ou:org -:name inet:asn | slib.crtsh.search")
            self.stormIsInWarn("Unable to search for ou:org", msgs)
            self.stormIsInWarn("Unable to search for inet:asn 1", msgs)
            assert not [m for m in msgs if m[0] == "node"]

            # An unsupported node doesn't stop the others.
            msgs = await core.stormlist("inet:asn=1 inet:fqdn=old.vertex.link | slib.crtsh.search")
            self.stormIsInWarn("Unable to search for inet:asn 1", msgs)
            self.stormHasNoErr(msgs)
            assert len([m for m in msgs if m[0] == "node"]) == 1

            # Options ignore inbound nodes.
            assert await certIds(core, "inet:fqdn | slib.crtsh.search --identity shop") == [14]

    async def test_search_failure(self):
        async with crtshSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.crtsh.search --ip nope")
            self.stormIsInWarn("slib.crtsh: Search failed: Invalid IP address: nope", msgs)
            assert not [m for m in msgs if m[0] == "node"]


class TestCrtshStormPivot(s_tests.SynTest):

    async def test_pivot(self):
        async with crtshSvc(self) as (core, svc, fake):
            await core.nodes("slib.crtsh.cert 4 10 13")

            assert await certIds(core, f"{CERT[4]} | slib.crtsh.pivot --by issued --limit 1") == [14]
            assert await certIds(core, f"{CERT[10]} | slib.crtsh.pivot --by siblings --valid --no-precerts") == [14, 11]
            assert await certIds(core, f"{CERT[10]} | slib.crtsh.pivot --by key") == [9, 15]
            assert await certIds(core, f"{CERT[10]} | slib.crtsh.pivot --by subject") == [9, 15]
            assert await certIds(core, f"{CERT[10]} | slib.crtsh.pivot --by serial") == [9]
            assert await certIds(core, f"{CERT[10]} | slib.crtsh.pivot --by ski --chain") == [9, 15]
            assert await crtshIds(await core.nodes(f"{CERT[15]} :issuer:cert -> *")) == [2]

            # Without inbound nodes.
            assert await certIds(core, "slib.crtsh.pivot --cert 10 --cert 2 --by serial") == [9]

            msgs = await core.stormlist(f"{CERT[13]} | slib.crtsh.pivot --by key")
            self.stormIsInWarn("Pivot by key from", msgs)
            self.stormIsInWarn("Unable to pivot by key: Unable to parse certificate", msgs)

            await core.nodes("[ inet:fqdn=vertex.link ]")
            await core.nodes("[ crypto:x509:cert=* :serial=00 ]")
            msgs = await core.stormlist("inet:fqdn=vertex.link crypto:x509:cert:serial=00 | slib.crtsh.pivot --by key")
            self.stormIsInWarn("Unable to pivot from inet:fqdn vertex.link", msgs)
            self.stormIsInWarn("Unable to pivot from crypto:x509:cert", msgs)


class TestCrtshStormChain(s_tests.SynTest):

    async def test_chain(self):
        async with crtshSvc(self) as (core, svc, fake):
            await core.nodes("slib.crtsh.cert 10")

            msgs = await core.stormlist(f"{CERT[10]} | slib.crtsh.chain --print")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("Chain 1:", msgs)
            self.stormIsInPrint("    crt.sh ID 2: CN=Test Issuing CA 1,O=Test Trust,C=US", msgs)
            self.stormIsInPrint("Chain 2:", msgs)
            self.stormIsInPrint("    crt.sh ID 3: CN=Test Root E2,O=Test Trust,C=US", msgs)
            nodes = [m[1] for m in msgs if m[0] == "node"]
            assert [n[1]["props"]["sha256"] for n in nodes] == [SHA[c] for c in (10, 2, 4, 1, 3)]

            # :issuer:cert is the preferred parent at every level.
            assert await crtshIds(await core.nodes(f"{CERT[10]} :issuer:cert -> *")) == [2]
            assert await crtshIds(await core.nodes(f"{CERT[2]} :issuer:cert -> *")) == [1]
            assert await crtshIds(await core.nodes(f"{CERT[4]} :issuer:cert -> *")) == [3]
            assert await core.nodes(f"{CERT[1]} :issuer:cert -> *") == []
            assert {"rep.crtsh.root", "rep.crtsh.ca"} <= set((await core.nodes(CERT[3]))[0].tags)

            # Without inbound nodes, and no printing by default.
            msgs = await core.stormlist("slib.crtsh.chain --cert 2")
            assert not [m for m in msgs if m[0] == "print"]
            assert len([m for m in msgs if m[0] == "node"]) == 2

            msgs = await core.stormlist("slib.crtsh.chain --cert 999")
            self.stormIsInWarn("slib.crtsh: Building the chain of 999 failed: crt.sh has no certificate", msgs)

            await core.nodes("[ inet:fqdn=vertex.link ]")
            msgs = await core.stormlist("inet:fqdn=vertex.link | slib.crtsh.chain")
            self.stormIsInWarn("Unable to build the chain of inet:fqdn vertex.link", msgs)


class TestCrtshStormCa(s_tests.SynTest):

    async def test_ca(self):
        async with crtshSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.crtsh.ca Test")
            self.stormIsInPrint("C=US, O=Test Trust, CN=Test Issuing CA 1", msgs)
            assert not [m for m in msgs if m[0] == "node"]

            assert await certIds(core, "slib.crtsh.ca --id 2 --id 1 --certs") == [1, 2, 4]
            assert await certIds(core, "slib.crtsh.ca 'Root E2' --issued --chain") == [4, 3]
            assert await crtshIds(await core.nodes(f"{CERT[4]} :issuer:cert -> *")) == [3]
            ids = await certIds(core, "slib.crtsh.ca --id 2 --issued --valid --no-precerts --limit 2 "
                                      "--since 2000-01-01 --until '+1 day'")
            assert ids == [14, 10]
            assert fake.last("certsByIssuer")["since"] == 946684800000

            msgs = await core.stormlist("slib.crtsh.ca nope --issued")
            self.stormIsInPrint("slib.crtsh.ca: No matching CAs.", msgs)
            assert fake.called("certsByIssuer") == 2

            msgs = await core.stormlist("slib.crtsh.ca")
            self.stormIsInErr("slib.crtsh.ca requires a CA name or --id.", msgs)

            fake.fail = "crt.sh is down"
            msgs = await core.stormlist("slib.crtsh.ca Test")
            self.stormIsInWarn("slib.crtsh: Finding CAs failed: crt.sh is down", msgs)
            self.stormIsInPrint("No matching CAs.", msgs)

    async def test_lib(self):
        async with crtshSvc(self) as (core, svc, fake):
            # Errors from generators end them with a warning.
            q = "for $n in $lib.import(slib.crtsh.lib).issued() { $lib.print($n) }"
            msgs = await core.stormlist(q)
            self.stormIsInWarn("Listing issued certificates failed: A CA ID or certificate is required.", msgs)

            q = "for $n in $lib.import(slib.crtsh.lib).issued(valu=10) { $lib.print($n) }"
            msgs = await core.stormlist(q)
            self.stormIsInWarn("may not be a CA certificate", msgs)

            q = """for $n in $lib.import(slib.crtsh.lib).chain((10)) { $lib.print($n.repr()) }
                   for $n in $lib.import(slib.crtsh.lib).chain((999)) { $lib.print($n.repr()) }"""
            msgs = await core.stormlist(q)
            assert len([m for m in msgs if m[0] == "print"]) == 5
            self.stormIsInWarn("Building the chain of 999 failed", msgs)


class TestCrtshStormAdmin(s_tests.SynTest):

    async def test_tags(self):
        async with crtshSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.crtsh.admin.tags")
            self.stormIsInPrint("slib.crtsh tags: enabled=true prefix=rep.crtsh", msgs)
            msgs = await core.stormlist("slib.crtsh.admin.tags --prefix my.tags --disable")
            self.stormIsInPrint("enabled=false prefix=my.tags", msgs)
            msgs = await core.stormlist("slib.crtsh.admin.tags --enable")
            self.stormIsInPrint("enabled=true prefix=my.tags", msgs)
            msgs = await core.stormlist("slib.crtsh.admin.tags --enable --disable")
            self.stormIsInErr("Use --enable or --disable, not both.", msgs)

    async def test_sql(self):
        async with crtshSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.crtsh.admin.sql 'SELECT id FROM ca WHERE id = $1' --args ((1),)")
            self.stormIsInPrint("1 rows", msgs)
            self.stormIsInPrint('"key": "0102"', msgs)
            assert fake.last("raw")["sql"] == "SELECT id FROM ca WHERE id = $1"
            assert list(fake.last("raw")["args"]) == [1]

            msgs = await core.stormlist("slib.crtsh.admin.sql 'SELECT * FROM nope'")
            self.stormIsInWarn('slib.crtsh: Query failed: relation "nope" does not exist', msgs)


class TestCrtshStormPerms(s_tests.SynTest):

    async def _addUser(self, core, name, *perms):
        user = await core.auth.addUser(name)
        for perm in perms:
            await user.addRule((True, perm))
        return user.iden

    async def test_perms(self):
        async with crtshSvc(self) as (core, svc, fake):
            # A user doesn't need service.get, the privileged modules handle that.
            user = await self._addUser(core, "user", ("node",), USER_PERM)
            noperms = await self._addUser(core, "noperms", ("node",))
            admin = await self._addUser(core, "admin", ("slib", "crtsh", "admin"))

            for query in ("slib.crtsh.cert 10 --chain", "slib.crtsh.search --dns vertex.link",
                          "slib.crtsh.cert 10 | slib.crtsh.pivot --by key",
                          "slib.crtsh.chain --cert 10", "slib.crtsh.ca Test --certs"):
                msgs = await core.stormlist(query, opts={"user": user})
                self.stormHasNoWarnErr(msgs)
                msgs = await core.stormlist(query, opts={"user": noperms})
                self.stormIsInErr("requires permission: slib.crtsh.user", msgs)

            for query in ("slib.crtsh.admin.tags", "slib.crtsh.admin.sql 'SELECT 1'"):
                msgs = await core.stormlist(query, opts={"user": user})
                self.stormIsInErr("requires permission", msgs)
                msgs = await core.stormlist(query, opts={"user": admin})
                self.stormHasNoWarnErr(msgs)

            msgs = await core.stormlist('$lib.service.get("slib.crtsh").get(10)', opts={"user": user})
            self.stormIsInErr("must have permission service.get", msgs)

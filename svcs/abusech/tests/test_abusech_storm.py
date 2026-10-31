"""Pytests for the slib.abusech Storm package (commands, modules, modeling, and perms)."""

import json
import pathlib
import tomllib

import synapse.tests.utils as s_tests

from abusechsvc import __version__
from abusechsvc.defs import EXT_PROPS, PKGDEFS, SOURCES, SVC_NAME

from . import fakeabusech as fd
from .fakeabusech import abusechSvc


CMDS = tuple(cmd["name"] for cmd in PKGDEFS[0]["commands"])
MODS = tuple(mod["name"] for mod in PKGDEFS[0]["modules"])

SHA256 = fd.SHA256
FILE = f"file:bytes=sha256:{SHA256}"


def src(plat):
    """The meta:source guid of an abuse.ch platform."""
    return SOURCES[plat][0]


async def nodeset(core, query):
    """Return the set of (form, repr) for the nodes a query lifts."""
    return {(node.form.name, node.repr()) for node in await core.nodes(query)}


async def count(core, query):
    return len(await core.nodes(query))


class TestStormPkg(s_tests.SynTest):
    """The package loads and the service registers with the Cortex."""

    def test_versions_match(self):
        pyproject = pathlib.Path(__file__).parent.parent / "pyproject.toml"
        with pyproject.open("rb") as fd_:
            assert tomllib.load(fd_)["project"]["version"] == __version__
        assert PKGDEFS[0]["version"] == __version__

    async def test_pkg(self):
        assert len(CMDS) == 32

        async with abusechSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("service.list")
            self.stormIsInPrint(f"true (svc) ({SVC_NAME} @ {__version__})", msgs)

            for cmd in CMDS:
                assert cmd in core.stormcmds, cmd

            for mod in MODS:
                msgs = await core.stormlist(f"$mod = $lib.import({mod})")
                self.stormHasNoErr(msgs)

            # The service add event creates a meta:source per platform, the ext props, and the tag settings.
            for plat, (guid, name, url) in SOURCES.items():
                nodes = await core.nodes(f"meta:source={guid}")
                assert len(nodes) == 1 and nodes[0].get("name") == name.lower(), plat
                assert nodes[0].get("type") == f"slib.abusech.{plat}"
            for prop in EXT_PROPS:
                assert core.model.prop(f"file:bytes:{prop}") is not None, prop

            msgs = await core.stormlist("slib.abusech.admin.tags")
            self.stormIsInPrint("enabled=true prefix=rep.abusech", msgs)


class TestStormBazaar(s_tests.SynTest):

    async def test_lookup(self):
        async with abusechSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(f"slib.abusech.bazaar.lookup --hash {SHA256} --yield")
            self.stormHasNoErr(msgs)
            assert [m[1][0] for m in msgs if m[0] == "node"] == [("file:bytes", f"sha256:{SHA256}")]

            nodes = await core.nodes(FILE)
            assert len(nodes) == 1
            f = nodes[0]
            assert f.get("md5") == fd.MD5 and f.get("sha1") == fd.SHA1 and f.get("size") == 1234567
            assert f.get("name") == "invoice.exe" and f.get("mime") == "application/x-dosexec"
            assert f.get("mime:pe:imphash") == "f34d5f2d4577ed6d9ceec516c1f5a744"
            assert f.get("ssdeeps") == ("24576:abcdefg:hijklmn",)
            assert f.get("_sha3_384") == fd.SHA3 and f.get("_tlsh") == "t1a2b3c4d5e6f7"
            assert f.get("_dhash_icon") == "e8e8b2b2b2b2e8e8"
            assert f.get(".seen")[0] == 1790856000000
            for tag in ("agenttesla", "exe", "guloader", "type.exe", "delivery.email_attachment", "origin.de"):
                assert f"rep.abusech.bazaar.{tag}" in f.tags, tag
            # Tags carry the time abuse.ch saw the sample.
            assert f.tags["rep.abusech.bazaar.agenttesla"] == (1790856000000, 1790929800000)

            assert await count(core, f"meta:source={src('bazaar')} -(seen)> file:bytes") == 3

            # The malware family.
            nodes = await core.nodes("risk:tool:software:tag=rep.abusech.bazaar.agenttesla")
            assert len(nodes) == 1
            assert nodes[0].get("soft:name") == "agenttesla" and nodes[0].get("reporter:name") == "abuse.ch"

            # The reporter.
            nodes = await core.nodes("inet:service:account:user=abuse_ch -(seen)> file:bytes")
            assert [n.ndef[1] for n in nodes] == [f"sha256:{SHA256}"]
            assert await count(core, "inet:service:account -> inet:service:platform +:name=malwarebazaar") == 1

            # ClamAV and vendor results.
            scans = {n.get("scanner:name"): n for n in await core.nodes(f"{FILE} -> it:av:scan:result:target:file")}
            assert set(scans) == {"clamav", "any.run", "triage", "reversinglabs", "unpacme", "yoroi_yomi", "spamhaus_hbl",
                                  "filescan-io", "cape", "cert-pl_mwdb", "kaspersky", "docguard"}
            assert scans["yoroi_yomi"].get("verdict") == 10 and scans["yoroi_yomi"].get("signame") is None
            assert scans["filescan-io"].get("verdict") == 10
            assert scans["cape"].get("signame") == "agenttesla"
            assert scans["clamav"].get("signame") == "win.trojan.agenttesla-1234"
            assert scans["clamav"].get("verdict") == 40
            assert scans["reversinglabs"].get("multi:count") == 50
            assert scans["reversinglabs"].get("multi:count:malicious") == 40
            assert scans["any.run"].get("time") == 1790856300000
            assert "trojan" in scans["any.run"].get("categories")

            # Report links, and the file UnpacMe unpacked.
            assert await nodeset(core, f"{FILE} <(refs)- inet:url") == {
                ("inet:url", "https://app.any.run/tasks/1234"),
                ("inet:url", "https://tria.ge/reports/1234/"),
                ("inet:url", "https://www.unpac.me/results/1234/"),
                ("inet:url", "https://www.spamhaus.org/hbl/"),
                ("inet:url", "https://www.filescan.io/uploads/1/reports/2/overview"),
                ("inet:url", "https://www.capesandbox.com/analysis/96328/"),
                ("inet:url", "https://mwdb.cert.pl/sample/x/"),
                ("inet:url", "https://opentip.kaspersky.com/x/results"),
                ("inet:url", "https://twitter.com/abuse_ch/status/1"),
            }

            # URLs DocGuard found in the file.
            assert await nodeset(core, f"{FILE} -(refs)> inet:url") == {
                ("inet:url", "http://docguard.example.net/payload.bin")}

            # Triage's extracted C2s.
            cfg = (await core.nodes(f"it:sec:c2:config:file=sha256:{SHA256}"))[0]
            assert cfg.get("family") == "agenttesla"
            assert set(cfg.get("servers")) == {"tcp://c2.example.org:587", "tcp://9.8.7.6:2929"}
            assert await nodeset(core, f"{FILE} -(refs)> * +#rep.abusech.bazaar.c2") == {
                ("inet:fqdn", "c2.example.org"), ("inet:server", "tcp://9.8.7.6:2929")}
            assert "rep.abusech.bazaar.agenttesla" in (await core.nodes("inet:fqdn=c2.example.org"))[0].tags

            # File format, architecture, Magika type, and OLE flags; TrID and OLE details as notes.
            for tag in ("magika.pebin", "format.pe", "arch.amd64", "ole.encrypted", "ole.vba_macros"):
                assert f"rep.abusech.bazaar.{tag}" in f.tags or await count(core, f"{FILE} +#rep.abusech.bazaar.{tag}"), tag
            nodes = await core.nodes(f"file:subfile:parent=sha256:{SHA256} :child -> file:bytes")
            assert [n.get("sha256") for n in nodes] == [fd.UNPACKED]
            assert "rep.abusech.bazaar.agenttesla" in nodes[0].tags

            # The sample's dropper.
            nodes = await core.nodes(f"{FILE} <(refs)- file:bytes")
            assert [n.get("sha256") for n in nodes] == [fd.DROPPER]

            # YARA matches.
            nodes = await core.nodes(f"it:app:yara:match:file=sha256:{SHA256} -> it:app:yara:rule")
            assert len(nodes) == 1
            assert nodes[0].get("name") == "AgentTesla_Strings"
            assert nodes[0].get("url") == "https://bazaar.abuse.ch/browse/signature/AgentTesla/"
            assert await count(core, "it:app:yara:rule:name=AgentTesla_Strings :author -> ps:contact +:name=abuse.ch") == 1
            assert await count(core, "it:app:yara:rule <(about)- meta:note +:text='Detects AgentTesla'") == 1

            # The code signing certificate.
            nodes = await core.nodes(f"crypto:x509:signedfile:file=sha256:{SHA256} -> crypto:x509:cert")
            assert len(nodes) == 1
            cert = nodes[0]
            assert cert.get("sha256") == "b" * 64 and cert.get("serial").endswith("c8f5d1e1a2b3c4d5")
            assert cert.get("subject") == "Evil Corp LLC" and cert.get("issuer") == "Sectigo RSA Code Signing CA"
            assert cert.get("validity:notbefore") == 1767225600000
            assert "rep.abusech.bazaar.cscb" in cert.tags
            assert await count(core, "crypto:x509:cert <(about)- meta:note +:text='Used to sign AgentTesla'") == 1

            # Comments and other file information.
            notes = {n.get("text"): n for n in await core.nodes(f"{FILE} <(about)- meta:note")}
            assert set(notes) == {"Delivered via a fake invoice.", "Confirmed AgentTesla.",
                                  "comment: Seen in a phishing campaign",
                                  "trid: 44.6% (.EXE) Win64 Executable (generic) (6522/11/2)",
                                  "ole: format: MS Excel 97-2003, container: OLE, application: Microsoft Excel, maldoc score: 9",
                                  "olevba Suspicious: Hex Strings - Hex-encoded strings were detected"}
            assert notes["Confirmed AgentTesla."].get("type") == "slib.abusech.bazaar.comment."
            assert notes["Confirmed AgentTesla."].get("created") == 1790859600000
            assert await count(core, "meta:note:text='Confirmed AgentTesla.' :author -> ps:contact +:name=analyst") == 1

            # Lookups are idempotent.
            await core.nodes(f"slib.abusech.bazaar.lookup --hash {SHA256}")
            # 11 vendors (UnpacMe twice, for the sample and its unpacked file) and ClamAV.
            assert await count(core, "it:av:scan:result") == 13
            assert await count(core, "meta:note") == 8
            assert await count(core, "it:sec:c2:config") == 1
            assert await count(core, "risk:tool:software") == 1
            assert await count(core, "crypto:x509:cert") == 1

    async def test_lookup_pipeline(self):
        async with abusechSvc(self) as (core, svc, fake):
            await core.nodes(f"[ hash:md5={fd.MD5} (file:bytes=* :name=nohash) inet:fqdn=vertex.link ]")
            msgs = await core.stormlist(f"hash:md5={fd.MD5} file:bytes:name=nohash inet:fqdn=vertex.link | slib.abusech.bazaar.lookup")
            self.stormIsInWarn("has no hash to look up", msgs)
            assert sorted(m[1][0][0] for m in msgs if m[0] == "node") == ["file:bytes", "hash:md5", "inet:fqdn"]
            assert fake.last("/bazaar")["form"]["hash"] == fd.MD5

            msgs = await core.stormlist(f"slib.abusech.bazaar.lookup --hash {'a' * 64}")
            self.stormIsInPrint("is not in MalwareBazaar", msgs)
            msgs = await core.stormlist("slib.abusech.bazaar.lookup --hash nothex")
            self.stormIsInWarn("Not an MD5, SHA1, SHA256, or SHA3-384 hash", msgs)

            nodes = await core.nodes(f"hash:md5={fd.MD5} | slib.abusech.bazaar.lookup --yield")
            assert [n.get("sha256") for n in nodes] == [SHA256]

    async def test_search(self):
        async with abusechSvc(self) as (core, svc, fake):
            nodes = await core.nodes("slib.abusech.bazaar.search signature AgentTesla --limit 5")
            assert {n.get("sha256") for n in nodes} == {SHA256, "f" * 64}
            assert fake.last("/bazaar")["form"] == {"query": "get_siginfo", "signature": "AgentTesla", "limit": "5"}
            # Anonymous submissions don't model a reporter.
            assert await count(core, "inet:service:account") == 1
            assert await count(core, f"file:bytes={'f' * 64} +#rep.abusech.bazaar.dll") == 1

            nodes = await core.nodes("slib.abusech.bazaar.search recent")
            assert len(nodes) == 2
            assert fake.last("/bazaar")["form"] == {"query": "get_recent", "selector": "time"}
            await core.nodes("slib.abusech.bazaar.search recent 100")
            assert fake.last("/bazaar")["form"]["selector"] == "100"

            msgs = await core.stormlist("slib.abusech.bazaar.search tag nothing")
            self.stormIsInPrint("Found 0 samples", msgs)
            msgs = await core.stormlist("slib.abusech.bazaar.search tag")
            self.stormIsInErr("requires a value", msgs)

    async def test_cscb(self):
        async with abusechSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.abusech.bazaar.cscb")
            self.stormIsInPrint("1 blocklisted code signing certificates", msgs)
            assert not [m for m in msgs if m[0] == "node"]

            nodes = await core.nodes("slib.abusech.bazaar.cscb --yield")
            assert len(nodes) == 1
            cert = nodes[0]
            assert cert.get("sha256") == "1" * 64 and cert.get("subject") == "Bad Signer Ltd"
            assert cert.tags["rep.abusech.bazaar.cscb"] == (1788256800000, 1788256800001)
            assert await count(core, "crypto:x509:cert <(about)- meta:note +:text='Malware signing (Emotet)'") == 1

    async def test_download(self):
        async with abusechSvc(self) as (core, svc, fake):
            for plat in ("bazaar", "urlhaus", "yaraify"):
                msgs = await core.stormlist(f"slib.abusech.{plat}.download --hash {fd.SAMPLE_SHA256} --yield")
                self.stormIsInPrint(f"Saved {fd.SAMPLE_SHA256}", msgs)
                nodes = [m for m in msgs if m[0] == "node"]
                assert len(nodes) == 1
                assert await core.axon.has(bytes.fromhex(fd.SAMPLE_SHA256))

                msgs = await core.stormlist(f"slib.abusech.{plat}.download --hash {MD5()}")
                self.stormIsInWarn("is not a SHA256 hash", msgs)

                await core.nodes(f"[ hash:sha256={'a' * 64} ]")
                msgs = await core.stormlist(f"hash:sha256={'a' * 64} | slib.abusech.{plat}.download")
                if plat == "urlhaus":
                    self.stormIsInWarn("failed", msgs)
                else:
                    self.stormIsInWarn("does not have", msgs)

                msgs = await core.stormlist(f"[ inet:fqdn=vertex.link ] | slib.abusech.{plat}.download")
                self.stormIsInWarn("has no SHA256 to download", msgs)

            nodes = await core.nodes(f"file:bytes={fd.SAMPLE_SHA256}")
            assert nodes[0].get("size") == len(fd.SAMPLE_BYTES)
            assert await count(core, f"file:bytes={fd.SAMPLE_SHA256} <(seen)- meta:source") == 3

            # Files YARAify unpacked.
            msgs = await core.stormlist(f"slib.abusech.yaraify.download --unpacked --hash {fd.SAMPLE_SHA256}")
            self.stormIsInPrint(f"Saved {fd.SAMPLE_SHA256}", msgs)
            assert fake.last("/yaraify")["json"]["query"] == "get_unpacked"
            msgs = await core.stormlist(f"slib.abusech.yaraify.download --unpacked --hash {'a' * 64}")
            self.stormIsInWarn("does not have", msgs)

    async def test_submit(self):
        async with abusechSvc(self) as (core, svc, fake):
            size, sha256 = await core.axon.put(b"MZ sample to submit")
            sha256 = sha256.hex()
            await core.nodes(f"[ file:bytes={sha256} :size={size} :name=evil.exe ]")

            msgs = await core.stormlist(
                f"file:bytes={sha256} | slib.abusech.bazaar.submit --tag exe --delivery email_link "
                f"--link https://x.com/1 --ref any_run=https://app.any.run/tasks/1 --comment hi --dropped-by {SHA256}"
            )
            self.stormIsInPrint("Submitting", msgs)
            req = fake.last("/bazaar")
            assert req["files"]["file"] == ("evil.exe", b"MZ sample to submit")
            assert json.loads(req["form"]["json_data"]) == {
                "anonymous": 0, "tags": ["exe"], "delivery_method": "email_link",
                "references": {"links": ["https://x.com/1"], "any_run": ["https://app.any.run/tasks/1"]},
                "context": {"comment": "hi", "dropped_by_sha256": [SHA256]},
            }

            msgs = await core.stormlist(f"[ file:bytes={'a' * 64} ] | slib.abusech.bazaar.submit")
            self.stormIsInWarn("is not in the Axon", msgs)
            msgs = await core.stormlist("[ inet:fqdn=vertex.link ] | slib.abusech.bazaar.submit")
            self.stormIsInWarn("Only file:bytes nodes", msgs)

    async def test_update(self):
        async with abusechSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(f"slib.abusech.bazaar.update --hash {SHA256} --comment hello --add add_tag=x --add bad")
            self.stormIsInWarn("--add must be <key>=<value>", msgs)
            assert fake.queries("bazaar") == ["add_comment", "update"]
            assert fake.last("/bazaar")["form"] == {"query": "update", "sha256_hash": SHA256, "key": "add_tag", "value": "x"}

            # Unknown keys, and updating samples MalwareBazaar doesn't have, fail.
            msgs = await core.stormlist(f"slib.abusech.bazaar.update --hash {SHA256} --add tags=x")
            self.stormIsInWarn("Unknown MalwareBazaar update key tags", msgs)
            msgs = await core.stormlist(f"slib.abusech.bazaar.update --hash {'a' * 64} --comment x")
            self.stormIsInWarn("hash_not_found", msgs)

            await core.nodes(f"[ {FILE} ]")
            await core.nodes(f"{FILE} | slib.abusech.bazaar.update --comment again")
            assert fake.last("/bazaar")["form"]["comment"] == "again"

            msgs = await core.stormlist("slib.abusech.bazaar.update --hash abc --comment x")
            self.stormIsInWarn("is not a SHA256 hash", msgs)
            msgs = await core.stormlist("slib.abusech.bazaar.update --hash abc")
            self.stormIsInErr("requires --comment and/or --add", msgs)

    async def test_export(self):
        async with abusechSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.abusech.bazaar.export")
            assert not [m for m in msgs if m[0] == "node"]
            nodes = await core.nodes(FILE)
            assert "rep.abusech.bazaar.agenttesla" in nodes[0].tags
            assert await count(core, f"{FILE} -> it:av:scan:result:target:file +:scanner:name=clamav") == 1
            assert await count(core, f"{FILE} -> it:av:scan:result:target:file +:scanner:name=virustotal") == 1

            nodes = await core.nodes("slib.abusech.bazaar.export full --limit 1 --yield")
            assert len(nodes) == 1
            msgs = await core.stormlist("slib.abusech.bazaar.export full")
            self.stormIsInWarn("may take a while", msgs)


def MD5():
    return fd.MD5


class TestStormUrlhaus(s_tests.SynTest):

    async def test_url(self):
        async with abusechSvc(self) as (core, svc, fake):
            url = fd.URLHAUS_URL["url"]
            nodes = await core.nodes(f"[ inet:url={url} ] | slib.abusech.urlhaus.lookup --yield")
            assert len(nodes) == 1
            u = nodes[0]
            for tag in ("malware_download", "elf", "mozi", "status.online", "larted"):
                assert f"rep.abusech.urlhaus.{tag}" in u.tags, tag
            assert u.tags["rep.abusech.urlhaus.mozi"] == (1790848800000, 1791021600000)

            assert await count(core, "inet:fqdn=evil.example.com +#rep.abusech.urlhaus.spamhaus_dbl.abused_legit_malware") == 1
            assert await count(core, "inet:fqdn=evil.example.com +#rep.abusech.urlhaus.surbl") == 0
            assert await count(core, f"inet:url={url} <(refs)- inet:url +inet:url=https://urlhaus.abuse.ch/url/105821/") == 1
            assert await count(core, f"inet:service:account:user=lrz_urlhaus -(seen)> inet:url +inet:url={url}") == 1

            nodes = await core.nodes(f"inet:urlfile:url={url} -> file:bytes")
            assert len(nodes) == 1
            pay = nodes[0]
            assert pay.get("sha256") == fd.PAYLOAD and pay.get("md5") == fd.PAYLOAD_MD5 and pay.get("size") == 307960
            assert pay.get("name") == "mozi.m" and pay.get("_tlsh") == "t1ffff"
            assert "rep.abusech.urlhaus.mozi" in pay.tags and "rep.abusech.urlhaus.type.elf" in pay.tags
            vt = (await core.nodes(f"file:bytes={fd.PAYLOAD} -> it:av:scan:result:target:file"))[0]
            assert vt.get("scanner:name") == "virustotal" and vt.get("multi:count") == 60
            assert vt.get("multi:count:malicious") == 10 and vt.get("verdict") == 40
            assert await count(core, f"file:bytes={fd.PAYLOAD} <(refs)- inet:url +inet:url=https://www.virustotal.com/gui/file/x") == 1

            # Status tags are replaced when the status changes.
            fake.overrides[("urlhaus", "url/")] = (200, dict(fd.URLHAUS_URL, url_status="offline"))
            nodes = await core.nodes(f"inet:url={url} | slib.abusech.urlhaus.lookup")
            u = nodes[0]
            assert "rep.abusech.urlhaus.status.offline" in u.tags
            assert "rep.abusech.urlhaus.status.online" not in u.tags
            fake.overrides.clear()

            nodes = await core.nodes("slib.abusech.urlhaus.lookup --id 105821 --url http://nope.com/ --yield")
            assert [n.repr() for n in nodes] == [url]
            assert fake.last("/urlhaus")["form"] == {"urlid": "105821"}

    async def test_host_payload(self):
        async with abusechSvc(self) as (core, svc, fake):
            nodes = await core.nodes("[ inet:ipv4=1.2.3.4 ] | slib.abusech.urlhaus.lookup --yield")
            assert [n.repr() for n in nodes] == ["1.2.3.4"]
            u = (await core.nodes("inet:url=http://1.2.3.4/i"))[0]
            assert "rep.abusech.urlhaus.status.offline" in u.tags and "rep.abusech.urlhaus.32_bit" in u.tags
            assert await count(core, "inet:ipv4=1.2.3.4 <(refs)- inet:url +inet:url=https://urlhaus.abuse.ch/host/1.2.3.4/") == 1
            assert await count(core, "inet:service:account") == 0

            nodes = await core.nodes(f"[ hash:md5={fd.PAYLOAD_MD5} ] | slib.abusech.urlhaus.lookup --yield")
            assert [n.get("sha256") for n in nodes] == [fd.PAYLOAD]
            assert fake.last("/urlhaus")["form"] == {"md5_hash": fd.PAYLOAD_MD5}
            assert await count(core, f"file:bytes={fd.PAYLOAD} -> inet:urlfile -> inet:url") == 1

            nodes = await core.nodes(f"file:bytes={fd.PAYLOAD} | slib.abusech.urlhaus.lookup")
            assert fake.last("/urlhaus")["form"] == {"sha256_hash": fd.PAYLOAD}

            await core.nodes(f"slib.abusech.urlhaus.lookup --host 1.2.3.4 --hash {fd.PAYLOAD}")
            msgs = await core.stormlist("[ file:bytes=* ] | slib.abusech.urlhaus.lookup")
            self.stormIsInWarn("has no MD5 or SHA256", msgs)
            msgs = await core.stormlist("[ ou:org=* ] | slib.abusech.urlhaus.lookup")
            self.stormIsInWarn("is not supported", msgs)

    async def test_search(self):
        async with abusechSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.abusech.urlhaus.search tag Mozi")
            self.stormIsInPrint("URLhaus has 2 URLs for tag Mozi", msgs)
            assert len([m for m in msgs if m[0] == "node"]) == 2

            nodes = await core.nodes("slib.abusech.urlhaus.search signature Mozi")
            assert [n.repr() for n in nodes] == [fd.URLHAUS_URL["url"]]
            vt = (await core.nodes(f"file:bytes={fd.PAYLOAD} -> it:av:scan:result:target:file"))[0]
            assert vt.get("verdict") == 10

            nodes = await core.nodes("slib.abusech.urlhaus.search recent-urls --limit 3")
            assert len(nodes) == 1 and fake.last("/urlhaus")["path"] == "/urlhaus/urls/recent/limit/3/"
            nodes = await core.nodes("slib.abusech.urlhaus.search recent-payloads")
            assert [n.get("sha256") for n in nodes] == [fd.PAYLOAD]

            msgs = await core.stormlist("slib.abusech.urlhaus.search tag")
            self.stormIsInErr("requires a value", msgs)

    async def test_submit_export(self):
        async with abusechSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(
                "[ inet:url=http://a.com/1 inet:url=http://a.com/2 inet:fqdn=a.com ] | "
                "slib.abusech.urlhaus.submit --url http://a.com/3 --tag elf --anonymous"
            )
            self.stormIsInWarn("Only inet:url nodes", msgs)
            self.stormIsInPrint("Your submission has been accepted", msgs)
            body = fake.last("/urlhaus_submit")["json"]
            assert body["anonymous"] == "1"
            assert sorted(s["url"] for s in body["submission"]) == ["http://a.com/1", "http://a.com/2", "http://a.com/3"]
            assert body["submission"][0]["tags"] == ["elf"]

            nodes = await core.nodes("slib.abusech.urlhaus.export online --yield")
            assert [n.repr() for n in nodes] == ["http://csv.example.com/x.exe"]
            assert "rep.abusech.urlhaus.agenttesla" in nodes[0].tags
            assert await count(core, "inet:service:account:user=reporter1") == 1
            await core.nodes("slib.abusech.urlhaus.export full --limit 1")
            assert fake.last()["path"] == "/urlhaus_export/testkey/full.csv.zip"


class TestStormThreatFox(s_tests.SynTest):

    async def test_lookup(self):
        async with abusechSvc(self) as (core, svc, fake):
            nodes = await core.nodes("[ inet:fqdn=gaga.com ] | slib.abusech.threatfox.lookup --yield")
            assert [n.repr() for n in nodes] == ["gaga.com"]
            assert fake.last("/threatfox")["json"] == {"query": "search_ioc", "search_term": "gaga.com", "exact_match": True}
            fqdn = nodes[0]
            for tag in ("botnet_cc", "dridex", "exe", "test"):
                assert f"rep.abusech.threatfox.{tag}" in fqdn.tags, tag

            nodes = await core.nodes("inet:fqdn=gaga.com <(refs)- it:sec:stix:indicator")
            assert len(nodes) == 1
            ind = nodes[0]
            assert ind.get("id") == "threatfox--41" and ind.get("confidence") == 50
            assert ind.get("pattern") == "[domain-name:value = 'gaga.com']" and ind.get("pattern_type") == "stix"
            assert ind.get("name") == "threatfox IOC 41: gaga.com"
            assert "Dridex C2 seen in the wild." in ind.get("description")
            assert ind.get("labels") == ("botnet_cc", "dridex", "exe", "test")
            assert ind.get("created") == 1790838000000
            assert await count(core, "it:sec:stix:indicator <(refs)- inet:url +inet:url=https://twitter.com/abuse_ch/status/2") == 1

            nodes = await core.nodes("risk:tool:software:tag=rep.abusech.threatfox.dridex")
            assert len(nodes) == 1 and nodes[0].get("id") == "win.dridex" and nodes[0].get("soft:name") == "dridex"
            assert await count(core, "risk:tool:software <(refs)- inet:url +inet:url=https://malpedia.caad.fkie.fraunhofer.de/details/win.dridex") == 1

            # The IOC's malware sample references it.
            assert await count(core, f"{FILE} -(refs)> inet:fqdn +inet:fqdn=gaga.com") == 1
            assert await count(core, "inet:service:account:user=abuse_ch -(seen)> inet:fqdn") == 1

    async def test_lookup_forms(self):
        async with abusechSvc(self) as (core, svc, fake):
            nodes = await core.nodes("[ inet:server=tcp://5.6.7.8:443 ] | slib.abusech.threatfox.lookup --yield")
            assert [n.repr() for n in nodes] == ["tcp://5.6.7.8:443"]
            assert fake.last("/threatfox")["json"]["search_term"] == "5.6.7.8:443"
            srv = nodes[0]
            assert "rep.abusech.threatfox.cobalt_strike" in srv.tags and "rep.abusech.threatfox.cs_watermark_987654321" in srv.tags
            assert await count(core, "inet:ipv4=5.6.7.8 +#rep.abusech.threatfox.cobalt_strike") == 0
            tool = (await core.nodes("risk:tool:software:tag=rep.abusech.threatfox.cobalt_strike"))[0]
            assert set(tool.get("soft:names")) == {"agentemis", "beacon", "cobaltstrike", "cobalt strike"}
            ind = (await core.nodes("inet:server=tcp://5.6.7.8:443 <(refs)- it:sec:stix:indicator"))[0]
            assert ind.get("updated") == 1790985600000

            nodes = await core.nodes("[ inet:url=http://c2.example.org/gate.php ] | slib.abusech.threatfox.lookup --yield")
            assert len(nodes) == 1 and "rep.abusech.threatfox.loki_password_stealer_pws" in nodes[0].tags

            nodes = await core.nodes(f"[ {FILE} ] | slib.abusech.threatfox.lookup --yield")
            assert {n.ndef[0] for n in nodes} == {"inet:fqdn", "file:bytes"}
            assert fake.last("/threatfox")["json"] == {"query": "search_hash", "hash": SHA256}
            assert await count(core, f"{FILE} +#rep.abusech.threatfox.payload +#rep.abusech.threatfox.agent_tesla") == 1

            nodes = await core.nodes("slib.abusech.threatfox.lookup --id 41 --ioc nope.com --hash nope --yield")
            assert [n.repr() for n in nodes] == ["gaga.com"]
            await core.nodes("slib.abusech.threatfox.lookup --ioc gaga.com --fuzzy")
            assert fake.last("/threatfox")["json"]["exact_match"] is False

            msgs = await core.stormlist("[ ou:org=* ] | slib.abusech.threatfox.lookup")
            self.stormIsInWarn("is not supported", msgs)

    async def test_search_ref(self):
        async with abusechSvc(self) as (core, svc, fake):
            nodes = await core.nodes("slib.abusech.threatfox.search recent 3")
            assert {n.repr() for n in nodes} == {"gaga.com", "tcp://5.6.7.8:443"}
            assert fake.last("/threatfox")["json"]["days"] == 3
            nodes = await core.nodes("slib.abusech.threatfox.search malware win.cobalt_strike --limit 1")
            assert len(nodes) == 1
            assert fake.last("/threatfox")["json"] == {"query": "malwareinfo", "malware": "win.cobalt_strike", "limit": 1}
            await core.nodes("slib.abusech.threatfox.search tag Emotet")
            assert fake.last("/threatfox")["json"]["query"] == "taginfo"
            msgs = await core.stormlist("slib.abusech.threatfox.search tag")
            self.stormIsInErr("requires a value", msgs)

            msgs = await core.stormlist("slib.abusech.threatfox.ref types")
            self.stormIsInPrint("ip:port combination", msgs)
            msgs = await core.stormlist("slib.abusech.threatfox.ref tags")
            self.stormIsInPrint("Emotet", msgs)
            msgs = await core.stormlist("slib.abusech.threatfox.ref malware")
            self.stormIsInPrint("win.dridex", msgs)
            msgs = await core.stormlist("slib.abusech.threatfox.ref label --malware cobalt --platform win")
            self.stormIsInPrint("win.cobalt_strike", msgs)
            assert fake.last("/threatfox")["json"] == {"query": "get_label", "malware": "cobalt", "platform": "win"}
            msgs = await core.stormlist("slib.abusech.threatfox.ref label")
            self.stormIsInErr("requires --malware", msgs)

    async def test_submit_export(self):
        async with abusechSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(
                "[ inet:server=tcp://1.2.3.4:443 inet:server=tcp://1.2.3.5:8443 inet:fqdn=skip.com ] | "
                "slib.abusech.threatfox.submit botnet_cc win.cobalt_strike --confidence 75 --tag CS --comment hi"
            )
            self.stormIsInWarn("Skipping skip.com, every IOC must be a ip:port", msgs)
            self.stormIsInPrint("Submitting 2 IOCs to ThreatFox", msgs)
            body = fake.last("/threatfox")["json"]
            assert body["query"] == "submit_ioc" and body["ioc_type"] == "ip:port"
            assert sorted(body["iocs"]) == ["1.2.3.4:443", "1.2.3.5:8443"]
            assert body["confidence_level"] == 75 and body["tags"] == ["CS"] and body["comment"] == "hi"

            await core.nodes(f"[ {FILE} ] | slib.abusech.threatfox.submit payload win.agent_tesla")
            assert fake.last("/threatfox")["json"]["ioc_type"] == "sha256_hash"
            await core.nodes("slib.abusech.threatfox.submit payload_delivery x --ioc a.com --type domain --anonymous")
            body = fake.last("/threatfox")["json"]
            assert body["iocs"] == ["a.com"] and body["anonymous"] == 1
            msgs = await core.stormlist("slib.abusech.threatfox.submit payload_delivery x --ioc a.com")
            self.stormIsInWarn("Use --type with --ioc", msgs)
            msgs = await core.stormlist("[ file:bytes=* ] | slib.abusech.threatfox.submit payload x")
            self.stormIsInWarn("can't be submitted", msgs)

            nodes = await core.nodes("slib.abusech.threatfox.export --yield")
            assert [n.repr() for n in nodes] == ["export.example.com"]
            assert "rep.abusech.threatfox.qakbot" in nodes[0].tags and "rep.abusech.threatfox.ta570" in nodes[0].tags
            msgs = await core.stormlist("slib.abusech.threatfox.export full --limit 1")
            self.stormIsInWarn("may take a while", msgs)


class TestStormYaraify(s_tests.SynTest):

    async def test_lookup(self):
        async with abusechSvc(self) as (core, svc, fake):
            nodes = await core.nodes(f"[ {FILE} ] | slib.abusech.yaraify.lookup --malpedia tok --yield")
            assert len(nodes) == 1
            f = nodes[0]
            assert f.get("_gimphash") == "abcdef0123" and f.get("_sha3_384") == fd.SHA3
            assert fake.last("/yaraify")["json"]["malpedia-token"] == "tok"

            rule = (await core.nodes(f"it:app:yara:match:file=sha256:{SHA256} -> it:app:yara:rule"))[0]
            assert rule.get("name") == "win_agent_tesla_auto" and rule.get("ext:id") == "6a6d2b48-1234-4cde-9f00-112233445566"
            assert rule.get("family") == "win.agent_tesla"
            assert "rep.abusech.yaraify.tlp.white" in rule.tags
            assert await count(core, "it:app:yara:rule <(about)- meta:note +:text~='License: CC BY-NC 4.0'") == 1
            assert await count(core, f"{FILE} -> it:av:scan:result:target:file +:scanner:name=clamav") == 1

            nodes = await core.nodes(f"file:subfile:parent=sha256:{SHA256}")
            assert len(nodes) == 1 and nodes[0].get("name") == "unpacked.bin"
            assert await count(core, f"it:app:yara:match:file=sha256:{fd.UNPACKED} -> it:app:yara:rule +:name=AgentTesla_Unpacked") == 1

            nodes = await core.nodes("slib.abusech.yaraify.lookup --task cfa49f83-6d98-11ed-a71a-42010aa4000b --task queued-task --yield")
            assert [n.get("sha256") for n in nodes] == [SHA256]
            msgs = await core.stormlist("slib.abusech.yaraify.lookup --task queued-task")
            self.stormIsInPrint("Task queued-task is queued", msgs)
            msgs = await core.stormlist("slib.abusech.yaraify.lookup --hash nothex")
            self.stormIsInWarn("failed", msgs)
            msgs = await core.stormlist("[ ou:org=* ] | slib.abusech.yaraify.lookup")
            self.stormIsInWarn("has no hash", msgs)

    async def test_search_rules(self):
        async with abusechSvc(self) as (core, svc, fake):
            nodes = await core.nodes("slib.abusech.yaraify.search yara MyRule --limit 5")
            assert [n.get("sha256") for n in nodes] == ["a" * 64]
            assert fake.last("/yaraify")["json"] == {"query": "get_yara", "search_term": "MyRule", "result_max": 5}
            assert await count(core, "it:app:yara:rule:name=MyRule -> it:app:yara:match") == 1

            nodes = await core.nodes("slib.abusech.yaraify.rules --uuid 6a6d2b48-1234-4cde-9f00-112233445566 --recent --yield")
            assert {n.get("name") for n in nodes} == {"win_agent_tesla_auto", "helper_rule", "New_Rule_1", "Private_Rule"}
            # Recent rules get their text when the author shares them.
            rule = (await core.nodes("it:app:yara:rule:name=New_Rule_1"))[0]
            assert rule.get("text") == fd.NEW_RULE_TEXT.strip()
            assert rule.get("ext:id") == "11111111-2222-3333-4444-555555555555"
            assert (await core.nodes("it:app:yara:rule:name=Private_Rule"))[0].get("text") is None

            # Your deployed rules, and an updated rule's text replaces the old one.
            fake.overrides[("yaraify", "get_yara_rule")] = (200, fd.NEW_RULE_TEXT.replace("0x5a4d", "0x457f"))
            nodes = await core.nodes("slib.abusech.yaraify.rules --deployed --yield")
            assert [n.get("name") for n in nodes] == ["New_Rule_1"]
            assert "0x457f" in nodes[0].get("text")
            assert await count(core, "it:app:yara:rule:name=New_Rule_1") == 1
            fake.overrides.clear()
            rule = (await core.nodes("it:app:yara:rule:name=win_agent_tesla_auto"))[0]
            assert rule.get("text").startswith("rule win_agent_tesla_auto")
            assert rule.get("created") == 1767225600000
            assert await count(core, "it:app:yara:rule:name=win_agent_tesla_auto :author -> ps:contact +:name='felix bilstein'") == 1

            nodes = await core.nodes("slib.abusech.yaraify.rules --all --limit 1 --yield")
            assert len(nodes) == 1
            msgs = await core.stormlist("slib.abusech.yaraify.rules")
            self.stormIsInErr("requires --uuid, --recent, --deployed, or --all", msgs)

    async def test_scan_tasks_deploy(self):
        async with abusechSvc(self) as (core, svc, fake):
            size, sha256 = await core.axon.put(b"MZ scan me")
            sha256 = sha256.hex()
            await core.nodes(f"[ file:bytes={sha256} :size={size} ]")

            msgs = await core.stormlist(f"file:bytes={sha256} | slib.abusech.yaraify.scan --unpack --identifier ident")
            self.stormIsInPrint("task 11111111-aaaa-bbbb-cccc-000000000001", msgs)
            req = fake.last("/yaraify")
            assert req["files"]["file"] == (sha256, b"MZ scan me")
            assert json.loads(req["form"]["json_data"])["unpack"] == 1

            nodes = await core.nodes(f"file:bytes={sha256} | slib.abusech.yaraify.scan --rescan --wait 30 --yield")
            assert [n.get("sha256") for n in nodes] == [SHA256]
            assert fake.queries("yaraify")[-2:] == ["rescan_file", "get_results"]

            nodes = await core.nodes(f"slib.abusech.yaraify.scan --hash {SHA256} --wait 30 --yield")
            assert [n.get("sha256") for n in nodes] == [SHA256]
            msgs = await core.stormlist("[ file:bytes=* ] | slib.abusech.yaraify.scan")
            self.stormIsInWarn("has no hash to rescan", msgs)

            msgs = await core.stormlist("slib.abusech.yaraify.tasks --new")
            self.stormIsInPrint("Your new (private) identifier is abcdef-identifier", msgs)
            msgs = await core.stormlist("slib.abusech.yaraify.tasks ident --status queued")
            self.stormIsInPrint("cfa49f83-6d98-11ed-a71a-42010aa4000b", msgs)
            assert fake.last("/yaraify")["json"]["task_status"] == "queued"
            msgs = await core.stormlist("slib.abusech.yaraify.tasks")
            self.stormIsInErr("requires an identifier", msgs)

            await core.nodes("[ it:app:yara:rule=* :name=myrule :text='rule myrule { condition: true }' ]")
            msgs = await core.stormlist("it:app:yara:rule | slib.abusech.yaraify.deploy --text 'rule t { condition: true }'")
            self.stormIsInPrint("Rule deployed", msgs)
            assert fake.last("/yaraify")["files"]["yara_file"] == ("myrule.yar", b"rule myrule { condition: true }")
            msgs = await core.stormlist("slib.abusech.yaraify.deploy --delete 6a6d2b48-1234-4cde-9f00-112233445566 --delete nope")
            self.stormIsInPrint("YARA rule deleted", msgs)
            self.stormIsInWarn("Unknown YARA rule", msgs)
            assert fake.last("/yaraify")["json"] == {"query": "delete_yara_rule", "yarahub_uuid": "nope"}
            msgs = await core.stormlist("[ it:app:yara:rule=* :name=empty ] | slib.abusech.yaraify.deploy")
            self.stormIsInWarn("has no :text", msgs)
            msgs = await core.stormlist("[ inet:fqdn=a.com ] | slib.abusech.yaraify.deploy")
            self.stormIsInWarn("Only it:app:yara:rule nodes", msgs)


class TestStormBlocklists(s_tests.SynTest):

    async def test_feodo(self):
        async with abusechSvc(self) as (core, svc, fake):
            nodes = await core.nodes("slib.abusech.feodo --yield")
            assert {n.repr() for n in nodes} == {"tcp://50.16.16.211:8080", "tcp://60.1.2.3:443"}
            srv = (await core.nodes("inet:server=tcp://50.16.16.211:8080"))[0]
            for tag in ("c2", "qakbot", "status.online"):
                assert f"rep.abusech.feodo.{tag}" in srv.tags, tag
            ip = (await core.nodes("inet:ipv4=50.16.16.211"))[0]
            assert ip.get("asn") == 14618 and ip.get("loc") == "us" and "rep.abusech.feodo.qakbot" in ip.tags
            assert await count(core, "inet:asn=14618 +:name=amazon-aes") == 1
            assert await count(core, "inet:dns:a=(ec2.example.com, 50.16.16.211)") == 1
            assert await count(core, "risk:tool:software:tag=rep.abusech.feodo.emotet") == 1

            nodes = await core.nodes("slib.abusech.feodo recommended --yield")
            assert {n.repr() for n in nodes} == {"tcp://50.16.16.211:8080"}
            nodes = await core.nodes("slib.abusech.feodo aggressive --yield")
            assert [n.repr() for n in nodes] == ["tcp://80.1.2.3:447"]
            assert not await core.nodes("slib.abusech.feodo --limit 1")

    async def test_sslbl(self):
        async with abusechSvc(self) as (core, svc, fake):
            nodes = await core.nodes("slib.abusech.sslbl certs --yield")
            assert {n.get("sha1") for n in nodes} == {"1" * 40, "2" * 40}
            cert = (await core.nodes(f"crypto:x509:cert:sha1={'1' * 40}"))[0]
            assert "rep.abusech.sslbl.c2" in cert.tags and "rep.abusech.sslbl.dridex" in cert.tags
            assert await count(core, f"crypto:x509:cert:sha1={'1' * 40} <(about)- meta:note +:text='Dridex C&C'") == 1

            # The C2 IP lists were deprecated.
            msgs = await core.stormlist("slib.abusech.sslbl ips")
            self.stormIsInErr("Invalid choice", msgs)

            nodes = await core.nodes("slib.abusech.sslbl ja3 --yield")
            assert [n.repr() for n in nodes] == ["51c64c77e60f3980eea90869b68c58a8"]
            assert "rep.abusech.sslbl.ja3" in nodes[0].tags and "rep.abusech.sslbl.dridex" in nodes[0].tags

    async def test_fplist(self):
        async with abusechSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.abusech.fplist")
            self.stormIsInPrint("3 false positive entries", msgs)
            # A sample's rows are one file, including the SHA3-384, and SHA3-only entries model too.
            f = (await core.nodes(f"file:bytes={'0' * 64}"))[0]
            assert f.get("md5") == "0" * 32 and f.get("sha1") == "0" * 40 and f.get("_sha3_384") == "0" * 96
            assert await count(core, f"file:bytes:md5={'0' * 32}") == 1
            nodes = await core.nodes(f"file:bytes:_sha3_384={'1' * 96}")
            assert len(nodes) == 1 and "rep.abusech.hunting.fp.threatfox" in nodes[0].tags
            nodes = await core.nodes("slib.abusech.fplist --platform urlhaus --yield")
            assert [n.repr() for n in nodes] == ["legit.example.com"]
            assert "rep.abusech.hunting.fp.urlhaus" in nodes[0].tags
            f = (await core.nodes(f"file:bytes={'0' * 64}"))[0]
            assert "rep.abusech.hunting.fp.malwarebazaar" in f.tags
            assert await count(core, f"file:bytes={'0' * 64} <(about)- meta:note +:text='Legitimate installer (removed by admin)'") == 1


class TestStormEnrich(s_tests.SynTest):

    async def test_enrich(self):
        async with abusechSvc(self) as (core, svc, fake):
            await core.nodes(f"[ {FILE} inet:url={fd.URLHAUS_URL['url']} inet:ipv4=1.2.3.4 inet:server=tcp://5.6.7.8:443 ]")
            msgs = await core.stormlist(f"{FILE} inet:url={fd.URLHAUS_URL['url']} inet:ipv4=1.2.3.4 "
                                        "inet:server=tcp://5.6.7.8:443 | slib.abusech.enrich")
            self.stormHasNoErr(msgs)
            assert fake.queries("bazaar") == ["get_info"]
            assert set(fake.queries("yaraify")) == {"lookup_hash"}
            assert set(fake.queries("threatfox")) == {"search_hash", "search_ioc"}
            # The IP is searched with a wildcard, so it finds its ip:port IOCs.
            assert {"search_term": "1.2.3.4", "exact_match": False, "query": "search_ioc"} in [
                r["json"] for r in fake.requests if r["path"].startswith("/threatfox")]
            assert {r["path"] for r in fake.requests if r["path"].startswith("/urlhaus")} == {
                "/urlhaus/payload/", "/urlhaus/url/", "/urlhaus/host/"}

            fake.requests.clear()
            nodes = await core.nodes(f"{FILE} | slib.abusech.enrich --platform bazaar --yield")
            assert [n.get("sha256") for n in nodes] == [SHA256]
            assert fake.queries("bazaar") == ["get_info"] and not fake.queries("threatfox")

            # URLhaus doesn't take SHA1s, and ThreatFox only finds them as hash IOCs.
            fake.requests.clear()
            await core.nodes(f"[ hash:sha1={fd.SHA1} ] | slib.abusech.enrich")
            assert fake.queries("bazaar") == ["get_info"] and fake.queries("threatfox") == ["search_ioc"]
            assert not [r for r in fake.requests if r["path"].startswith("/urlhaus")]

            # URLhaus doesn't take IPv6 hosts, ThreatFox does.
            fake.requests.clear()
            nodes = await core.nodes("[ inet:ipv6=2001:db8::1 ] | slib.abusech.enrich")
            assert not [r for r in fake.requests if r["path"].startswith("/urlhaus")] and fake.queries("threatfox")

            msgs = await core.stormlist("[ ou:org=* ] | slib.abusech.enrich")
            self.stormIsInWarn("is not supported", msgs)
            msgs = await core.stormlist("[ file:bytes=* ] | slib.abusech.enrich")
            self.stormIsInWarn("has no hash to enrich", msgs)


class TestStormAdmin(s_tests.SynTest):

    async def test_keys_tags_request(self):
        async with abusechSvc(self, apikey=None) as (core, svc, fake):
            msgs = await core.stormlist(f"slib.abusech.bazaar.lookup --hash {SHA256}")
            self.stormIsInWarn("No abuse.ch Auth-Key is configured", msgs)

            msgs = await core.stormlist("slib.abusech.admin.apikey")
            self.stormIsInPrint("No service-wide Auth-Key is set", msgs)
            msgs = await core.stormlist("slib.abusech.admin.apikey svckey")
            self.stormIsInPrint("Set the slib.abusech Auth-Key", msgs)
            msgs = await core.stormlist("slib.abusech.admin.apikey")
            self.stormIsInPrint("A service-wide Auth-Key is set", msgs)
            await core.nodes(f"slib.abusech.bazaar.lookup --hash {SHA256}")
            assert fake.last("/bazaar")["authkey"] == "svckey"

            # A user's own key wins.
            msgs = await core.stormlist("slib.abusech.apikey")
            self.stormIsInPrint("You don't have an abuse.ch Auth-Key set", msgs)
            msgs = await core.stormlist("slib.abusech.apikey mykey")
            self.stormIsInPrint("Saved your abuse.ch Auth-Key", msgs)
            msgs = await core.stormlist("slib.abusech.apikey")
            self.stormIsInPrint("Your abuse.ch Auth-Key is set", msgs)
            await core.nodes(f"slib.abusech.bazaar.lookup --hash {SHA256}")
            assert fake.last("/bazaar")["authkey"] == "mykey"
            msgs = await core.stormlist("slib.abusech.apikey newkey")
            self.stormIsInPrint("Updated your abuse.ch Auth-Key", msgs)
            await core.nodes("slib.abusech.feodo")
            await core.nodes("slib.abusech.threatfox.search recent")
            assert fake.last("/threatfox")["authkey"] == "newkey"
            msgs = await core.stormlist("slib.abusech.apikey --clear")
            self.stormIsInPrint("Deleted your abuse.ch Auth-Key", msgs)
            msgs = await core.stormlist("slib.abusech.apikey --clear")
            self.stormIsInPrint("You don't have an abuse.ch Auth-Key set", msgs)

            msgs = await core.stormlist("slib.abusech.admin.apikey --clear")
            self.stormIsInPrint("Cleared the slib.abusech Auth-Key", msgs)

            # Tag settings.
            msgs = await core.stormlist("slib.abusech.admin.tags --prefix rep.abuse")
            self.stormIsInPrint("enabled=true prefix=rep.abuse", msgs)
            await core.nodes("slib.abusech.feodo")
            assert await count(core, "inet:server +#rep.abuse.feodo.c2") == 2
            await core.nodes("slib.abusech.admin.tags --disable")
            await core.nodes("slib.abusech.sslbl ja3")
            assert not (await core.nodes("hash:md5"))[0].tags
            await core.nodes("slib.abusech.admin.tags --enable")
            msgs = await core.stormlist("slib.abusech.admin.tags --enable --disable")
            self.stormIsInErr("Use --enable or --disable, not both", msgs)

            # Raw requests.
            msgs = await core.stormlist("slib.abusech.admin.apikey svckey")
            msgs = await core.stormlist('slib.abusech.admin.request threatfox --json ({"query": "types"})')
            self.stormIsInPrint("ip:port combination", msgs)
            msgs = await core.stormlist(f'slib.abusech.admin.request bazaar --form ({{"query": "get_info", "hash": "{SHA256}"}})')
            self.stormIsInPrint("AgentTesla", msgs)
            msgs = await core.stormlist("slib.abusech.admin.request urlhaus --path urls/recent/ --method get")
            self.stormIsInPrint("105821", msgs)
            msgs = await core.stormlist("slib.abusech.admin.request bazaar")
            self.stormIsInWarn("unknown_query", msgs)


class TestStormPerms(s_tests.SynTest):

    async def test_perms(self):
        async with abusechSvc(self) as (core, svc, fake):
            user = await core.auth.addUser("analyst")
            opts = {"user": user.iden}

            await core.nodes(f"[ {FILE} ]")
            await user.addRule((True, ("node",)))

            # No slib.abusech perms, no access.
            for query in (f"slib.abusech.bazaar.lookup --hash {SHA256}", "slib.abusech.feodo",
                          f"slib.abusech.bazaar.download --hash {fd.SAMPLE_SHA256}",
                          "slib.abusech.urlhaus.submit --url http://a.com/x", "slib.abusech.admin.tags",
                          "slib.abusech.apikey"):
                msgs = await core.stormlist(query, opts=opts)
                self.stormIsInErr("permission", msgs)

            # The user perm is enough to query and model, without service.get or axon perms.
            await user.addRule((True, ("slib", "abusech", "user")))
            msgs = await core.stormlist(f"slib.abusech.bazaar.lookup --hash {SHA256} --yield", opts=opts)
            self.stormHasNoErr(msgs)
            assert len([m for m in msgs if m[0] == "node"]) == 1
            msgs = await core.stormlist("slib.abusech.feodo", opts=opts)
            self.stormHasNoErr(msgs)
            msgs = await core.stormlist("slib.abusech.apikey userkey", opts=opts)
            self.stormHasNoErr(msgs)
            await core.nodes("slib.abusech.feodo", opts=opts)
            assert fake.last("/feodo")["authkey"] == "userkey"

            # But not to download, submit, or administer.
            for query in (f"slib.abusech.bazaar.download --hash {fd.SAMPLE_SHA256}",
                          "slib.abusech.urlhaus.submit --url http://a.com/x", "slib.abusech.admin.tags",
                          "slib.abusech.admin.apikey"):
                msgs = await core.stormlist(query, opts=opts)
                self.stormIsInErr("permission", msgs)

            await user.addRule((True, ("slib", "abusech", "download")))
            msgs = await core.stormlist(f"slib.abusech.bazaar.download --hash {fd.SAMPLE_SHA256}", opts=opts)
            self.stormIsInPrint("Saved", msgs)

            await user.addRule((True, ("slib", "abusech", "submit")))
            msgs = await core.stormlist("slib.abusech.urlhaus.submit --url http://a.com/x", opts=opts)
            self.stormIsInPrint("accepted", msgs)
            assert fake.last("/urlhaus_submit")["authkey"] == "userkey"

            # Users can't read the service-wide key, or other users' keys.
            msgs = await core.stormlist("$lib.print($lib.service.get(slib.abusech))", opts=opts)
            self.stormIsInErr("permission", msgs)


class TestStormAudit(s_tests.SynTest):
    """Endpoints and behaviors added after auditing the service against abuse.ch's docs and live APIs."""

    async def test_new_options(self):
        async with abusechSvc(self) as (core, svc, fake):
            nodes = await core.nodes("slib.abusech.bazaar.search detections 12")
            assert [n.get("sha256") for n in nodes] == [SHA256]
            assert fake.last("/bazaar")["form"] == {"query": "recent_detections", "hours": "12"}
            nodes = await core.nodes("slib.abusech.bazaar.search serial 0a1b2c3d")
            assert len(nodes) == 2
            assert fake.last("/bazaar")["form"] == {"query": "get_certificate", "serial_number": "0a1b2c3d"}

            nodes = await core.nodes("slib.abusech.bazaar.export yara --yield")
            assert {n.get("name") for n in nodes} == {"unixredflags3", "pe_imphash"}
            assert nodes[0].form.name == "it:app:yara:rule"

            nodes = await core.nodes("slib.abusech.urlhaus.export payloads --yield")
            assert [n.repr() for n in nodes] == [fd.URLHAUS_URL["url"]]
            assert await count(core, f"inet:urlfile:url={fd.URLHAUS_URL['url']} -> file:bytes +:sha256={fd.PAYLOAD}") == 1

            # ThreatFox: IPs find their ip:port IOCs, and files their own hash IOC.
            nodes = await core.nodes("[ inet:ipv4=5.6.7.8 ] | slib.abusech.threatfox.lookup --yield")
            assert [n.repr() for n in nodes] == ["tcp://5.6.7.8:443"]
            nodes = await core.nodes(f"slib.abusech.threatfox.lookup --hash {fd.SHA1} --yield")
            assert nodes == [] and fake.queries("threatfox")[-1] == "search_ioc"

            msgs = await core.stormlist("slib.abusech.yaraify.tasks ident --status all")
            self.stormHasNoWarnErr(msgs)
            assert fake.last("/yaraify")["json"] == {"query": "list_tasks", "identifier": "ident"}

            msgs = await core.stormlist("[ inet:ipv6=2001:db8::1 ] | slib.abusech.urlhaus.lookup")
            self.stormIsInWarn("only support FQDNs and IPv4", msgs)

            # Submitting a file only known by its SHA1.
            await core.nodes(f"[ file:bytes=* :sha1={fd.SHA1} ] | slib.abusech.threatfox.submit payload win.x")
            assert fake.last("/threatfox")["json"]["ioc_type"] == "sha1_hash"

    async def test_yaraify_results(self):
        async with abusechSvc(self) as (core, svc, fake):
            nodes = await core.nodes("slib.abusech.yaraify.lookup --task cfa49f83-6d98-11ed-a71a-42010aa4000b --yield")
            assert [n.get("sha256") for n in nodes] == [SHA256]
            assert await count(core, f"it:app:yara:match:file=sha256:{SHA256}") == 1
            assert await count(core, f"{FILE} -> it:av:scan:result:target:file +:scanner:name=clamav") == 1
            # Masked matches aren't modeled as rules.
            assert await count(core, "it:app:yara:rule:name=xxx") == 0
            msgs = await core.stormlist("slib.abusech.yaraify.lookup --task unknown-task")
            self.stormIsInPrint("Task unknown-task is unknown", msgs)

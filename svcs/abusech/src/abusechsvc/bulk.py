"""Build Synapse nodes for bulk imports of abuse.ch exports, in the service's Python runtime.

Modeling millions of export rows one at a time in Storm takes days. Instead, the service builds
the same nodes the Storm model (``slib.abusech.model``) would create, as packed ``syn.nodes``
nodedefs written to a msgpack ``.nodes`` file, which the Cortex ingests in bulk with
``$lib.feed.fromAxon()``.

``NodeBuilder`` mirrors the Storm model function by function for the record shapes the exports
contain (see ``norm.normSample``, ``norm.normUrl``, ``norm.normUrlhausPayloadRow``, and
``norm.normIoc``). Values are normalized with a standalone copy of the Synapse data model, so
primary values and props match what Storm creates, and nodes keyed by their primary value (files
by SHA256, URLs, IPs, FQDNs, etc.) merge with nodes modeled live.

Guid-by-dict nodes (``risk:tool:software``, ``inet:service:account``, ``it:av:scan:result``, etc.) get
the guid ``$lib.guid()`` would give them, but Storm's ``{...}`` guid syntax first looks for an
existing node with those props, which the service can't do. Where a matching node was made some
other way (ex. by hand, or with a different guid), the import adds a second node instead of
reusing it.

Known differences from the Storm model, because bulk ingest can only add and set:

* Old ``<prefix>.<platform>.status.*`` tags on existing nodes aren't removed.
* Array props (``file:bytes:ssdeeps``, ``risk:tool:software:soft:names``) are set to the values
  seen in the import, replacing (not adding to) values on existing nodes.
* ``file:bytes:name`` is set even when an existing node already has a name.
* Files only known by an MD5/SHA1 (ex. ThreatFox hash IOCs) always get a ``guid:`` file:bytes,
  where Storm would reuse an existing node with that hash.
"""

from collections.abc import Iterator
from typing import Any

import synapse.common as s_common
import synapse.exc as s_exc
import synapse.datamodel as s_datamodel
import synapse.lib.dyndeps as s_dyndeps
import synapse.lib.modules as s_modules

from .defs import EXT_PROPS, SOURCES


NORM_ERRORS = (s_exc.SynErr, ValueError, TypeError)
"""What normalizing a bad value with the data model can raise."""


PLATFORMS = {
    "bazaar": ("malwarebazaar", "https://bazaar.abuse.ch"),
    "urlhaus": ("urlhaus", "https://urlhaus.abuse.ch"),
    "threatfox": ("threatfox", "https://threatfox.abuse.ch"),
    "yaraify": ("yaraify", "https://yaraify.abuse.ch"),
    "feodo": ("feodo tracker", "https://feodotracker.abuse.ch"),
    "sslbl": ("ssl blacklist", "https://sslbl.abuse.ch"),
    "hunting": ("abuse.ch hunting", "https://hunting.abuse.ch"),
}
"""The inet:service:platform name and URL of each platform (see the Storm model's ``$platnames``)."""

BUILDER_VERSION = 1
"""Bumped when the nodes the builder creates change, recorded with each bulk import."""

Ndef = tuple[str, Any]


def buildModel() -> s_datamodel.Model:
    """A standalone Synapse data model with the service's extended props, for normalizing values."""

    model = s_datamodel.Model()
    defs = []
    for path in s_modules.coremods:
        defs.extend(s_dyndeps.getDynLocal(path).getModelDefs(None))
    model.addDataModels(defs)
    for prop, (ptype, doc) in EXT_PROPS.items():
        tdef = (
            ("hex", {"size": 96})
            if ptype == "hash:sha3_384"
            else ("str", {"strip": True, "lower": True})
        )
        model.addFormProp("file:bytes", prop, tdef, {"doc": doc})
    return model


class NodeBuilder:
    """Builds packed nodes for abuse.ch records, mirroring ``slib.abusech.model``.

    Nodes accumulate (and merge) until ``flush()`` returns them as nodedefs. Nodes that collect
    array values across many records (malware families) are held until ``finish()`` so their
    arrays aren't replaced batch by batch.
    """

    def __init__(self, model: s_datamodel.Model, prefix: str | None):
        self.model = model
        self.prefix = prefix
        self.nodes: dict[Ndef, dict] = {}
        self.held: dict[Ndef, dict] = {}
        self.arrays: dict[tuple[Ndef, str], set] = {}

    # ---- Packed node helpers ----

    def _info(self, ndef: Ndef, hold: bool = False) -> dict:
        nodes = self.held if hold or ndef in self.held else self.nodes
        info = nodes.get(ndef)
        if info is None:
            info = nodes[ndef] = {"props": {}, "tags": {}, "edges": set()}
        return info

    def node(self, form: str, valu: Any, hold: bool = False) -> Ndef | None:
        """Normalize a primary value (like ``[ form?=valu ]``). Returns the ndef, or None if it's invalid."""

        if valu in (None, ""):
            return None
        try:
            norm, _ = self.model.form(form).type.norm(valu)
        except NORM_ERRORS:
            return None
        ndef = (form, norm)
        self._info(ndef, hold=hold)
        return ndef

    def guid(self, form: str, props: dict, hold: bool = False) -> Ndef | None:
        """A guid node made from a dict of props (like ``[ form=({...}) ]``), with those props set."""

        formobj = self.model.form(form)
        norms = []
        for name, valu in props.items():
            try:
                norms.append((name, formobj.prop(name).type.norm(valu)[0]))
            except NORM_ERRORS:
                return None
        norms.sort()
        ndef = (form, s_common.guid(norms))
        info = self._info(ndef, hold=hold)
        info["props"].update(dict(norms))
        return ndef

    def prop(self, ndef: Ndef | None, name: str, valu: Any, ifunset: bool = False) -> None:
        """Set a prop (like ``[ :name ?= valu ]``), skipping invalid values."""

        if ndef is None or valu is None:
            return
        prop = self.model.form(ndef[0]).prop(name)
        if prop is None:
            return
        try:
            norm, _ = prop.type.norm(valu)
        except NORM_ERRORS:
            return
        props = self._info(ndef)["props"]
        if name == ".seen" and name in props:
            props[name] = (min(props[name][0], norm[0]), max(props[name][1], norm[1]))
        elif not (ifunset and name in props):
            props[name] = norm

    def addArray(self, ndef: Ndef | None, name: str, valu: Any) -> None:
        """Add a value to an array prop (like ``[ :name ?+= valu ]``)."""

        if ndef is None or valu is None:
            return
        prop = self.model.form(ndef[0]).prop(name)
        try:
            norm, _ = prop.type.arraytype.norm(valu)
        except NORM_ERRORS:
            return
        vals = self.arrays.setdefault((ndef, name), set())
        vals.add(norm)
        self._info(ndef)["props"][name] = tuple(sorted(vals))

    def tag(self, ndef: Ndef | None, tag: str, first: Any = None, last: Any = None) -> None:
        """Add a tag, with the time interval Storm's ``tagNode()`` would give it."""

        if ndef is None:
            return
        try:
            name, _ = self.model.type("syn:tag").norm(tag)
        except NORM_ERRORS:
            return
        ival = (None, None)
        times = [t for t in (first, last) if t]
        if times:
            try:
                ival, _ = self.model.type("ival").norm(
                    tuple(times) if len(times) == 2 else times[0]
                )
            except NORM_ERRORS:
                # Like Storm's +?#tag=ival, a tag with an invalid interval isn't added.
                return
        tags = self._info(ndef)["tags"]
        old = tags.get(name)
        if old is None or old == (None, None):
            tags[name] = ival
        elif ival != (None, None):
            tags[name] = (min(old[0], ival[0]), max(old[1], ival[1]))

    def tags(
        self, ndef: Ndef | None, plat: str, tags: Any, first: Any = None, last: Any = None
    ) -> None:
        """Apply abuse.ch tags as ``<prefix>.<plat>.<tag>`` (see the Storm model's ``tagNode()``)."""

        if self.prefix is None or not tags or ndef is None:
            return
        for tag in tags:
            if tag:
                self.tag(ndef, f"{self.prefix}.{plat}.{tag}", first, last)

    def edge(self, n1: Ndef | None, verb: str, n2: Ndef | None) -> None:
        if n1 is None or n2 is None:
            return
        self._info(n1)["edges"].add((verb, n2))

    def seen(
        self, ndef: Ndef | None, plat: str, first: Any = None, last: Any = None
    ) -> Ndef | None:
        """Link a node to the platform's meta:source and update its .seen (see ``seen()``)."""

        if ndef is None:
            return None
        self.edge(("meta:source", SOURCES[plat][0]), "seen", ndef)
        if first:
            self.prop(ndef, ".seen", first)
        if last:
            self.prop(ndef, ".seen", last)
        return ndef

    # ---- Observables ----

    def ipNode(self, ip: str, plat: str, first=None, last=None) -> Ndef | None:
        form = "inet:ipv6" if ":" in str(ip) else "inet:ipv4"
        return self.seen(self.node(form, ip), plat, first, last)

    def serverNode(self, ip: str, port: int, plat: str, first=None, last=None) -> Ndef | None:
        server = f"tcp://[{ip}]:{port}" if ":" in str(ip) else f"tcp://{ip}:{port}"
        return self.seen(self.node("inet:server", server), plat, first, last)

    def refNode(self, url: str | None, ndef: Ndef | None, plat: str) -> Ndef | None:
        if not url or ndef is None:
            return None
        ref = self.seen(self.node("inet:url", url), plat)
        self.edge(ref, "refs", ndef)
        return ref

    def obsNode(self, obs: dict | None, plat: str, first=None, last=None) -> Ndef | None:
        if obs is None:
            return None
        form = obs["form"]
        if form == "file:bytes":
            return self.fileNode(obs["hashes"], plat, first, last)
        if form == "inet:server":
            self.ipNode(obs["ip"], plat, first, last)
            return self.serverNode(obs["ip"], obs["port"], plat, first, last)
        if form in ("inet:ipv4", "inet:ipv6"):
            return self.ipNode(obs["valu"], plat, first, last)
        return self.seen(self.node(form, obs["valu"]), plat, first, last)

    # ---- Files ----

    def fileNode(self, hashes: dict, plat: str, first=None, last=None) -> Ndef | None:
        if hashes.get("sha256"):
            ndef = self.node("file:bytes", hashes["sha256"])
        else:
            for htype in ("sha1", "md5", "sha3_384"):
                if hashes.get(htype):
                    ndef = self.node("file:bytes", f"guid:{s_common.guid((htype, hashes[htype]))}")
                    break
            else:
                return None
        if ndef is None:
            return None
        for htype in ("md5", "sha1", "sha256"):
            self.prop(ndef, htype, hashes.get(htype))
        self.seen(ndef, plat, first, last)
        self.prop(ndef, "_sha3_384", hashes.get("sha3_384"))
        return ndef

    def family(
        self,
        plat: str,
        name: str | None,
        tagname: str | None = None,
        aliases: Any = None,
        id: str | None = None,
        url: str | None = None,
    ) -> Ndef | None:
        """A malware family as a risk:tool:software (see ``family()``). Held until ``finish()``."""

        if not name:
            return None
        if tagname and self.prefix:
            ndef = self.guid(
                "risk:tool:software", {"tag": f"{self.prefix}.{plat}.{tagname}"}, hold=True
            )
        else:
            ndef = self.guid(
                "risk:tool:software", {"soft:name": name, "reporter:name": "abuse.ch"}, hold=True
            )
        if ndef is None:
            return None
        self.prop(ndef, "soft:name", name)
        self.prop(ndef, "reporter:name", "abuse.ch")
        self.prop(ndef, "type", "malware")
        self.prop(ndef, "id", id)
        self.seen(ndef, plat)
        for alias in aliases or ():
            self.addArray(ndef, "soft:names", alias)
        self.addArray(ndef, "soft:names", name)
        self.refNode(url, ndef, plat)
        return ndef

    def reporter(self, name: str | None, ndef: Ndef | None, plat: str) -> Ndef | None:
        if not name or ndef is None:
            return None
        pname, purl = PLATFORMS[plat]
        platform = self.guid("inet:service:platform", {"name": pname})
        self.prop(platform, "url", purl)
        account = self.guid("inet:service:account", {"platform": platform[1], "user": name})
        self.edge(account, "seen", ndef)
        return account

    def scan(self, file: Ndef, sc: dict, plat: str) -> Ndef | None:
        props = {"target:file": file[1], "scanner:name": sc["vendor"]}
        if sc.get("signame"):
            props["signame"] = sc["signame"]
        ndef = self.guid("it:av:scan:result", props)
        self.prop(ndef, "signame", sc.get("signame"))
        self.prop(ndef, "verdict", sc.get("verdict"))
        self.prop(ndef, "time", sc.get("time"))
        self.prop(ndef, "multi:count", sc.get("count"))
        self.prop(ndef, "multi:count:malicious", sc.get("malicious"))
        self.seen(ndef, plat)
        for cat in sc.get("categories") or ():
            self.addArray(ndef, "categories", str(cat).lower())
        self.refNode(sc.get("link"), file, plat)
        return ndef

    def sample(self, s: dict | None, plat: str) -> Ndef | None:
        """A file:bytes from a normalized export sample (see ``sample()``)."""

        if s is None:
            return None
        first, last = s.get("first_seen"), s.get("last_seen")
        file = self.fileNode(s, plat, first, last)
        if file is None:
            return None

        self.prop(file, "size", s.get("size"))
        self.prop(file, "mime", s.get("mime"))
        self.prop(file, "mime:pe:imphash", s.get("imphash"))
        self.prop(file, "name", s.get("name"), ifunset=True)
        if s.get("ssdeep"):
            self.addArray(file, "ssdeeps", s["ssdeep"])
        for key, prop in (
            ("sha3_384", "_sha3_384"),
            ("tlsh", "_tlsh"),
            ("telfhash", "_telfhash"),
            ("gimphash", "_gimphash"),
            ("dhash_icon", "_dhash_icon"),
        ):
            self.prop(file, prop, s.get(key))

        self.tags(file, plat, s.get("tags"), first, last)
        self.tags(file, plat, s.get("families"), first, last)
        if s.get("type"):
            self.tags(file, plat, (f"type.{s['type']}",))
        if s.get("delivery_method"):
            self.tags(file, plat, (f"delivery.{s['delivery_method']}",), first)
        if s.get("origin_country"):
            self.tags(file, plat, (f"origin.{s['origin_country']}",), first)
        self.tags(file, plat, s.get("attrs"))

        if s.get("signature"):
            self.family(plat, s["signature"], (s.get("families") or [None])[0])
        self.reporter(s.get("reporter"), file, plat)

        for sig in s.get("clamav") or ():
            self.scan(file, {"vendor": "clamav", "signame": sig, "verdict": 40}, plat)
        for sc in s.get("scans") or ():
            self.scan(file, sc, plat)
        for link in s.get("links") or ():
            self.refNode(link["url"], file, plat)
        return file

    # ---- URLhaus ----

    def url(self, u: dict | None, plat: str = "urlhaus") -> Ndef | None:
        """An inet:url from a normalized URLhaus URL (see ``url()``)."""

        if u is None:
            return None
        first, last = u.get("added"), u.get("last_online")
        urlnode = self.seen(self.node("inet:url", u["url"]), plat, first, last)
        if urlnode is None:
            return None

        if u.get("threat"):
            self.tags(urlnode, plat, (u["threat"],), first, last)
        self.tags(urlnode, plat, u.get("tags"), first, last)
        if u.get("status"):
            self.tags(urlnode, plat, (f"status.{u['status']}",), first, last)
        if u.get("larted"):
            self.tags(urlnode, plat, ("larted",))

        if u.get("host"):
            host = self.obsNode(u["host"], plat, first)
            self.tags(host, plat, u.get("blacklists"))

        self.refNode(u.get("reference"), urlnode, plat)
        self.reporter(u.get("reporter"), urlnode, plat)

        for pay in u.get("payloads") or ():
            file = self.sample(pay, plat)
            if file is not None:
                self.seen(
                    self.node("inet:urlfile", (urlnode[1], file[1])),
                    plat,
                    pay.get("seen"),
                    pay.get("last"),
                )
        return urlnode

    # ---- ThreatFox ----

    def ioc(self, i: dict | None, plat: str = "threatfox") -> Ndef | None:
        """The observable for a normalized ThreatFox IOC (see ``ioc()`` and ``indicator()``)."""

        if i is None:
            return None
        first, last = i.get("first_seen"), i.get("last_seen")
        obs = self.obsNode(i.get("obs"), plat, first, last)
        if obs is None:
            return None

        tags = []
        if i.get("threat_type"):
            tags.append(i["threat_type"])
        if i.get("family_tag"):
            tags.append(i["family_tag"])
        tags.extend(i.get("tags") or ())
        if i.get("compromised"):
            tags.append("compromised")
        self.tags(obs, plat, tags, first, last)

        if i.get("id"):
            desc = i.get("threat_type_desc")
            if i.get("comment"):
                desc = f"{desc}\n\n{i['comment']}" if desc else i["comment"]
            labels = []
            if i.get("threat_type"):
                labels.append(i["threat_type"])
            if i.get("family_tag"):
                labels.append(i["family_tag"])
            labels.extend(i.get("tags") or ())

            ind = self.guid("it:sec:stix:indicator", {"id": f"{plat}--{i['id']}"})
            self.prop(ind, "name", f"{plat} IOC {i['id']}: {i['ioc']}")
            self.prop(ind, "confidence", i.get("confidence"))
            self.prop(ind, "description", desc)
            self.prop(ind, "pattern", i.get("pattern"))
            self.prop(ind, "pattern_type", "stix")
            self.prop(ind, "created", first)
            self.prop(ind, "updated", last)
            self.prop(ind, "valid_from", first)
            self.prop(ind, "labels", labels)
            self.seen(ind, plat, first, last)
            self.edge(ind, "refs", obs)
            self.refNode(i.get("reference"), ind, plat)

        if i.get("family"):
            self.family(
                plat,
                i["family"],
                i.get("family_tag"),
                i.get("aliases"),
                i.get("malware"),
                i.get("malpedia"),
            )
        self.reporter(i.get("reporter"), obs, plat)

        for s in i.get("samples") or ():
            file = self.sample(s, plat)
            self.edge(file, "refs", obs)
            if i.get("family_tag"):
                self.tags(file, plat, (i["family_tag"],), s.get("seen"))
        return obs

    # ---- Output ----

    @staticmethod
    def _pack(nodes: dict[Ndef, dict]) -> Iterator[tuple]:
        for ndef, info in nodes.items():
            packed = {"props": info["props"], "tags": info["tags"]}
            if info["edges"]:
                packed["edges"] = sorted(info["edges"], key=repr)
            yield (ndef, packed)

    def flush(self) -> list[tuple]:
        """Return the accumulated nodes as ``syn.nodes`` nodedefs and start a new batch."""

        nodes, self.nodes = self.nodes, {}
        # Only held nodes' arrays accumulate across batches; the rest are complete once flushed.
        self.arrays = {k: v for k, v in self.arrays.items() if k[0] in self.held}
        # Held nodes are kept, but their edges (to this batch's nodes) go out with the batch.
        for ndef, info in self.held.items():
            if info["edges"]:
                nodes.setdefault(ndef, {"props": {}, "tags": {}, "edges": set()})["edges"] |= info[
                    "edges"
                ]
                info["edges"] = set()
        return list(self._pack(nodes))

    def finish(self) -> list[tuple]:
        """Return the remaining nodes, including the held ones with their complete arrays."""

        nodes = self.flush()
        held, self.held = self.held, {}
        return nodes + list(self._pack(held))

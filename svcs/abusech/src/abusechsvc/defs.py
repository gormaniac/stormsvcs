"""The Python definition of the slib.abusech Storm package."""


from stormlibpp import StormPkg

from . import __version__


SVC_NAME = "slib.abusech"
SVC_VER = __version__
SVC_GUID = "07574885b1dd44518f554cc7356d056a"
SVC_SYN_MIN_VER = (2, 137, 0)

SOURCES = {
    "bazaar": ("0880c1df548847f591cc4d25071e8ec7", "MalwareBazaar", "https://bazaar.abuse.ch"),
    "urlhaus": ("30f3e2d0445842dc998e5d84667730d5", "URLhaus", "https://urlhaus.abuse.ch"),
    "threatfox": ("72093b870fba45978e5a725ccf5d4af7", "ThreatFox", "https://threatfox.abuse.ch"),
    "yaraify": ("dfe12ed859bf4bbea106c0f9cec44fa8", "YARAify", "https://yaraify.abuse.ch"),
    "feodo": ("a4449303c07f41f782aa730f8d449033", "Feodo Tracker", "https://feodotracker.abuse.ch"),
    "sslbl": ("af7571ed96af44cba0ceab4b6bf44c5b", "SSL Blacklist", "https://sslbl.abuse.ch"),
    "hunting": ("2f9357321acd42188845ba7c95bf6471", "abuse.ch Hunting", "https://hunting.abuse.ch"),
}
"""The meta:source (guid, name, url) for each abuse.ch platform, keyed by the platform's short name."""

EXT_PROPS = {
    "_sha3_384": ("hash:sha3_384", "The SHA3-384 hash of the file."),
    "_tlsh": ("str", "The TLSH fuzzy hash of the file."),
    "_telfhash": ("str", "The telfhash (ELF symbol fuzzy hash) of the file."),
    "_gimphash": ("str", "The gimphash (Go import hash) of the file."),
    "_dhash_icon": ("str", "The dhash (perceptual hash) of the file's icon."),
}
"""Extended file:bytes props added for the fuzzy hashes abuse.ch provides that Synapse doesn't model."""


def _addStorm() -> str:
    """The Storm run when the service is added to a Cortex (as root)."""

    lines = []
    for plat, (guid, name, url) in SOURCES.items():
        lines.append(f'[ meta:source={guid} :name="{name.lower()}" :type=slib.abusech.{plat} :url={url} ] | spin |')
    for prop, (ptype, doc) in EXT_PROPS.items():
        if ptype == "hash:sha3_384":
            # Synapse doesn't have a SHA3 hash type, a 96 char hex string works everywhere.
            typedef = "(['hex', {'size': 96}])"
        else:
            typedef = "(['str', {'strip': true, 'lower': true}])"
        lines.append(
            f'if (not $lib.model.prop("file:bytes:{prop}")) {{ '
            f'$lib.model.ext.addFormProp(file:bytes, {prop}, {typedef}, ({{"doc": "{doc}"}})) }}'
        )
    lines.append(
        'if ($lib.globals.get("slib:abusech:tag:enabled") = $lib.null) { '
        '$lib.globals.set("slib:abusech:tag:enabled", (true)) }'
    )
    lines.append(
        'if ($lib.globals.get("slib:abusech:tag:prefix") = $lib.null) { '
        '$lib.globals.set("slib:abusech:tag:prefix", "rep.abusech") }'
    )
    return "\n".join(lines)


SVC_EVTS = {"add": {"storm": _addStorm()}}


class SlibAbuseChPkg(StormPkg):
    """The slib.abusech Storm package for the abuse.ch service."""

    proto_name = SVC_NAME


PKGDEFS = (SlibAbuseChPkg().asdict(),)

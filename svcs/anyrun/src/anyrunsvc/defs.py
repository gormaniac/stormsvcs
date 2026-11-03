"""The Python definition of the slib.anyrun Storm package."""

from stormlibpp import StormPkg

from . import __version__

SVC_NAME = "slib.anyrun"
SVC_VER = __version__

SOURCE_GUID = "efe78724dcaf411b87b8b34cf6fe589e"
"""The guid of the meta:source node every modeled node is linked to with a -(seen)> edge."""

SVC_EVTS = {
    "add": {
        "storm": (
            f"[(meta:source={SOURCE_GUID} :name=any.run :type=slib.anyrun "
            ":url=https://any.run)] | spin | "
            'if ($lib.globals.get("slib:anyrun:tag:enabled") = $lib.null) { '
            '    $lib.globals.set("slib:anyrun:tag:enabled", (true)) '
            "} "
            'if ($lib.globals.get("slib:anyrun:tag:prefix") = $lib.null) { '
            '    $lib.globals.set("slib:anyrun:tag:prefix", "rep.anyrun") '
            "}"
        )
    }
}


class SlibAnyRunPkg(StormPkg):
    """The slib.anyrun Storm package for the ANY.RUN service."""

    proto_name = SVC_NAME


PKGDEFS = (SlibAnyRunPkg().asdict(),)

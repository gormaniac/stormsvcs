"""The Python definition of the slib.hatching Storm package."""

from stormlibpp import StormPkg

from . import __version__

SVC_NAME = "slib.hatching"
SVC_VER = __version__
SVC_GUID = "b6c643155da441bf8c9cc407073f7243"
SVC_SYN_MIN_VER = (2, 137, 0)

SOURCE_GUID = "76172c35a9074f998791a9d2b69ff6d8"
"""The guid of the meta:source node every modeled node is linked to with a -(seen)> edge."""

SVC_EVTS = {
    "add": {
        "storm": (
            f'[(meta:source={SOURCE_GUID} :name="hatching triage" :type=slib.hatching '
            ":url=https://tria.ge)] | spin | "
            'if ($lib.globals.get("slib:hatching:tag:enabled") = $lib.null) { '
            '    $lib.globals.set("slib:hatching:tag:enabled", (true)) '
            "} "
            'if ($lib.globals.get("slib:hatching:tag:prefix") = $lib.null) { '
            '    $lib.globals.set("slib:hatching:tag:prefix", "rep.hatching") '
            "}"
        )
    }
}


class SlibHatchingPkg(StormPkg):
    """The slib.hatching Storm package for the Hatching Triage service."""

    proto_name = SVC_NAME


PKGDEFS = (SlibHatchingPkg().asdict(),)

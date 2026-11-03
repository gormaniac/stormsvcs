"""The Python definition of the slib.vt Storm package."""

from stormlibpp import StormPkg

from . import __version__

SVC_NAME = "slib.vt"
SVC_VER = __version__

# The guid of the slib.vt meta:source node.
SVC_GUID = "176fcd24cf1f42bfa5d95a013eec1487"

SVC_EVTS = {
    "add": {
        # Runs once, as root, when the service is first added to a Cortex.
        "storm": (
            f"[(meta:source={SVC_GUID} :name=virustotal :type=slib.vt "
            ":url=https://www.virustotal.com)] | spin | "
            'if ($lib.globals.get("slib:vt:tag:enabled") = $lib.null) { '
            '    $lib.globals.set("slib:vt:tag:enabled", (true)) '
            "} "
            'if ($lib.globals.get("slib:vt:tag:prefix") = $lib.null) { '
            '    $lib.globals.set("slib:vt:tag:prefix", "rep.vt") '
            "}"
        )
    }
}


class SlibVtPkg(StormPkg):
    """The slib.vt Storm package for the VirusTotal service."""

    proto_name = SVC_NAME


PKGDEFS = (SlibVtPkg().asdict(),)

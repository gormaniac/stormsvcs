"""The Python definition of the slib.crtsh Storm package."""

from stormlibpp import StormPkg

from . import __version__

SVC_NAME = "slib.crtsh"
SVC_VER = __version__
SVC_GUID = "c7357722661f45a4b81c91ccfbbb37c0"
"""The guid of the slib.crtsh meta:source node. Storm reads it from the model module's modconf."""

SVC_EVTS = {
    "add": {
        "storm": (
            f'[(meta:source={SVC_GUID} :name="crt.sh" :type=slib.crtsh :url=https://crt.sh)] | spin | '
            'if ($lib.globals.get("slib:crtsh:tag:enabled") = $lib.null) { '
            '    $lib.globals.set("slib:crtsh:tag:enabled", (true)) '
            "} "
            'if ($lib.globals.get("slib:crtsh:tag:prefix") = $lib.null) { '
            '    $lib.globals.set("slib:crtsh:tag:prefix", "rep.crtsh") '
            "}"
        )
    }
}


class SlibCrtshPkg(StormPkg):
    """The slib.crtsh Storm package for the crtsh service."""

    proto_name = SVC_NAME


def _pkgdef() -> dict:
    pkgdef = SlibCrtshPkg().asdict()
    for mdef in pkgdef["modules"]:
        if mdef["name"] == "slib.crtsh.model":
            mdef["modconf"] = {"source": SVC_GUID}
    return pkgdef


PKGDEFS = (_pkgdef(),)

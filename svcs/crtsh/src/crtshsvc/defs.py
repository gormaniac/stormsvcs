"""The Python definition of the slib.crtsh Storm package."""

from stormlibpp import StormPkg

from . import __version__

SVC_NAME = "slib.crtsh"
SVC_VER = __version__
SVC_GUID = "c7357722661f45a4b81c91ccfbbb37c0"
SVC_SYN_MIN_VER = (2, 145, 0)

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


PKGDEFS = (SlibCrtshPkg().asdict(),)

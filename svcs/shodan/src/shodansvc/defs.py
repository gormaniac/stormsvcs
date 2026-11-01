"""The Python definition of the slib.shodan Storm package."""

from stormlibpp import StormPkg

from . import __version__

SVC_NAME = "slib.shodan"
SVC_VER = __version__
SVC_GUID = "5c1b0a3d0e7f4b2e9a8c6d4f2b1e0a97"
SVC_SYN_MIN_VER = (2, 145, 0)

SVC_EVTS = {
    "add": {
        "storm": (
            f'[(meta:source={SVC_GUID} :name="shodan" :type=slib.shodan :url=https://www.shodan.io)] | spin | '
            'if ($lib.globals.get("slib:shodan:tag:enabled") = $lib.null) { '
            '    $lib.globals.set("slib:shodan:tag:enabled", (true)) '
            "} "
            'if ($lib.globals.get("slib:shodan:tag:prefix") = $lib.null) { '
            '    $lib.globals.set("slib:shodan:tag:prefix", "rep.shodan") '
            "}"
        )
    }
}


class SlibShodanPkg(StormPkg):
    """The slib.shodan Storm package for the shodan service."""

    proto_name = SVC_NAME


PKGDEFS = (SlibShodanPkg().asdict(),)

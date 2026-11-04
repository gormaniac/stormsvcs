"""The Python definition of the slib.bgphe Storm package."""

from stormlibpp import StormPkg

from . import __version__

SVC_NAME = "slib.bgphe"
SVC_VER = __version__

# The guid of the slib.bgphe meta:source node.
SVC_GUID = "5cb263934371467b8844e789c39f81aa"

SVC_EVTS = {
    "add": {
        # Runs once, as root, when the service is first added to a Cortex.
        "storm": (
            f'[(meta:source={SVC_GUID} :name="bgp.he.net" :type=slib.bgphe '
            ":url=https://bgp.he.net)]"
        )
    }
}


class SlibBgpHePkg(StormPkg):
    """The slib.bgphe Storm package for the bgphe service."""

    proto_name = SVC_NAME


PKGDEFS = (SlibBgpHePkg().asdict(),)

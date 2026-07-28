"""The Python definition of the ipapi Storm package."""


from stormlibpp import StormPkg

from . import __version__


SVC_NAME = "slib.ip-api"
SVC_VER = __version__
SVC_GUID = "c177b2a9c0eff5c2984946d439de23ea"
SVC_SYN_MIN_VER = (2, 137, 0)

SVC_EVTS = {
    "add": {
        "storm": (
            f'[(meta:source={SVC_GUID} :name={SVC_NAME})] ',
            '$lib.globals.set("slib:ip-api:tag:enabled", (true))'
        )
    }
}


class SlibIpApiPkg(StormPkg):
    """The slib.ip-api Storm package for the ipapi service."""

    proto_name = SVC_NAME


PKGDEFS = (SlibIpApiPkg().asdict(),)


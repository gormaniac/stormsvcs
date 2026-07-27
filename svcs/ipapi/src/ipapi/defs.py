"""The Python definition of the ipapi Storm package."""


from stormlibpp import StormPkg

from . import __version__


SVC_NAME = "slib.ipapi"
SVC_VER = __version__
SVC_GUID = "7b5869b5bcd8a9154163c2874f93f12a"
SVC_SYN_MIN_VER = (2, 137, 0)

SVC_EVTS = {
    "add": {
        "storm": f'[(meta:source={SVC_GUID} :name={SVC_NAME})]'
    }
}


class SlibIpApiPkg(StormPkg):
    """The slib.ipapi Storm package for the ipapi service."""

    proto_name = SVC_NAME


PKGDEFS = (SlibIpApiPkg().asdict(),)


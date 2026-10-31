"""The Python definition of the slib.capa Storm package."""

from stormlibpp import StormPkg

from . import __version__


SVC_NAME = "slib.capa"
SVC_VER = __version__
SVC_GUID = "ee5999b4059645168272e22d7cd087e3"
"""The guid of the slib.capa ``meta:source`` node."""
SVC_SYN_MIN_VER = (2, 137, 0)

RULES_VERSION = "v10.0.0"
"""The capa-rules release bundled with this version of the service (it matches flare-capa)."""

RULES_URL = "https://github.com/mandiant/capa-rules/blob/{version}/{path}"
"""The default template of a rule's URL, given the rules ``version`` and the rule's ``path``."""

SVC_EVTS = {
    "add": {
        "storm": (
            f'[(meta:source={SVC_GUID} :name="capa" :type=slib.capa '
            ":url=https://github.com/mandiant/capa)]"
        )
    }
}


class SlibCapaPkg(StormPkg):
    """The slib.capa Storm package for the capa service."""

    proto_name = SVC_NAME


PKGDEFS = (SlibCapaPkg().asdict(),)

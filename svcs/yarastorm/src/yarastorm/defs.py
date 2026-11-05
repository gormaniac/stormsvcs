"""The Python definition of the yarastorm Storm package."""

from stormlibpp import StormPkg

from . import __version__

SVC_NAME = "slib.yara"
"""The name of the service and its Storm package."""

SVC_VER = __version__
"""The version of the service and its Storm package."""

SVC_GUID = "12bc0c8c1a37a29808d97972875d3913"
"""The guid of the service's meta:source node, also hard coded in slib.yara.ingest."""

ADMIN_PERM = ("slib", "yara", "admin")
"""The permission needed to change the rules that the service scans with."""

SVC_EVTS = {"add": {"storm": f"[(meta:source={SVC_GUID} :name={SVC_NAME})]"}}
"""Storm that runs when the service is first added to a Cortex."""


class SlibYaraPkg(StormPkg):
    """The slib.yara Storm package for the yarastorm service."""

    proto_name = SVC_NAME


PKGDEFS = (SlibYaraPkg().asdict(),)
"""The Storm packages the service loads into the Cortex."""

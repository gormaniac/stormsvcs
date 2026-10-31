"""The Python definition of the slib.pcap Storm package."""


from stormlibpp import StormPkg

from . import __version__


SVC_NAME = "slib.pcap"
"""The name of the service and its Storm package."""
SVC_VER = __version__
"""The service's version."""
SVC_GUID = "cae9b5f5923a48b9a1a691f851a77429"
"""The guid of the service's meta:source node."""
SVC_SYN_MIN_VER = (2, 137, 0)
"""The minimum Synapse version the service supports."""

SVC_EVTS = {
    "add": {
        "storm": f'[(meta:source={SVC_GUID} :name="slib.pcap" :type=slib.pcap)]'
    }
}
"""Storm that runs when the service is added to a Cortex."""


class SlibPcapPkg(StormPkg):
    """The slib.pcap Storm package for the pcap service."""

    proto_name = SVC_NAME


PKGDEFS = (SlibPcapPkg().asdict(),)
"""The Storm packages the service loads into the Cortex."""

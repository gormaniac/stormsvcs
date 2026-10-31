"""The Python definition of the slib.pcap Storm package."""

from stormlibpp import StormPkg

from . import __version__

SVC_NAME = "slib.pcap"
"""The name of the service and its Storm package."""
SVC_VER = __version__
"""The service's version."""
SVC_GUID = "cae9b5f5923a48b9a1a691f851a77429"
"""The guid of the service's meta:source node."""
SVC_SYN_MIN_VER = (2, 234, 0)
"""The minimum Synapse version the service supports."""

SYNC_PERIOD = "hourly@:17"
"""The default schedule (a cron.add --period) of the slib.pcap.sync cron job."""

SYNC_QUERY = "slib.pcap.sync"
"""The Storm the scheduled sync cron job runs."""

SYNC_DOC = (
    "Sync the slib.pcap rule feeds into the Cortex and push the enabled it:app:snort:rule "
    "and it:app:suricata:rule nodes to the slib.pcap service."
)
"""The doc of the slib.pcap.sync cron job."""

CRON_GLOBAL = "slib:pcap:cron"
"""The Storm global that holds the iden of the scheduled sync cron job."""


def _addStorm() -> str:
    """The Storm run when the service is added to a Cortex (as root).

    Creates the service's meta:source and the cron job that keeps the Cortex's feeds and the
    service's rules in sync (see slib.pcap.admin.schedule).
    """

    return f"""
    [ meta:source={SVC_GUID} :name="slib.pcap" :type=slib.pcap ]
    spin |
    if (not $lib.globals.get({CRON_GLOBAL})) {{
        $cron = $lib.cron.add(query="{SYNC_QUERY}", period="{SYNC_PERIOD}")
        $cron.set(name, "slib.pcap.sync")
        $cron.set(doc, "{SYNC_DOC}")
        $lib.globals.set({CRON_GLOBAL}, $cron.iden)
    }}
    """


def _delStorm() -> str:
    """The Storm run when the service is removed from a Cortex, removes the sync cron job."""

    return f"""
    $iden = $lib.globals.pop({CRON_GLOBAL})
    if $iden {{
        try {{ $lib.cron.del($iden) }} catch * as err {{ }}
    }}
    """


SVC_EVTS = {
    "add": {"storm": _addStorm()},
    "del": {"storm": _delStorm()},
}
"""Storm that runs when the service is added to, or removed from, a Cortex."""


class SlibPcapPkg(StormPkg):
    """The slib.pcap Storm package for the pcap service."""

    proto_name = SVC_NAME


PKGDEFS = (SlibPcapPkg().asdict(),)
"""The Storm packages the service loads into the Cortex."""

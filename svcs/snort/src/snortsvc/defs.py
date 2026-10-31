"""The Python definition of the slib.snort Storm package."""

from stormlibpp import StormPkg

from . import __version__

SVC_NAME = "slib.snort"
SVC_VER = __version__
SVC_GUID = "325168602368411eb9fda9657114c085"
"""The guid of the service's meta:source."""

SVC_SYN_MIN_VER = (2, 234, 0)

SYNC_PERIOD = "hourly@:17"
"""The default schedule (a cron.add --period) of the slib.snort.sync cron job."""

SYNC_QUERY = "slib.snort.sync"
"""The Storm the scheduled sync cron job runs."""

SYNC_DOC = (
    "Sync the slib.snort rule feeds into the Cortex and push the enabled "
    "it:app:snort:rule nodes to the slib.snort service."
)
"""The doc of the slib.snort.sync cron job."""

CRON_GLOBAL = "slib:snort:cron"
"""The Storm global that holds the iden of the scheduled sync cron job."""


def _addStorm() -> str:
    """The Storm run when the service is added to a Cortex (as root).

    Creates the service's meta:source and the cron job that keeps the Cortex's feeds and the
    service's rules in sync (see slib.snort.admin.schedule).
    """

    return f"""
    [ meta:source={SVC_GUID} :name="slib.snort" :type=slib.snort ]
    spin |
    if (not $lib.globals.get({CRON_GLOBAL})) {{
        $cron = $lib.cron.add(query="{SYNC_QUERY}", period="{SYNC_PERIOD}")
        $cron.set(name, "slib.snort.sync")
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


class SlibSnortPkg(StormPkg):
    """The slib.snort Storm package for the Snort service."""

    proto_name = SVC_NAME


PKGDEFS = (SlibSnortPkg().asdict(),)

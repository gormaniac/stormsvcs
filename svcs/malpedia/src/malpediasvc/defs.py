"""The Python definition of the slib.malpedia Storm package."""

from stormlibpp import StormPkg

from . import __version__

SVC_NAME = "slib.malpedia"
SVC_VER = __version__

# The guid of the slib.malpedia meta:source node.
SVC_GUID = "15b7f8ff9cef4e8fa9fedd9f2b10c1a5"

# The one time cron job the add event starts: unless malpedia:autosync is off, schedule the
# daily sync and run the initial sync.
AUTO_QUERY = "if $lib.import(slib.malpedia.priv.admin).autoSchedule() { slib.malpedia.sync }"

SVC_EVTS = {
    "add": {
        # Runs once, as root, when the service is first added to a Cortex. It sets up the
        # meta:source and default settings, then (unless malpedia:autosync is off) schedules
        # the daily sync and starts the initial one in the background.
        "storm": (
            f"$autoquery = {AUTO_QUERY!r} "
            f"[(meta:source={SVC_GUID} :name=malpedia :type=slib.malpedia "
            ":url=https://malpedia.caad.fkie.fraunhofer.de)] | spin | "
            'if ($lib.globals.get("slib:malpedia:tag:prefix") = $lib.null) { '
            '    $lib.globals.set("slib:malpedia:tag:prefix", "rep.malpedia") '
            "} "
            'if ($lib.globals.get("slib:malpedia:tag:tlp") = $lib.null) { '
            '    $lib.globals.set("slib:malpedia:tag:tlp", "rep.malpedia.tlp") '
            "} "
            # The service isn't ready while this runs, so a one time cron job does the rest.
            "$job = $lib.cron.at(query=$autoquery, now=(true)) "
            '$job.set(name, "slib.malpedia (initial setup and sync)")'
        )
    }
}


class SlibMalpediaPkg(StormPkg):
    """The slib.malpedia Storm package for the malpedia service."""

    proto_name = SVC_NAME


PKGDEFS = (SlibMalpediaPkg().asdict(),)

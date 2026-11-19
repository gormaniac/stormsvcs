"""The Python definition of the slib.malpedia Storm package."""

import json

from stormlibpp import StormPkg

from . import __version__

SVC_NAME = "slib.malpedia"
SVC_VER = __version__

# The guid of the slib.malpedia meta:source node.
SVC_GUID = "15b7f8ff9cef4e8fa9fedd9f2b10c1a5"

# The one time cron job the add event starts: unless malpedia:autosync is off, schedule the
# daily sync and run the initial sync.
AUTO_QUERY = "if $lib.import(slib.malpedia.priv.admin).autoSchedule() { slib.malpedia.sync }"

# The name of that one time cron job.
SETUP_JOB = "slib.malpedia (initial setup and sync)"


def stormStr(text: str) -> str:
    """A Storm double quoted string literal for text."""

    # json.dumps escapes quotes, backslashes, and control characters the same way Storm's
    # double quoted strings unescape them. Non-ASCII would become \uXXXX, keep it ASCII.
    if not text.isascii():
        raise ValueError(f"Storm string literals here must be ASCII: {text!r}")
    return json.dumps(text)


SVC_EVTS = {
    "add": {
        # Runs once, as root, when the service is added to a Cortex (again after a
        # service.del, the Cortex gives a re-added service a new iden). It sets up the
        # meta:source and default settings, then starts the setup job, which (unless
        # malpedia:autosync is off) schedules the daily sync and runs the initial one.
        "storm": (
            f"$autoquery = {stormStr(AUTO_QUERY)} "
            f"[(meta:source={SVC_GUID} :name=malpedia :type=slib.malpedia "
            ":url=https://malpedia.caad.fkie.fraunhofer.de)] | spin | "
            'if ($lib.globals.get("slib:malpedia:tag:prefix") = null) { '
            '    $lib.globals.set("slib:malpedia:tag:prefix", "rep.malpedia") '
            "} "
            'if ($lib.globals.get("slib:malpedia:tag:tlp") = null) { '
            '    $lib.globals.set("slib:malpedia:tag:tlp", "rep.malpedia.tlp") '
            "} "
            # Setup jobs an earlier service.del couldn't delete would never run again.
            "for $old in $lib.cron.list() { "
            f"    if ($old.pack().name = {stormStr(SETUP_JOB)}) {{ "
            "        try { $lib.cron.del($old.iden) } catch * as err { } "
            "    } "
            "} "
            # The service isn't ready while this runs, so a one time cron job does the rest. It
            # is created (and runs once) even when malpedia:autosync is off, because only the
            # service can read its config: then it doesn't schedule or sync anything.
            "$job = $lib.cron.at(query=$autoquery, now=(true)) "
            f"$job.set(name, {stormStr(SETUP_JOB)})"
        )
    },
    "del": {
        # Runs as root when the service is deleted, after its package is gone (so it can't use
        # the package's modules). Deletes the daily sync cron job (it would fail every day
        # without the service) and any setup jobs left behind. The tag settings are kept, so
        # adding the service again tags nodes the same way.
        "storm": (
            '$iden = $lib.globals.get("slib:malpedia:cron") '
            "if $iden { "
            "    try { $lib.cron.del($iden) } catch * as err { } "
            '    $lib.globals.pop("slib:malpedia:cron") '
            "} "
            "for $job in $lib.cron.list() { "
            f"    if ($job.pack().name = {stormStr(SETUP_JOB)}) {{ "
            "        try { $lib.cron.del($job.iden) } catch * as err { } "
            "    } "
            "}"
        )
    },
}


class SlibMalpediaPkg(StormPkg):
    """The slib.malpedia Storm package for the malpedia service."""

    proto_name = SVC_NAME


PKGDEFS = (SlibMalpediaPkg().asdict(),)

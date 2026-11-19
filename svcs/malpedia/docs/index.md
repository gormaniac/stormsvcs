# Malpedia

`slib.malpedia` is a Storm Service (a Synapse Advanced Power-Up) that keeps the public data of
[Malpedia](https://malpedia.caad.fkie.fraunhofer.de), Fraunhofer FKIE's malware corpus, in
sync with a Synapse Cortex. It models:

| Malpedia | Synapse form | Approximate size |
| --- | --- | --- |
| Library articles (BibTeX + references) | `media:news` | ~19k |
| Threat actors | `risk:threat` | ~1.1k |
| Malware families | `risk:tool:software` | ~3.8k |
| TLP:WHITE YARA rules | `it:app:yara:rule` | ~2.3k |

These are linked to each other with edges (`-(refs)>`, `-(uses)>`, `-(detects)>`,
`-(targets)>`) and tags (`rep.malpedia.threat.<actor>`, `rep.malpedia.mal.<family>`,
`rep.malpedia.tlp.<tlp>`). All of it is `-(seen)>` by the `malpedia` `meta:source`.

The service only uses Malpedia's API endpoints that need no account ("Access limitation:
none"). It never sends an API token and never scrapes the website. MISP data
(`/api/get/misp`), samples, scans, and ApiScout are out of scope.

## Features

- **One bulk pull, then small daily updates.** Registering the service (`service.add`) starts
  an initial sync that downloads everything once. A daily cron job then checks Malpedia's
  version (one tiny request) and only downloads the bulk data when the version changed. See
  [Syncing](syncing.md).
- **A local snapshot.** The service stores a normalized copy of Malpedia in its own LMDB slab.
  Modeling a new view, a `--full` re-model, and a tag prefix change all read the snapshot, not
  Malpedia.
- **Per-view change tracking.** The service remembers which version of every record each view
  has modeled. A sync models only what changed. It also undoes what an old version of a record
  added, for example a tag for an actor that an article is no longer about.
- **Safe failure.** Everything is downloaded and normalized before the snapshot changes. A
  pull that would remove more than half of a kind's records is refused unless it's forced.
- **Polite to upstream.** Requests are serialized and spaced `malpedia:interval` seconds
  apart. They send a `User-Agent` that names the service, and back off exponentially on
  errors.
- **On-demand refresh** of single actors or families (`slib.malpedia.refresh`) and a live
  name search (`slib.malpedia.search`).

## Architecture

```text
+-------------------+  Telepath  +--------------------------+  HTTPS (GET only)  +----------+
| Cortex            | <--------> | MalpediaSvc (Cell)       | -----------------> | Malpedia |
|  slib.malpedia    |  RetnApi   |  slab: info/snap/views   |  MalpediaClient    | /api/... |
|  Storm package    |  Telepath- |  norm.py, bib.py         |  throttle, retry   |          |
|  (commands, cron) |  Retn      |                          |                    |          |
+-------------------+            +--------------------------+                    +----------+
```

- The **Cell** ({src}`svcs/malpedia/src/malpediasvc/svc.py`) pulls Malpedia, normalizes it
  into records ({src}`svcs/malpedia/src/malpediasvc/norm.py`), stores the snapshot, and works
  out per-view diffs.
- The **Telepath API** ({src}`svcs/malpedia/src/malpediasvc/api.py`) is a
  `stormlibpp.svc.RetnApi`. Every call returns a `TelepathRetn` (`status`/`mesg`/`data`) and
  never raises to Storm. See [Telepath API](api.md).
- The **Storm package** `slib.malpedia` asks the service for changed records and turns them
  into nodes, tags and edges. It does this as root, inside privileged (`asroot`) modules, so
  users don't need node permissions on every form involved. See [Commands](commands.md) and
  [Data model](model.md).

## Quick start

1. Run the image (see [Deployment](deployment.md) for a full compose file):

   ```bash
   docker run -d --name malpedia \
       -e SYN_MALPEDIASVC_AUTH_PASSWD=secret \
       -v malpedia:/vertex/storage \
       -p 27492:27492 \
       ghcr.io/gormaniac/stormsvcs/malpedia:latest
   ```

2. Add it to the Cortex:

   ```text
   service.add slib.malpedia tcp://root:secret@malpedia:27492/
   service.list
   ```

   Adding the service creates the `malpedia` `meta:source` and the default tag settings. It
   also schedules the daily sync and starts the initial sync in the background, in the
   Cortex's default view. The initial sync takes about 10-15 minutes.

3. Grant analysts access:

   ```text
   auth.user.addrule analyst slib.malpedia.user
   auth.user.addrule analyst slib.malpedia.sync
   ```

4. Check on it, and use it:

   ```text
   slib.malpedia.status
   slib.malpedia.search "fancy bear"
   risk:threat:ext:id=apt28 -(uses)> risk:tool:software
   #rep.malpedia.mal.win.xagent
   ```

```{toctree}
:maxdepth: 2

deployment
commands
model
api
internals
syncing
```

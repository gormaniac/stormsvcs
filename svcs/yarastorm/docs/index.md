# Yara Storm

Yara Storm (`yarastorm`) is a Synapse Advanced Power-Up that scans files stored in an Axon with
Yara rules that are modeled in the Cortex as `it:app:yara:rule` nodes. Rules are compiled with
[Yara-X](https://virustotal.github.io/yara-x/) (the `yara-x` Python package) inside the service,
saved to the service's storage, and matches are written back to the Cortex as
`it:app:yara:match` nodes.

| | |
| --- | --- |
| Python package | `yarastorm` |
| Storm package | `slib.yara` |
| Cell class | `yarastorm.svc.YaraSvc` |
| Docker image | `ghcr.io/gormaniac/stormsvcs/yarastorm` |
| Synapse | `>=2.248.0,<3.0.0` (Storm package `synapse_version`) |

## Why a service

The Cortex can model Yara rules (`it:app:yara:rule:text`) and their matches, but it can't run
them. This service owns the compute: compiling rule text, keeping compiled rules on disk,
pulling file bytes from an Axon, and scanning them. The Storm package only decides which nodes
to send to the service and how to model the results.

## Features

- Validate a rule's `:text` without saving it (`slib.yara.check`).
- Enable and disable rules for scanning, which compiles them into or removes them from the
  service and sets `it:app:yara:rule:enabled` (`slib.yara.enable`, `slib.yara.disable`).
- Reconcile the service's compiled rules with the `:enabled` rules in the Cortex
  (`slib.yara.sync`).
- Scan `file:bytes` nodes, by `:sha256`, with every compiled rule, and create an
  `it:app:yara:match` node for each matching rule (`slib.yara.scan`).
- An optional per-file size limit (`max_size`) for what the service pulls from the Axon, and a
  per-rule scan timeout (`scan_timeout`). Scans run off the event loop, in a worker thread.
- A `slib.yara.admin` permission gating every command that changes the rule set, enforced in
  the Cortex (Storm) and again in the service (Telepath).

## Architecture

```text
 Storm user                       Cortex                              yarastorm (YaraSvc Cell)
 ----------                       ------                              ------------------------
 it:app:yara:rule | slib.yara.enable
          |
          v
  slib.yara.* commands  --> slib.yara.lib module --Telepath-->  YaraApi (RetnApi)
                                ($lib.service.get(slib.yara))         |
                                                                      v
                                                              YaraSvc.compileRule()
                                                                      |
                                                           yara_x.compile() -> rule_dir/<guid>

 file:bytes | slib.yara.scan
          |
          v
  slib.yara.lib.match() --Telepath (generator)--> YaraSvc.matchFile()
                                                       |  axon.size()/axon.get() over Telepath
                                                       v
                                                     Axon (axon_url)
          ^                                            |
          |   one TelepathRetn per compiled rule       |
  slib.yara.ingest.yaraMatch() <-----------------------+
  [ it:app:yara:match=(rule, file) .seen=now ] <(seen)+ meta:source
```

Every Telepath call returns a `TelepathRetn` (`status`, `mesg`, `data`) and never raises; see
[API](api.md#the-telepathretn-convention).

## Quick start

1. Run the service with an Axon URL and a Telepath listener (see
   [Deployment](deployment.md#docker-compose-example) for a full compose file):

   ```bash
   docker run -d --name yarastorm \
     -v yarastorm-storage:/vertex/storage \
     -e SYN_YARASVC_DMON_LISTEN=tcp://0.0.0.0:27492/ \
     -e SYN_YARASVC_AUTH_PASSWD=secret \
     -e SYN_YARASVC_AXON_URL=tcp://root:secret@axon:27492/ \
     ghcr.io/gormaniac/stormsvcs/yarastorm:latest
   ```

2. Add the service to the Cortex and wait for the `slib.yara` package to load:

   ```text
   service.add yara tcp://root:secret@yarastorm:27492/
   service.list
   ```

3. Grant analysts who manage rules `slib.yara.admin`:

   ```text
   auth.user.addrule analyst1 slib.yara.admin
   ```

4. Create, check, enable a rule, and scan a file:

   ```text
   [ it:app:yara:rule=* :name=hello :text='rule hello { strings: $a = "hello" condition: $a }' ]
   | slib.yara.check | slib.yara.enable

   file:bytes=sha256:<hex> | slib.yara.scan
   it:app:yara:match
   ```

```{toctree}
:maxdepth: 2

deployment
commands
model
api
internals
```

# capa

`slib.capa` is a Storm Service (a Synapse Advanced Power-Up) that runs Mandiant's
[capa](https://github.com/mandiant/capa) against files stored in a Synapse Axon, and models the
capa rules they match. The service is the Python package `capasvc`, its Storm package is
`slib.capa`.

capa identifies capabilities in executable files (PE, .NET, ELF and raw shellcode) by matching
a library of YAML rules against features it extracts from the code. Every capa rule has a name,
a namespace (ex. `host-interaction/process/create`), and optional ATT&CK and MBC mappings. This
service turns all of that into Synapse nodes, so that matched capabilities can be pivoted and
queried like any other data.

## Features

- **Every capa rule is a `meta:rule`**, imported in bulk when the package loads: its
  documentation (`:desc`), YAML (`:text`), GitHub URL (`:url`), first author (`:author`),
  and its full meta as node data. Rules `-(refs)>` their ATT&CK techniques
  (`it:mitre:attack:technique`) and MBC behaviors (`ou:technique`), and each version of the
  rules is a `meta:ruleset` that `-(has)>` its rules.
- **Every rule namespace is a documented `syn:tag`** under a configurable prefix, ex.
  `host-interaction/process/create` is `#rep.capa.host_interaction.process.create`.
- **Scanning a `file:bytes`** links every matched rule to it with a `-(matches)>` edge, tags
  it with the rules' namespaces, and saves the full results (versions, detected format, arch
  and OS, match counts and addresses) in its `slib:capa` node data. A rescan replaces the
  earlier results.
- **Idempotent scans**: a file already scanned with the same rules, custom rules, `--format`,
  `--os` and tag settings is skipped unless `--force` is used.
- **Custom rules**: users write capa rules as `meta:rule` nodes with `:type=capa.custom`, and
  every scan uses them together with the official rules. See [Custom rules](custom-rules.md).
- **Files never pass through Storm**: the service pulls file bytes from the Axon itself, by
  `:sha256`.
- **Bundled rules and signatures**: the container image ships the capa-rules release and FLIRT
  signatures that match its version of capa (`flare-capa==10.0.0`, rules `v10.0.0`).

## Architecture

```text
 Storm user
    |  slib.capa.scan / slib.capa.info / slib.capa.admin.*
    v
 +-----------------+   Telepath: scan(), rulesInfo(), rules(), tags(), custom(), reload()
 | Synapse Cortex  | <----------------------------------------------------------------+
 | (slib.capa pkg) |                  TelepathRetn {status, mesg, data}               |
 +-----------------+                                                                  |
        |                                                                 +------------------+
        | file:bytes (sha256)                                             |  CapaSvc (Cell)  |
        v                                                                 |  capasvc.svc     |
 +-----------------+        axon.size() / axon.get() by sha256           |                  |
 |      Axon       | <--------------------------------------------------- |  capa subprocess |
 +-----------------+                                                      |  per file        |
                                                                          +------------------+
                                                                          /vertex/storage/capa/
                                                                          (work, cache, custom)
```

1. The Storm package's [`slib.capa.scan`](commands.md#slibcapascan) command sends a file's
   `:sha256` (plus `--format`, `--os` and the key of the view's custom rules) to the service.
2. The service ({src}`svcs/capa/src/capasvc/svc.py`) downloads the file from its configured
   Axon into its storage, runs `python -m capa.main --json` on it in a subprocess, and condenses
   capa's JSON result document into a summary of matched rules.
3. The Storm package ({src}`svcs/capa/src/capasvc/pkgproto/storm/modules/slib.capa.model.storm`)
   turns the summary into edges, tags and node data.

The rule import works the same way: the package's `onload` asks the service for its rules
(`rulesInfo()`, then the `rules()` generator and `tags()`) and models them, skipping the work
when nothing changed since the last import.

## Quick start

1. Run the service next to an Axon that the Cortex also uses (see
   [Deployment](deployment.md) for a full compose file):

   ```bash
   docker run -d --name capa \
     -e SYN_CAPASVC_DMON_LISTEN=tcp://0.0.0.0:27492/ \
     -e SYN_CAPASVC_AUTH_PASSWD=secret \
     -e SYN_CAPASVC_AXON_URL=tcp://root:axonsecret@axon:27492/ \
     -v capa-storage:/vertex/storage \
     ghcr.io/gormaniac/stormsvcs/capa:0.6.0
   ```

2. Add it to the Cortex. The Storm package loads and imports every capa rule and tag doc
   (this takes a while with the full capa-rules release):

   ```text
   service.add slib.capa tcp://root:secret@capa:27492/
   service.list
   ```

3. Grant analysts the user permission (and node permissions to write the results):

   ```text
   auth.user.addrule analyst slib.capa.user
   ```

4. Check it is ready, then scan:

   ```text
   slib.capa.info

   file:bytes#my.samples | slib.capa.scan

   // Shellcode needs its format, capa can't detect it.
   file:bytes=<sha256> | slib.capa.scan --format sc64

   // Every file that does process injection.
   file:bytes#rep.capa.host_interaction.process.inject
   ```

## Pages

```{toctree}
:maxdepth: 2

deployment
commands
model
api
internals
custom-rules
```

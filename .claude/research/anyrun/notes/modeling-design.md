# slib.anyrun modeling design (scrapped)

How the scrapped `slib.anyrun` service modeled ANY.RUN data in Synapse 2.x (2.256), and the
decisions reviewed with the maintainer. It followed the `slib.hatching` service's patterns: a
`TelepathRetn` API, `slib.anyrun.priv.*` asroot modules, per-user API keys in a user scoped vault
(type `anyrun`), a service-wide key, tags under a configurable prefix (`rep.anyrun`), and a
`meta:source` linked with `-(seen)>`.

The package was named `slib.anyrun`, not `slib.any.run`, so the package doesn't get an `any` level.

## Tasks (sandbox runs)

- The sample is a `file:bytes` (file and download tasks) or an `inet:url` (URL tasks), tagged
  with ANY.RUN's tags and threat names for the task's run time. A download task's sample also
  gets `-(refs)>` the URL it came from.
- **Every task gets one `it:av:scan:result`** (guid from the task ID): `Malicious activity` is 40,
  `Suspicious activity` 30, `No threats detected` 10, and **unknown (20)** when there's no verdict
  yet, ex. a running task. Modeling the task again updates the same node.
- **Tasks still in progress** (report status not `done`, `failed`, `error`, or `canceled`) were
  modeled as far as they got, the user was warned, and a one time cron job re-ran
  `slib.anyrun.enrich --task <task> --attempt <n>` in 10 minutes, for 3 tries in all. The job was
  created by the asroot `priv.user` module, so users didn't need `cron.add`, but Synapse makes the
  calling user its creator, so it ran as them (their vault key, their node permissions) in their
  view. Its iden was a guid of (user, view, task, attempt), so ingesting a running task twice
  didn't start a second chain of retries.
- Families became `risk:tool:software`, techniques `-(uses)> it:mitre:attack:technique`, mutexes
  `-(refs)> it:dev:mutex`, and malware configs `it:sec:c2:config` with their C2 servers tagged
  `c2` and the family.
- Processes (`it:exec:proc`), DNS requests and answers, HTTP requests, connections (`inet:flow`),
  Suricata alerts (`it:app:suricata:rule` matched by `it:app:suricata:matched`, whose `:target` is
  an `inet:flow` guid, not an ndef), and file and registry operations were all linked to the
  sample with `:sandbox:file`.
- **Not modeled:** JA3/JA3S/JARM (`inet:tls:ja3:sample` needs the client address, which ANY.RUN
  doesn't report) and process users (`it:exec:proc:user` is deprecated, and the repo's conftest
  fails tests that use it).

## File operations

- Created files (`modified.files`) became `it:exec:file:add`. Files without a SHA256 were kept by
  path, with `-(refs)>` their `hash:md5`.
- The incidents' `File` events became `it:exec:file:add`, `write`, and `del`. A rename (`newname`)
  was a `del` of the old path plus an `add` of the new one, `FileDrop` events carried their
  hashes, and `CLOSE` was skipped.
- **Every `it:exec:file:*` was tagged `<prefix>.threat_lvl.<level>`** (`unknown`, `low`, `mid`,
  `high`) with ANY.RUN's threat level for the file at that path, from `modified.files`. The
  incidents' numeric threat levels rate the incident, not a file, so they weren't used.

## Registry operations

- `modified.registry` and the incidents' registry events became `it:exec:reg:set` and
  `it:exec:reg:del` of an `it:dev:regval`.
- `it:dev:regval` has no prop for a value's name, so **`:key` is the key with the name appended**
  (`...\CurrentVersion\Run\Updater`). The default value and deleted keys used the bare key.
- Hive abbreviations were expanded (`HKCU`, `\REGISTRY\MACHINE`...), because `it:dev:regkey`
  doesn't normalize anything.
- DWORD and QWORD values (and untyped integers) were `:int`, everything else `:str`.
- The regval's guid didn't include the task, so the same value set by different tasks or samples
  was one node.
- `modified.registry`'s operation strings aren't documented, so they were matched by keyword.
- **Reads** (`it:exec:file:read`, `it:exec:reg:get`) were only modeled with `enrich --reads`.

## Downloads

- Samples are zips with the password `infected` (per the SDK). Every download was unzipped when
  it was a zip and checked against the SHA256 the report expects.
- The PCAP, video (`file:bytes`, `:mime=video/mp4`), and screenshots were linked with
  **`-(refs)>` from the task's `it:av:scan:result`**, the only node unique to a task, so two runs
  of the same sample stay apart. The maintainer confirmed these refs edges.
- Screenshots were `it:screenshot` nodes (`:image`, `:sandbox:file`, `:time`, `:desc`). Their
  `time` is an int32, so it was treated as seconds into the task. A URL task's last screenshot was
  the `:page:image` of an `it:exec:url` for the browser's visit (also confirmed).

## TI Lookup, YARA Search, and feeds

- TI Lookup results were modeled on the looked up node: tags, threat names as
  `risk:tool:software`, and a per-node `it:av:scan:result`. TI Lookup's threat level 0 means "no
  info", so it wasn't mapped to a verdict. That left stale verdicts when an indicator later came
  back with no info, and wasn't fixed before the service was scrapped.
- YARA Search matches were `file:bytes` nodes with an `it:app:yara:match`.
- TAXII feed indicators were tagged `<prefix>.feed` for the time they're valid.
- The maintainer's rule: **if a feature isn't available on the plan in use, leave it out.**

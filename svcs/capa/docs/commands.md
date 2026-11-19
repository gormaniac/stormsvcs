# Commands

The `slib.capa` Storm package has five commands. They are defined in
{src}`svcs/capa/src/capasvc/pkgproto/slib.capa.yaml`, with their Storm in
{src}`svcs/capa/src/capasvc/pkgproto/storm/commands`.

| Command | Permission | Purpose |
| --- | --- | --- |
| [`slib.capa.scan`](#slibcapascan) | `slib.capa.user` | Run capa against `file:bytes` nodes and model the matched rules. |
| [`slib.capa.info`](#slibcapainfo) | `slib.capa.user` | Print the versions of capa and its rules, counts, tag settings, import state and custom rules. |
| [`slib.capa.admin.sync`](#slibcapaadminsync) | `slib.capa.admin` | Import the rules and the tag docs (runs automatically when the package loads). |
| [`slib.capa.admin.tags`](#slibcapaadmintags) | `slib.capa.admin` | Change the tag prefix or turn tagging on or off. |
| [`slib.capa.admin.contacts.migrate`](#slibcapaadmincontactsmigrate) | `slib.capa.admin` | Merge the `@handle` author contacts made before 0.5.0 into `:user` contacts. |

Errors from the service are reported as warnings (`slib.capa: <what> failed: <mesg>`), not
raised, so a failed file doesn't stop a pipeline. The admin commands need `slib.capa.user` too,
see [Permissions](deployment.md#permissions).

## Analyst commands

### slib.capa.scan

Run capa against files in the Axon and model the capa rules they match.

```text
<file:bytes nodes> | slib.capa.scan [--format <fmt>] [--os <os>] [--force] [--yield]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--format` | str, one of `auto`, `pe`, `dotnet`, `elf`, `sc32`, `sc64` | `auto` | The file's format. `auto` has capa detect PE, .NET and ELF files. Shellcode can't be detected: use `sc32` or `sc64`. |
| `--os` | str, one of `auto`, `windows`, `linux`, `macos` | `auto` | The file's OS. `auto` has capa detect it. |
| `--force` | flag | `false` | Scan files that were already scanned with the same rules and options. |
| `--yield` | flag | `false` | Yield the `meta:rule` nodes that matched instead of the inbound nodes. |

Formats that describe another file are not supported: sandbox reports (CAPE, DRAKVUF, VMRay)
and features frozen by capa (`freeze`), since their results are about the sample they came
from, not the file that was scanned.

**Input.** `file:bytes` nodes (`cmdinputs`). The file is fetched from the Axon by its
`:sha256`, so the bytes must be in the Axon the service is configured with. Other nodes are
warned about (`slib.capa.scan: Only file:bytes nodes can be scanned, skipping <form>=<repr>.`)
and passed through, or dropped with `--yield`. A `file:bytes` without `:sha256` is warned
about (`slib.capa: Unable to scan file:bytes=<repr>, it has no :sha256.`).

**What it does**, once per command run, on the first `file:bytes` (an empty pipeline never calls
the service):

1. Sends the view's custom rules to the service and gets back their key (see
   [Custom rules](custom-rules.md)). Skipped custom rules are warned about.
2. Unless `--force`, gets the rules info used to skip files already scanned. If the rules
   aren't available it warns, and every file is sent to the service (which then returns the
   real error).

Then for each file:

1. **Skip check** (without `--force`): the file is skipped when its `slib:capa` node data
   shows it was scanned with the same official rules (by SHA256), the same custom rules key
   (or none), the same `--format` and `--os`, and the current tag prefix (or with tagging off
   both times). Skipped files print
   `slib.capa: Skipping <sha256>, it was already scanned with these rules and tag settings (see --force).`
2. **Scan**: calls the service's `scan(sha256, fmt, osname, custom)`. A failure warns
   `slib.capa: Scanning <sha256> failed: <mesg>` (see the [error list](api.md#scan)).
3. **Model** the results (see [Scan results](model.md#scan-results)):
   - removes the earlier scan's capa `-(matches)>` edges and the tags it applied,
   - adds `meta:rule -(matches)> file:bytes` for every matched rule (modeling the rule if it
     isn't in the Cortex yet),
   - tags the file `<prefix>.<namespace tag>` for every matched rule with a namespace, unless
     tagging is disabled,
   - saves the results in the file's `slib:capa` node data, and links the file
     `meta:source -(seen)> file:bytes`.

**Output.** The inbound nodes, or with `--yield` the matched `meta:rule` nodes (nothing for a
skipped or failed file).

```text
// Scan files, already scanned files are skipped.
file:bytes#my.samples | slib.capa.scan

// Shellcode needs its format.
file:bytes:sha256=<sha256> | slib.capa.scan --format sc64

// A Linux ELF, scanned again even if it was before.
file:bytes:sha256=<sha256> | slib.capa.scan --os linux --force

// Yield the matched rules and pivot to their ATT&CK techniques.
file:bytes:sha256=<sha256> | slib.capa.scan --yield | -(refs)> it:mitre:attack:technique

// Rescan every file that has capa tags, ex. after a prefix change.
file:bytes#rep.capa | slib.capa.scan
```

### slib.capa.info

Print the versions of capa and its rules, the rule counts, the tag settings, the state of the
rule import, and the custom rules.

```text
slib.capa.info [--yield]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--yield` | flag | `false` | Yield the `meta:ruleset` node of the service's rules (if it was imported). |

It prints:

```text
capa: 10.0.0
rules: v10.0.0 (<n> rules, <n> library rules, <n> namespaces)
rules sha256: <sha256 of the rule files>
rules imported: true
tags: enabled=true prefix=rep.capa
tag docs imported: true
custom rules: 1 (0 skipped)
    my capa rule (meta:rule=<guid>)
```

- `rules imported` is whether the last import's sync key equals the service's current key.
  `false` means the next package load (or `slib.capa.admin.sync`) will import the rules.
- `tag docs imported` is whether the tag docs were imported under the current prefix for the
  current rules.
- `custom rules` sends the view's custom rules to the service, so it also warns about every
  skipped custom rule (invalid, duplicate name, or shadowed by an official rule). It prints
  `custom rules: 0` when there are none, or they couldn't be sent.

If the rules can't be loaded it only warns
`slib.capa: Getting the capa rules info failed: <mesg>`, and `--yield` yields nothing. With
`--yield` it yields the `meta:ruleset` (by the `ruleset` guid in the rules info) instead of
any inbound nodes.

```text
slib.capa.info
slib.capa.info --yield | -(has)> meta:rule +:type=capa.lib
```

## Admin commands

### slib.capa.admin.sync

Import every capa rule as a `meta:rule`, and every rule namespace as a documented `syn:tag`.

```text
slib.capa.admin.sync [--force] [--reload]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--force` | flag | `false` | Import the rules and tags even if they haven't changed (ex. to restore edited rule nodes). |
| `--reload` | flag | `false` | Have the service reload its rules from `capa:rules` first. |

This is what the package's `onload` runs (without options) every time the package loads.

1. With `--reload`, calls the service's `reload()`. A failure warns
   `slib.capa: Reloading the capa rules failed: <mesg>` and stops.
2. Gets the rules info. If the last rules import (the `slib:capa:sync:rules` global) has the
   same sync key and the `meta:ruleset` exists, the rule import is skipped. Otherwise it
   creates the `meta:ruleset`, clears the sync state (so an import that fails partway is done
   again next time), models every rule from the service's `rules()` generator, and records the
   key:

   ```text
   slib.capa: Importing <n> capa rules (v10.0.0).
   slib.capa: Imported <n> capa rules (v10.0.0).
   ```

3. Imports the tag docs under the current prefix, unless they were already imported for this
   prefix and key (`slib:capa:sync:tags` is `<prefix>:<key>`). They're imported even if tagging
   is disabled:

   ```text
   slib.capa: Imported the docs of <n> rep.capa tags.
   ```

**Output.** The `meta:ruleset` of the rules (the inbound nodes are dropped), or nothing if the
rules aren't available.

```text
slib.capa.admin.sync --force

// The rules in capa:rules were updated on disk.
slib.capa.admin.sync --reload
```

The import never deletes nodes. A rule that was removed from the rules keeps its node, and
custom rules (`:type=capa.custom`) are never touched.

### slib.capa.admin.tags

Configure the tags scans apply, `<prefix>.<namespace>`. Prints the settings, without options
too.

```text
slib.capa.admin.tags [--prefix <tag>] [--enable | --disable]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--prefix` | str | `null` (unchanged) | The tag prefix to use. Must be a valid tag name, already normalized (lowercase, no spaces). The package default is `rep.capa`. |
| `--enable` | flag | `false` | Enable tagging (the default state). |
| `--disable` | flag | `false` | Disable tagging. Scans still add edges and node data. |

```text
slib.capa tags: enabled=true prefix=rep.capa
```

- `--enable` with `--disable` raises `BadArg` (`Use --enable or --disable, not both.`).
- A prefix that isn't a valid tag, or that isn't already in its normalized form (ex. `""`,
  `has space`, `REP.capa`), raises `BadArg` (`<prefix> isn't a valid tag name.`).
- Setting a prefix imports the tag docs under the new prefix right away.

Files keep their old tags until they're scanned again. After a prefix change (or turning
tagging on or off) the next scan of a file isn't skipped: it removes the tags the previous
scan applied (whatever the prefix was) and applies the new ones. The `syn:tag` nodes under the
old prefix are left in place.

```text
slib.capa.admin.tags --prefix my.capa
file:bytes#rep.capa | slib.capa.scan

slib.capa.admin.tags --disable
```

### slib.capa.admin.contacts.migrate

Migrate the rule author contacts made for `@handle` authors before 0.5.0 to `:user` contacts.

```text
slib.capa.admin.contacts.migrate [--apply]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--apply` | flag | `false` | Migrate the contacts. Without it, the command is a dry run that only prints. |

A rule's `:author` is a `ps:contact` for its first author. Before 0.5.0, an `@handle` author
was a contact with the handle as its `:name` (guid ctor `{"name": "@handle"}`). It's now a
contact with the handle (without the `@`) as its `:user` (`{"user": "handle"}`). Re-importing
the rules points their `:author` at the new contacts but leaves the old ones behind.

**What it finds.** For every handle that's the `:author` of a capa rule (`meta:source=<slib.capa>
-(seen)> meta:rule +:type^=capa. :author -> ps:contact`, either the old contact or the new one),
the node the old ctor made (guid `$lib.guid((name, "@<handle>"))` with that `:name`). Other
`ps:contact` nodes, even with an `@` `:name`, are never touched.

**What it does** for each old contact:

- If it already has the handle as its `:user`, only its `:name` is removed.
- Otherwise it is merged into the current contact (made if it doesn't exist): props the new
  node doesn't have are copied (not the `@handle` `:name`; `.seen` intervals merge), array
  props are combined, tags (with their times), node data the new node doesn't have, and light
  edges (both directions) are moved, props of other nodes that reference it (by guid, ndef, or
  in an array, ex. a rule's `:author`) are re-pointed, and the old node is deleted.
- An old contact referenced by a read-only prop (ex. `ou:contest:result:participant` or
  `meta:seen:node`, part of the referencing node's primary value) can't be re-pointed. It is
  skipped with a warning naming those props and nodes. Recreate (or delete) them, then rerun.

Output, one line per contact and a summary:

```text
Would migrate ps:contact=<guid> (:name=@someone) into a new ps:contact=<guid> (:user=someone)
slib.capa.admin.contacts.migrate: Found 1 old contacts. This was a dry run, rerun with --apply to migrate them.

Migrated ps:contact=<guid> (:name=@someone) into a new ps:contact=<guid> (:user=someone)
slib.capa.admin.contacts.migrate: Migrated 1 old contacts, and re-pointed 3 nodes that referenced them.
```

Running it again after `--apply` prints
`slib.capa.admin.contacts.migrate: There are no old contacts to migrate.` Node edits run as
the calling user, so their node permissions apply.

```text
slib.capa.admin.contacts.migrate
slib.capa.admin.contacts.migrate --apply
```

# Custom rules

Users can write their own capa rules in Synapse, and every scan uses them together with the
official rules. The Python side is {src}`svcs/capa/src/capasvc/custom.py` and
`CapaSvc.custom()`/`_prepCustom()` in {src}`svcs/capa/src/capasvc/svc.py`; the Storm side is
the custom rules section of
{src}`svcs/capa/src/capasvc/pkgproto/storm/modules/slib.capa.lib.storm`.

## Writing a custom rule

A custom rule is a `meta:rule` with a `:type` of `capa.custom`, or a type below it (ex.
`capa.custom.myteam`), and the [capa rule](https://github.com/mandiant/capa-rules/blob/master/doc/format.md)
YAML in its `:text`:

```text
$yaml = '''
rule:
  meta:
    name: contain my marker
    namespace: custom/marker
    authors:
      - analyst@example.com
    scopes:
      static: file
      dynamic: file
  features:
    - string: "my-marker"
'''
[ meta:rule=* :name="contain my marker" :type=capa.custom :text=$yaml ]
```

The rules are found with `meta:rule:type^=capa.custom. +:text`. The trailing dot of the
taxonomy prefix means a type that only starts with the same letters (ex. `capa.customer`)
isn't a custom rule. Rules without `:text` are ignored.

## How scans use them

1. On the first file of every `slib.capa.scan` (and every `slib.capa.info`), the package lifts
   the custom rules in the current view and sends them to the service's
   [`custom()`](api.md#custom) as `[{"guid": <node guid>, "text": <:text>}, ...]`. Edits to
   a rule's `:text` are used by the next command run, and deleted rules are dropped.
2. The service checks each rule (`CustomRules._add()`, in guid order):

   | Check | Result |
   | --- | --- |
   | `guid` isn't 32 hex characters | error `Not a meta:rule guid.` |
   | `text` is empty or not a string | error `The rule has no :text.` |
   | capa can't parse the YAML | error `Invalid capa rule: <error>` |
   | an official rule has the same name | `shadowed` (the official rule wins) |
   | another custom rule has the same name | error `Another custom rule (meta:rule=<guid>) has the same name: <name>` (the lower guid wins) |

   The package warns about every skipped rule:

   ```text
   slib.capa: Skipping the custom capa rule meta:rule=<guid>: <mesg>
   slib.capa: Skipping the custom capa rule meta:rule=<guid>, an official capa rule has the same name: <name>
   ```

3. The usable rules are a **set**, identified by its **key**: the SHA256 of every usable rule's
   guid and text. The set is written to `capa/custom/<key>/<guid>.yml` (into a temporary
   directory first, then renamed, so capa never sees a partial set), and remembered by the
   service.
4. Each `scan()` passes the key. Before the first scan with a set, the service has capa load the
   official and custom rules together once (building capa's cache for the combination). If capa
   can't (ex. a custom rule uses a rule that doesn't exist), every scan with
   that set fails with `capa can't use the custom rules: <capa's error>` until it's fixed. A
   failed build is tried again after 60 seconds (`CUSTOM_RETRY`).
5. capa runs with `--rules <official> --rules <custom set>`. Custom rules can use official rules
   (ex. `match: contain loop`) and each other.

## Results

- A matched custom rule's own node gets the `-(matches)>` edge. The package never edits or
  deletes custom rule nodes (only if a matched custom node is missing from the view does the
  scan model it from the record, with the custom node's guid and `:type=capa.custom`).
- The file is tagged with the custom rule's namespace under the prefix, like an official rule.
  Custom namespaces don't get tag docs.
- The file's `slib:capa` node data records the set's key in `rules.custom`. A file is scanned
  again (without `--force`) when the view's custom rules change, since the key changes.
- `slib.capa.admin.sync` only touches the official rules.

A custom rule shadowed by an official rule stays as it is, and is used again if the official
rule goes away (ex. a rules update).

## Sets on the service

| Rule | Detail |
| --- | --- |
| Lifetime | Sets don't survive a restart (`capa/custom/` is deleted at startup) or a `reload()` (the sets are cleared). A scan with an unknown key fails with `Unknown custom capa rules (...), send them again with custom().`; the next command run sends them again. |
| Limit | The 16 most recently used sets are kept (`MAX_CUSTOM_SETS`). Older sets, and their capa cache, are deleted, unless a scan is using them. |
| Caches | Each set's capa cache (for the official plus custom rules) is kept while the set is, and deleted with it. |

## Listing them

`slib.capa.info` prints the usable custom rules and how many were skipped:

```text
custom rules: 2 (1 skipped)
    contain my marker (meta:rule=<guid>)
    contain other marker (meta:rule=<guid>)
```

From Storm, `$lib.import(slib.capa.lib).customInfo()` returns the service's full result
(`key`, `rules`, `errors`, `shadowed`).

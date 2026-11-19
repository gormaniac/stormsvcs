# Administration commands

All of these need the `slib.shodan.admin` permission. Calls to Shodan use the calling admin's
own vault key first, like every other command.

(shodan-cmd-admin-apikey)=
## slib.shodan.admin.apikey

Set, clear or check the service-wide API key, stored in the service (not the Cortex) and used
by every user without their own key.

```text
slib.shodan.admin.apikey [<apikey>] [--clear]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `apikey` | str, optional | null | The key to store (Telepath `setApiKey(apikey)`). Prints whether a key is set when omitted. |
| `--clear` | flag | false | Remove the stored key (`setApiKey(None)`). |

Prints `Set the slib.shodan API key.`, `Cleared the slib.shodan API key.`, or `A service-wide
API key is set.` / `No service-wide API key is set.` The check (`hasApiKey()`) is true when the
stored key or the `shodan:apikey` option is set. Clearing the stored key doesn't remove the
option.

```text
slib.shodan.admin.apikey ABCDEFG
slib.shodan.admin.apikey --clear
```

(shodan-cmd-admin-tags)=
## slib.shodan.admin.tags

Configure the tags the package applies for Shodan's tags (ex. `cloud`, `vpn`, `honeypot`), CISA
KEV vulns, files extracted from banners, and community query tags. Tags are
`<prefix>.<tag>` (see [model](model.md#tags)).

```text
slib.shodan.admin.tags [--prefix <tag>] [--enable] [--disable]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--prefix` | str | null | The tag prefix to use. Must already be a normalized `syn:tag` (lower case, stripped), or it raises `BadArg`. |
| `--enable` | flag | false | Turn tagging on. |
| `--disable` | flag | false | Turn tagging off. Using both raises `BadArg`. |

The settings are Storm globals in the Cortex, `slib:shodan:tag:prefix` (default `rep.shodan`)
and `slib:shodan:tag:enabled` (default true), set by the service's `add` event. The command
always prints the current settings, ex. `slib.shodan tags: enabled=true prefix=rep.shodan`.
Changes apply to nodes modeled afterwards. Existing tags aren't renamed or removed.

```text
slib.shodan.admin.tags --prefix rep.shodan.tag
slib.shodan.admin.tags --disable
```

(shodan-cmd-admin-dns-cleanup)=
## slib.shodan.admin.dns.cleanup

Replace the `inet:dns:a`/`inet:dns:aaaa` nodes versions before 0.17.0 made from Shodan's
hostnames with `inet:dns:rev`/`inet:dns:rev6` nodes. Shodan's hostnames come from reverse DNS
and TLS/HTTP observations, not forward lookups, so they're modeled as reverse records now.

```text
slib.shodan.admin.dns.cleanup [--apply]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--apply` | flag | false | Make the changes. Without it, the command is a dry run that prints what it would do. |

It runs entirely in the Cortex, as the calling user. Every `inet:dns:a` and `inet:dns:aaaa`
node the `meta:source` links to (`meta:source=5c1b0a3d0e7f4b2e9a8c6d4f2b1e0a97 -(seen)>`) is
lifted first, then each is checked. A node is kept, with the reason printed, when:

| Check | Reason printed |
| --- | --- |
| Its IP isn't linked to the `meta:source` | `the IP isn't from slib.shodan, it may be a DNS domain record` |
| It has no `.seen` | `it has no .seen, it may be a DNS lookup or an InternetDB hostname` |
| Its `inet:fqdn` is linked to the `meta:source` | `the hostname is a slib.shodan subdomain or reverse DNS name, it may be a DNS domain record` |
| The `meta:source` has an `inet:dns:ns` (by `:zone`), `inet:dns:soa`, `inet:dns:mx`, `inet:dns:txt` or `inet:dns:cname` (by `:fqdn`) for the hostname or a parent domain | `slib.shodan has DNS domain records for the zone` |

Every other node is replaced:

1. An `inet:dns:rev` (or `inet:dns:rev6`) for the IP and hostname is made, with the old node's
   `.seen`, linked to the `meta:source`.
2. The old node is deleted. When it's tagged, has any other edge to it, has any edge from it,
   or another node refers to it by a prop (ex. `inet:dns:answer:a`), only the `meta:source`'s
   `-(seen)>` edge is removed (`unlink`) instead.

Each node prints a line like `delete inet:dns:a=(...), adding the reverse DNS record (<ip>,
<fqdn>).` or `keep ...`, then a summary: `Dry run: would delete <n>, unlink <n>, keep <n>. Use
--apply to make the changes.` or `Deleted <n>, unlinked <n>, kept <n>.` A second run changes
nothing. Deleting needs the `node.del` permissions.

```text
slib.shodan.admin.dns.cleanup
slib.shodan.admin.dns.cleanup --apply
```

(shodan-cmd-admin-org)=
## slib.shodan.admin.org

Print the Shodan organization (enterprise) the API key belongs to, or manage its members.

```text
slib.shodan.admin.org [--add <user>]... [--remove <user>]... [--notify]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--add` | str, repeatable | `[]` | A username or email to add (`PUT /org/member/{user}`). |
| `--remove` | str, repeatable | `[]` | A username or email to remove (`DELETE /org/member/{user}`). |
| `--notify` | flag | false | Email added users (`notify=true`). Sent as `notify=false` otherwise. |

Without `--add` or `--remove`, it calls `GET /org` and prints the name, ID, upgrade type,
domains, admins and members. A key whose plan has no organization gets Shodan's error (often an
HTTP 403) as a warning.

```text
slib.shodan.admin.org
slib.shodan.admin.org --add analyst@example.com --notify
```

(shodan-cmd-admin-data)=
## slib.shodan.admin.data

List Shodan's bulk datasets (`GET /shodan/data`, a dataset / description table), or the files
in one (`GET /shodan/data/{dataset}`, a name / size / timestamp / url table). Enterprise only.

```text
slib.shodan.admin.data [<dataset>]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `dataset` | str, optional | null | The dataset to list the files of. |

```text
slib.shodan.admin.data
slib.shodan.admin.data raw-daily
```

(shodan-cmd-admin-request)=
## slib.shodan.admin.request

Send a request to any Shodan API and print the JSON response, for endpoints and options the
other commands don't cover.

```text
slib.shodan.admin.request <path> [--method get|post|put|delete]
                          [--base api|trends|internetdb|cvedb]
                          [--params <dict>] [--json <dict>] [--form <dict>]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `path` | str | required | The endpoint path, ex. `/shodan/host/count`. A missing leading `/` is added. |
| `--method` | `get`, `post`, `put`, `delete` | `get` | The HTTP method. |
| `--base` | `api`, `trends`, `internetdb`, `cvedb` | `api` | The API to send it to. |
| `--params` | any | null | A dict of query params. |
| `--json` | any | null | A dict to send as the JSON body. |
| `--form` | any | null | A dict to send as a form body (ex. for `POST /shodan/scan`, which ignores query params). Can't be used with `--json`. |

The key is added as the `key` param for `api` and `trends`. Param and form values are
converted like every other request: booleans to `true`/`false`, lists to comma separated
strings, dicts to JSON, and `null` values left out. The request goes through the same rate
limiter, retries and error handling as every other call (see [internals](internals.md)).

```text
slib.shodan.admin.request /shodan/host/8.8.8.8 --params ({"minify": true})
slib.shodan.admin.request /api/v1/search/facets --base trends
```

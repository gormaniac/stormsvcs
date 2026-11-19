# Scan, alert and notifier commands

The scan commands need `slib.shodan.scan`, and the alert and notifier commands need
`slib.shodan.alert`. These commands only print: inbound nodes pass through, and nothing is
modeled, except by `slib.shodan.scan --wait`. See [Commands](commands.md) for what every command
shares.

(shodan-cmd-scan)=
## slib.shodan.scan

Ask Shodan to scan IPs or netblocks (`POST /shodan/scan`). Uses one scan credit per IP.

```text
slib.shodan.scan [--ip <ip or cidr>]... [--force] [--wait <seconds>]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--ip` | str, repeatable | `[]` | An IP or CIDR to scan, added to the inbound nodes. |
| `--force` | flag | false | Re-scan IPs Shodan scanned recently (`force=true`, enterprise only). |
| `--wait` | int | `0` | Seconds to wait for the scan to finish, then ingest the results. `0` doesn't wait. |

Inbound `inet:ipv4`, `inet:ipv6`, `inet:cidr4` and `inet:cidr6` nodes and `--ip` values are
collected (each once) and submitted as a single scan when the command ends, so there's one scan
ID. Other forms are warned about. With no targets, it warns `Nothing to scan, use inbound nodes
or --ip.`

The request sends a form body, `ips=<comma separated targets>&force=<true|false>` (Shodan
ignores query params here). The command prints `Submitted scan <id> for <count> IPs,
<credits_left> scan credits left.`

With `--wait`, it checks `GET /shodan/scan/{id}` every 10 seconds (and once more at the
deadline) until the status is `DONE` or `FAILED`:

- `FAILED` warns `Scan <id> failed, nothing to ingest.`
- Any other status at the deadline warns `Scan <id> is still <status>, check it with
  slib.shodan.scan.status.`
- `DONE` runs a host lookup (like `slib.shodan.host`) for each IP target. Netblocks are
  skipped with a warning suggesting `slib.shodan.search "net:<cidr>"`. Ingesting needs the
  `slib.shodan.user` permission, which is only checked when `--wait` is above 0.

```text
inet:ipv4=1.2.3.4 | slib.shodan.scan --wait 300
slib.shodan.scan --ip 1.2.3.0/24
```

(shodan-cmd-scan-status)=
## slib.shodan.scan.status

Print one scan's status, or list your scans.

```text
slib.shodan.scan.status [<id>] [--page <n>]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `id` | str, optional | null | A scan ID. Lists every scan when omitted. |
| `--page` | int | `1` | The page of scans to list. |

With an ID, it calls `GET /shodan/scan/{id}` and prints `Scan <id>: <status> (<count> IPs,
created <created>)`. Without one, it calls `GET /shodan/scans?page=<n>` and prints `Total
scans: <n>` and an id / status / IPs / credits left / created table. The service removes the
`api_key` field Shodan includes in both responses.

```text
slib.shodan.scan.status
slib.shodan.scan.status ABCDEFG
```

(shodan-cmd-scan-internet)=
## slib.shodan.scan.internet

Ask Shodan to crawl the whole Internet for a port and protocol (`POST /shodan/scan/internet`,
enterprise only). The form body is `port=<port>&protocol=<protocol>`. Prints `Submitted scan
<id>.` List the protocols with `slib.shodan.ref protocols`.

```text
slib.shodan.scan.internet <port> <protocol>
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `port` | int | required | The port to scan. |
| `protocol` | str | required | The protocol to scan it with. |

```text
slib.shodan.scan.internet 8443 https
```

(shodan-cmd-alert-list)=
## slib.shodan.alert.list

List your network alerts, or print one.

```text
slib.shodan.alert.list [--id <id>] [--active]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--id` | str | null | An alert ID to print (`GET /shodan/alert/{id}/info`). |
| `--active` | flag | false | Only list alerts that haven't expired (`include_expired=false`). |

Without `--id`, it calls `GET /shodan/alert/info` (`include_expired=true` unless `--active`) and
prints `No network alerts.` or, for each alert:

```text
Alert ALERT1 - corp
  Created: 2026-10-01T00:00:00  Expires: 0  Expired: false
  IPs: 1.2.3.0/24
  Triggers: new_service
  Notifiers: default
```

(shodan-cmd-alert-add)=
## slib.shodan.alert.add

Create a network alert monitoring the inbound IPs and netblocks, and optionally enable triggers
and attach notifiers in the same command.

```text
slib.shodan.alert.add <name> [--ip <ip or cidr>]... [--expires <seconds>]
                      [--trigger <name>]... [--notifier <id>]...
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | str | required | The alert's name. |
| `--ip` | str, repeatable | `[]` | An IP or CIDR to monitor, added to the inbound nodes. |
| `--expires` | int | `0` | Seconds until the alert expires. `0` never expires. |
| `--trigger` | str, repeatable | `[]` | A trigger to enable (see `slib.shodan.ref triggers`). |
| `--notifier` | str, repeatable | `[]` | A notifier ID to attach. `default` is your account's email. |

Inbound `inet:ipv4`, `inet:ipv6`, `inet:cidr4` and `inet:cidr6` nodes and `--ip` values are
collected (each once) into one alert when the command ends. Other forms are warned about. With
no IPs, it warns and creates nothing.

1. `POST /shodan/alert` with the JSON body `{"name": <name>, "filters": {"ip": [...]},
   "expires": <expires>}`. Prints `Created alert <id> monitoring <n> IPs/netblocks.`
2. `PUT /shodan/alert/{id}/trigger/{trigger}` for each `--trigger`.
3. `PUT /shodan/alert/{id}/notifier/{notifier}` for each `--notifier`.

Each step's failure is a warning, and the rest still run.

```text
inet:cidr4=1.2.3.0/24 | slib.shodan.alert.add corp-network --trigger new_service --trigger vulnerable --notifier default
slib.shodan.alert.add single-host --ip 1.2.3.4 --expires 86400
```

(shodan-cmd-alert-edit)=
## slib.shodan.alert.edit

Edit an alert's IPs, triggers, ignored services and notifiers in one command.

```text
slib.shodan.alert.edit <id> [--ip <ip or cidr>]... [--append]
                       [--enable <trigger>]... [--disable <trigger>]...
                       [--ignore <trigger>/<ip>:<port>]... [--unignore <trigger>/<ip>:<port>]...
                       [--notifier <id>]... [--rm-notifier <id>]...
```

| Option | Type | Default | Meaning | Request |
| --- | --- | --- | --- | --- |
| `id` | str | required | The alert ID. | |
| `--ip` | str, repeatable | `[]` | An IP or CIDR to monitor, with the inbound nodes. | `POST /shodan/alert/{id}`, JSON `{"filters": {"ip": [...]}}` |
| `--append` | flag | false | Add the IPs to the alert's current ones instead of replacing them. | `GET /shodan/alert/{id}/info` first |
| `--enable` | str, repeatable | `[]` | A trigger to enable. | `PUT .../trigger/{trigger}` |
| `--disable` | str, repeatable | `[]` | A trigger to disable. | `DELETE .../trigger/{trigger}` |
| `--ignore` | str, repeatable | `[]` | A `<trigger>/<ip>:<port>` service to stop notifying about. | `PUT .../trigger/{trigger}/ignore/{ip}:{port}` |
| `--unignore` | str, repeatable | `[]` | A `<trigger>/<ip>:<port>` service to notify about again. | `DELETE .../trigger/{trigger}/ignore/{ip}:{port}` |
| `--notifier` | str, repeatable | `[]` | A notifier ID to attach. | `PUT .../notifier/{id}` |
| `--rm-notifier` | str, repeatable | `[]` | A notifier ID to detach. | `DELETE .../notifier/{id}` |

The IPs are only updated when there are inbound IPs/netblocks or `--ip` values. The steps run
in the order of the table, and each failure is a warning.

`--ignore` and `--unignore` values must be a trigger, `/`, an IP (IPv6 may be in brackets) and
a port, with no other `/`, `?`, `#` or `..`. Anything else warns `<value> is not in the format
<trigger>/<ip>:<port>.` and is skipped. The service checks the service part again before
building the path, so a value can never reach another endpoint with the API key.

```text
inet:cidr4=5.6.7.0/24 | slib.shodan.alert.edit ABCDEFG --append --enable malware
slib.shodan.alert.edit ABCDEFG --ignore open_database/1.2.3.4:9200
```

(shodan-cmd-alert-del)=
## slib.shodan.alert.del

Delete network alerts (`DELETE /shodan/alert/{id}` for each).

```text
slib.shodan.alert.del <id> [<id> ...]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `ids` | str, one or more | required | The alert IDs to delete. |

(shodan-cmd-notifier-list)=
## slib.shodan.notifier.list

List your notifiers (`GET /notifier`, an id / provider / description table), or print one as
JSON (`GET /notifier/{id}`).

```text
slib.shodan.notifier.list [--id <id>]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--id` | str | null | A notifier ID to print. |

(shodan-cmd-notifier-add)=
## slib.shodan.notifier.add

Create a notifier (`POST /notifier`). List the providers and their required arguments with
`slib.shodan.ref providers`.

```text
slib.shodan.notifier.add <provider> [--desc <desc>] [--arg <name>=<value>]...
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `provider` | str | required | The notifier provider, ex. `slack`. |
| `--desc` | str | null | A description. |
| `--arg` | str, repeatable | `[]` | A `<name>=<value>` provider argument, split on the first `=`. |

The form body is every `--arg`, plus `provider` and `description` (left out when there's no
`--desc`). An `--arg` without `=` warns and nothing is sent. Prints `Created notifier <id>.`

```text
slib.shodan.notifier.add slack --desc "SOC channel" --arg webhook_url=https://hooks.slack.com/...
```

(shodan-cmd-notifier-edit)=
## slib.shodan.notifier.edit

Change a notifier's provider arguments (`PUT /notifier/{id}`, the arguments as query params).

```text
slib.shodan.notifier.edit <id> [--arg <name>=<value>]...
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `id` | str | required | The notifier ID. |
| `--arg` | str, repeatable | `[]` | A `<name>=<value>` provider argument. |

An `--arg` without `=` warns and nothing is sent. Prints `Updated notifier <id>.`

```text
slib.shodan.notifier.edit ABCDEFG --arg to=soc@example.com
```

(shodan-cmd-notifier-del)=
## slib.shodan.notifier.del

Delete notifiers (`DELETE /notifier/{id}` for each).

```text
slib.shodan.notifier.del <id> [<id> ...]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `ids` | str, one or more | required | The notifier IDs to delete. |

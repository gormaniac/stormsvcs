# slib.snort

Match PCAPs in the Axon against Snort 3 rules, and keep the rules in sync with open source rule feeds.

The service's rules are the enabled `it:app:snort:rule` nodes (with `:text`) in the Cortex. Rules
from the feeds (by default the Snort 3 Community ruleset and Emerging Threats Open) are modeled
as `it:app:snort:rule` nodes in each feed's `meta:ruleset`, so they can be enabled, disabled, and
queried like any other rule. Add your own with `slib.snort.rule.add`.

Run any `slib.snort.*` command with `--help` for its options and examples.

## Syncing

`slib.snort.sync` downloads the feeds (once a day), models their rules, and pushes every enabled
rule to the service. It runs hourly as a cron job, see `slib.snort.admin.schedule`.
`slib.snort.rule.enable`, `slib.snort.rule.disable`, and `slib.snort.rule.add` push their rules
right away.

`:engine` is the rule's syntax: `3` (or unset) for Snort 3, or `2` for Snort 2.x (converted with
snort2lua by the service). Rules Snort can't load are skipped, see `slib.snort.rule.errors`.

## Permissions

- `slib.snort.user` - Scan PCAPs, check rules, and view the status, rule errors, and feeds.
- `slib.snort.rules` - Add, enable, and disable rules.
- `slib.snort.sync` - Sync the feeds into the Cortex and push the rules to the service.
- `slib.snort.admin` - Manage the feeds and the sync schedule.

## Examples

```
// Scan PCAPs, and see the rules that matched.
file:bytes#my.pcaps | slib.snort.scan --yield | -> it:app:snort:rule

// Add a custom rule.
slib.snort.rule.add 'alert http any any -> any any ( msg:"My rule"; http_uri; content:"/evil"; sid:1000001; rev:1; )'

// Turn off a noisy rule.
it:app:snort:rule:id=2013502 | slib.snort.rule.disable

// Sync now.
slib.snort.sync
```

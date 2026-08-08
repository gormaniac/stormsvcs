# yarastorm

A Synapse Storm service that adds Yara scanning features to a Synapse Cortex.

TODO:
- Migrate to Yara-X
    - We may still want to maintain our own object of individually compiled rules, Yara-X's Rules/Scanner objects return every match in one list. So, we'd no longer be able to stream results back to Storm, but would have to send all matches back in a chunk.
        - Plus we'd be unable to track Synapse's guid with each rule, without modifying the rule.
- Add a trigger on it:prod:yara:rule:enabled = true to send to this service and save it to the cell
    - reverse when :enabled = false
- matchFile is not defined properly in svc.py, it takes a list and the api sends a single rule. Make the input optional, if no specific rule is given, match against every rule registered in the cell.
- Move yara rule storage to the Cell's LMDB slab.

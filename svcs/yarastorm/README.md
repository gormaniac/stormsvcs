# yarastorm

A Synapse Storm service that adds Yara scanning features to a Synapse Cortex.

Rules are compiled with [Yara-X](https://virustotal.github.io/yara-x/) and saved in the service.
`slib.yara.enable` compiles an `it:app:yara:rule` into the service and sets `:enabled`, `slib.yara.disable`
removes it again. `slib.yara.scan` matches `file:bytes` nodes (by `:sha256`, pulled from the configured Axon)
against every rule saved in the service.

TODO:
- Add a trigger on it:app:yara:rule:enabled = true to send to this service and save it to the cell
    - reverse when :enabled = false
    - Rules updated in the Cortex (`:text` changes) aren't re-compiled until they are enabled again.
- Move yara rule storage to the Cell's LMDB slab.

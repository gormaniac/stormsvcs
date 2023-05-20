# stormsvcs

A collection of custom Storm services.

## Services

- `bytes`
  - Search various sources for available bytes for a given `hash:*` node.
- `capa`
  - Process files with Capa.
- `enrich`
  - Enrich any supported node from all possible enrichment sources.
- `example`
  - A copy of [the minimal example](https://synapse.docs.vertex.link/en/latest/synapse/devguides/stormservices.html#minimal-storm-service-example) in the Synapse docs.
- `hatching`
  - Enrich from and submit to Hatching Triage Sandbox (tria.ge).
- `ipinfo`
  - Enrich from ipinfo.io.
- `mandiant`
  - Enrich from Mandiant Advantage.
- `malbazaar`
  - Enrich from MalwareBazaar.
- `maxmind`
  - Enrich from Maxmind.
- `mxtoolbox`
  - Enrich from MXToolbox.
- `scraper`
  - Ingest and scrape a list of configured blogs, websites, social media accounts/searches.
- `shodan`
  - Enrich from Shodan.
- `snort`
  - Match PCAPs stored in `file:bytes` nodes against `rule:snort`/`rule:suricata` nodes.
- `virustotal`
  - Enrich from VT.
- `yara`
  - Support for matching `rule:yara` nodes to `file:bytes` nodes.

# stormsvcs

A collection of custom Storm services.

This is a monorepo of custom Storm services I've developed for personal projects. Each service lives as it's own package under `svcs/`.

Shared utility code lives upstream in the StormLib++ project. Each service should be treated as a standalone project, they can intercommunicate if desired (like the ``enrich`` package), but they must be workable and installable individually.

Actions run specific to each service, each service must maintain its own actions to build and test code + build and deploy docker images. However, a push to main requires that all tests pass regardless of which code is edited. The all in one testing action will call a registered test action for each service, as some services require custom environments/image builds.

All original code in this repo is covered under the same MIT license (see ``LICENSE``).

Each service must have the following:
- An entry in `services.toml` pointing to that service's:
	- unique name
		- can be different from the services folder name if desired
	- path to the service's source code
	- path to the service's CI workflow
- A uniquely named folder under `svcs/` that has:
	- A `README.md` file.
	- `pyproject.toml` and `uv.lock` file
		- Each service will manage its own dependencies.
		- A global `uv.lock` file will exist for the sake of ensuring the project wide development dependencies (`uv`, `tox`, `pylint`, etc.) are easily managed.
		- All services will depend on at least `stormlibpp` (and can inherit that packages `synapse` dependency)
	- A folder named `src/` that has all python and storm code for the Storm Service
	- A folder named `tests/` that has:
		- At least 1 pytest test
		- No default tests that call out to external services for testing
			- An optional gate is allowed to run external tests locally
	- A folder named `docker/` that defines a docker image for the service.
- A CI workflow that tests and builds the service
	- It must also build the docker image.
	- It must only run on PRs when the service's folder is changed AND with a "workflow_run" flag AND with a manual run flag.
- An entry in the global CI workflow pointing to the service's CI workflow.
	- This will run on every merge to main.

## Services Wish List/Plan

This is a ToDo/wish list, check `services.toml` for the current list of developed services.

- `bytes`
  - Search various sources for available bytes for a given `hash:*` node.
- `capa`
  - Process files with Capa.
- `enrich`
  - Enrich any supported node from all possible enrichment sources.
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
- `unattrib`
	- Make unattrib HTTP and socks proxy requests from within Synapse
- `spamhaus`
	- Maintain a local copy of SPAMHAUS's abuse data sets
- `crt.sh`
	- Search for and download metadata on SSL certificates from the crt.sh transparency service.

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
		- The root `pyproject.toml` and `uv.lock` only hold the repo's development tools (`ruff`, the ruff config every service uses, `pytest`), not service code.
		- All services depend on at least `stormlibpp` (and inherit its `synapse` dependency). The versions every service must lock are in the `[contract]` table of `services.toml`.
		- Bootstrap the service folder with: `uv init --no-workspace --lib --build-backend uv --vcs none  --no-pin-python`
	- A folder named `src/` that has all python and storm code for the Storm Service
		- The service's `CellApi` subclasses `stormlibpp.svc.RetnApi`, so every API method returns a `TelepathRetn` instead of raising to Storm.
	- A folder named `tests/` that has:
		- At least 1 pytest test
		- A `conftest.py` that enables StormLib++'s test plugin (`pytest_plugins = ["stormlibpp.testing"]`), which fails any test that uses a deprecated Synapse API.
		- Tests that call `stormlibpp.testing`'s `assertVersionsMatch()` and `assertMainHelp()`.
		- No default tests that call out to external services for testing
			- An optional gate is allowed to run external tests locally
	- A folder named `docker/` that defines the service's images:
		- `docker/prod/Dockerfile`, built `FROM ${BASE_IMAGE}` (an `ARG` declared before the first `FROM`, defaulting to the published base image).
		- `docker/test/Dockerfile`, built `FROM ${BASE_IMAGE}` too (defaulting to the service's published image), which runs the tests in the image.
	- A LICENSE file that is a symlink of this repo's LICENSE file (`ln -s ../../LICENSE LICENSE`)
	- A folder named `docs/` with the service's documentation in Markdown (MyST), starting at `docs/index.md`. See [Documentation](#documentation).
- A CI workflow that tests and builds the service
	- It must also build the docker image.
	- It must only run on PRs when the service's folder is changed, AND be callable (`workflow_call`) AND manually runnable (`workflow_dispatch`).
	- Call the reusable `.github/workflows/_service.yml` pipeline instead of defining jobs, copy `.github/workflows/virustotal.yml` and change the service name.
		- It expects `svcs/<service>/docker/prod/Dockerfile` (override with the `dockerfile` input) and tags the image `latest`, the `pyproject.toml` version, and the commit SHA.
		- Its inputs: `docker_tests: true` runs the tests in the test image, built on the new prod image (every service sets it). `storm_lint` is `report` (default), `block` (fail on any Storm lint finding, set it once a service lints clean) or `off`. `apt-packages` installs system packages the host test job needs.
		- On PRs the image is uploaded as a build artifact; it is only pushed to GHCR from `main`.
- An entry in the global CI workflow (`.github/workflows/_main.yml`) pointing to the service's CI workflow.
	- This runs on every push to main (including merged PRs) and publishes every service's image.
	- If the base image (`docker/`) changed, `_main.yml` rebuilds and pushes it first so the services build on it.
	- A PR that changes the base image also builds every service's prod image on the new base (`_base-image.yml`), before it's published.
	- `_main.yml` also runs weekly, rebuilding the base image and every service so system package updates land.
- `python3 scripts/check_svcs.py` passes for the service. It checks every service against the rules above (the "service contract"), and the Service Contract workflow runs it on every PR. `services.toml`'s `[contract]` table lists the enforced rules.
- All services, and their storm commands/modules, should namespace under `slib` (ex: `slib.yara`).
	- This is because all services here should be seen as the Advanced Power-Up extensions for the [StormLib++](https://github.com/gormaniac/stormlibpp) project which uses this same namespace.
		- Be careful of naming conflicts here.

# Documentation

The documentation site is at [docs.gormo.co/stormsvcs](https://docs.gormo.co/stormsvcs/): a deployment, command, data model, API, and internals reference for every service, plus the stormsvcs developer guide. It's built with Sphinx, MyST, and the Shibuya theme (like StormLib++ and the rest of docs.gormo.co) from:

- `docs/`: the home page, the Sphinx config, and the developer guide (`docs/dev/`).
- `svcs/<svc>/docs/`: each service's pages.

Build it locally (the output is in `build/docs/`):

```bash
uv run --group docs python scripts/build_docs.py
```

The `Docs` workflow builds it on every PR that touches the docs (warnings fail the build) and publishes it from `main`, as the `docs.tar.gz` asset on this repo's rolling `docs` release, which docs.gormo.co pulls. See `docs/dev/docs.md`.

# Services

- `yarastorm`
  - Support for matching `it:app:yara:rule` nodes to `file:bytes` nodes.
- `crtsh`
  - Look up, search, and pivot on certificates straight from the crt.sh certwatch database.
- `shodan`
  - Every Shodan API: host lookups, search, scanning, alerts, DNS, streaming, InternetDB, CVEDB, exploits, and trends.
- `abusech`
  - Every abuse.ch platform: MalwareBazaar, URLhaus, ThreatFox, YARAify, Feodo Tracker, SSL Blacklist, and the false positive list.
- `capa`
  - Run Mandiant's capa against files in the Axon, model the matched rules, and tag files with the rule namespaces.
- `pcap`
  - Analyze PCAPs (pcap, pcapng, gzip): model their network flows as `inet:flow` nodes with DNS, certificates, SSH keys, software, and transferred files (Suricata, tshark), and match them against Snort and Suricata rules from feeds or the graph, with every engine sandboxed.
- `hatching`
  - The whole Hatching Triage Sandbox API: submit files and URLs, model analyses (configs, processes, network, dropped files), download samples/pcaps/dropped files, and manage profiles, Yara rules, and users.
- `malpedia`
  - Keep Malpedia's library (`media:news`), threat actors (`risk:threat`), malware families (`risk:tool:software`), and YARA rules (`it:app:yara:rule`) in sync, with one bulk pull on registration and small daily updates from the public API.
- `bgphe`
  - Hurricane Electric's BGP Toolkit (bgp.he.net): CT log certificates by domain, subdomain, or IP, domain whois (RDAP, or whois text) and ASN whois (the org behind an ASN), and the prefixes an ASN originates.
- `virustotal`
  - The VirusTotal Public (community) API: enrich files, URLs, domains, and IPs (AV scans, sandbox verdicts, crowdsourced YARA/IDS/Sigma, DNS, whois, certs, behaviour), pivot on relationships, and submit, rescan, comment, and vote, all within the Public API's 4/minute and 500/day limits.

## Moved to StormLib++

These were services here, and are now pure Storm Rapid Power-Ups in [StormLib++](https://github.com/gormaniac/stormlibpp), with nothing to deploy:

- `ip_api` is the `slib.ipapi` package, version 1.1.0 or later (which has everything the service's last version, 0.3.0, did). Its commands, perms and settings are the same, and the service's `ipapi:apikey` option is now the `slib.ipapi.admin.apikey` command. To upgrade, remove the service with `service.del` and load the `slib.utils` and `slib.ipapi` packages.

## Services Wish List/Plan

This is a ToDo/wish list, check `services.toml` for the current list of developed services.

- `bytes`
  - Search various sources for available bytes for a given `hash:*` node.
- `enrich`
  - Enrich any supported node from all possible enrichment sources.
- `ipinfo`
  - Enrich from ipinfo.io.
- `mandiant`
  - Enrich from Mandiant Advantage.
- `maxmind`
  - Enrich from Maxmind.
- `mxtoolbox`
  - Enrich from MXToolbox.
- `scraper`
  - Ingest and scrape a list of configured blogs, websites, social media accounts/searches.
- `unattrib`
	- Make unattrib HTTP and socks proxy requests from within Synapse
- `spamhaus`
	- Maintain a local copy of SPAMHAUS's abuse data sets

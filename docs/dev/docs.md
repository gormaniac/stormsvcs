# Writing Docs

This site is built with [Sphinx](https://www.sphinx-doc.org/), the
[MyST](https://myst-parser.readthedocs.io/) Markdown parser and the
[Shibuya](https://shibuya.lepture.com/) theme. That's the same stack and theme options as
[StormLib++](https://docs.gormo.co/stormlibpp/) and docs.gormo.co, so the pages match.
It's published at `https://docs.gormo.co/stormsvcs/`.

## Where the docs live

| Source | On the site |
| --- | --- |
| `docs/index.md` | The home page |
| `docs/dev/*.md` | This developer guide, `/dev/` |
| `svcs/<svc>/docs/*.md` | Each service's pages, `/<key>/`, where `key` is its `services.toml` key |
| `services.toml` (generated) | `/services/`, the service index, and the header's Services menu |
| `docs/conf.py` | The Sphinx config and theme options |

The docs sit next to what they document, so a PR that changes a service can update its
docs in the same diff. A service's `README.md` is still the short user guide that ships in its
Storm package. Its `docs/` pages are the full reference.

## Building

`scripts/build_docs.py` is the single build entry point. Sphinx only reads one source tree,
so the script stages one in `build/docs-src/`. It copies `docs/`, copies each service's `docs/` to
`<key>/`, and generates `services.md` and `_services.json` (the service metadata that `conf.py`
reads for the Services menu). Then it runs `sphinx-build -b dirhtml -W --keep-going`, so
**every warning is an error**: a broken link, a page that isn't in a toctree, a bad heading
level, an unknown code lexer.

```bash
uv run --group docs python scripts/build_docs.py                 # the whole site, to build/docs/
uv run --group docs python scripts/build_docs.py virustotal      # just one service, faster
uv run --group docs python scripts/build_docs.py --tar build/docs.tar.gz
python3 -m http.server -d build/docs                             # then browse localhost:8000
```

The `docs` dependency group in the root `pyproject.toml` pins the toolchain (Sphinx,
`myst-parser`, `shibuya`) through the root `uv.lock`. `--tar` writes the site the way
docs.gormo.co expects `docs.tar.gz`, with the files at the archive's top level. CI builds it
on every docs PR and publishes it from `main` (see {doc}`ci`).

## A service's pages

Every service has the same set of pages, so readers know where to look:

| Page | For | Covers |
| --- | --- | --- |
| `index.md` | Everyone | What it does, the feature overview, the architecture summary, quick start, the toctree |
| `deployment.md` | Admins | The image, cell config, secrets, volumes, egress, compose, `service.add`, perms, upgrades |
| `commands.md` | Analysts | Every Storm command: options, defaults, perms, inputs, outputs, examples |
| `model.md` | Analysts, developers | Every form, prop, tag and edge written, and how upstream fields map to them |
| `api.md` | Developers | The Storm modules and the Telepath API: methods, args, `data` shapes, errors |
| `internals.md` | Developers | Module by module: the upstream client, state, background tasks, error handling, tests |

Large services split commands across several pages or add pages for big subsystems, such as
pcap's rule engines and sandbox. Every page must be in the service `index.md`'s toctree.

**Write from the code, not the README.** Every option, default, permission and form on these
pages must exist in the source. Update the docs in the same PR as the code change, and bump
the service's version as usual (see {doc}`versioning`).

The `docs` contract rule checks that every service has `docs/index.md`.

## MyST conventions

- One `#` heading per page, as its first line, with no skipped levels.
- Link to sibling pages with `[text](commands.md)` or `[text](commands.md#a-heading)`. Heading
  anchors are generated down to `###`.
- Link to this guide from a service page with an absolute doc path:
  `` {doc}`/dev/testing` ``.
- Link to a file in the repo with `` {src}`svcs/vt/src/vtsvc/quota.py` ``, and to a PR or issue
  with `` {gh}`55` ``.
- Storm code goes in ` ```text ` fences, because Pygments has no Storm lexer and an unknown lexer
  is a build error. Use `bash`, `yaml`, `json` and `python` where they fit.
- Admonitions use colon fences: `:::{note}` ... `:::` (also `warning`, `tip`, `important`).
- Escape `|` inside table cells as `\|`.

## Publishing on docs.gormo.co

docs.gormo.co pulls this site from the `docs` release's `docs.tar.gz`. For that to happen,
its `projects.txt` has to list `https://github.com/gormaniac/stormsvcs`. To link the site from
the docs.gormo.co header, add it to the `Storm Services` menu in that repo's `doc/conf.py`
with `"url": "stormsvcs"`.

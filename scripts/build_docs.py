#!/usr/bin/env python3
"""Build the stormsvcs documentation site.

The site has three parts, each written in Markdown (MyST) and kept next to what it documents:

- ``docs/``: the site's home page, the Sphinx config (``docs/conf.py``), and the stormsvcs
  developer documentation (``docs/dev/``).
- ``svcs/<svc>/docs/``: each service's own documentation, starting at its ``index.md``.
- ``services.toml``: the list of services. Every registered service is built into the site,
  at ``/<key>/`` (ex. ``https://docs.gormo.co/stormsvcs/virustotal/``).

Sphinx only reads one source tree, so this script stages the parts into one (``<out>-src``,
``build/docs-src`` by default). It copies ``docs/``, copies each service's ``docs/`` folder to
``<key>/``, and generates ``services.md`` (the service index) and ``_services.json`` (read by
``conf.py`` for the header's Services menu). Then it runs ``sphinx-build -b dirhtml`` with
warnings as errors, so a broken link or toctree fails the build.

Usage (from the repo root, with the root project's ``docs`` dependency group):

    uv run --group docs python scripts/build_docs.py [--out DIR] [--tar FILE] [SERVICE ...]

SERVICE limits the build to those services (their services.toml keys), for quick local
iteration on one service's pages; the full site always builds every service. --tar also
writes the built site as a gzipped tarball, laid out the way docs.gormo.co expects its
``docs.tar.gz`` release asset (the site's files at the archive's top level).
"""

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def _services() -> list[dict]:
    """Each service registered in services.toml, with what the site needs to know about it."""
    conf = tomllib.loads((ROOT / "services.toml").read_text())
    svcs = []
    for key, entry in conf.get("stormsvcs", {}).items():
        src = ROOT / entry["src"]
        project = tomllib.loads((src / "pyproject.toml").read_text())["project"]
        svcs.append(
            {
                "key": key,
                "name": entry.get("name", key),
                "src": entry["src"].strip("/"),
                "docs": src / "docs",
                "version": project.get("version", ""),
                "summary": entry.get("summary") or project.get("description", ""),
            }
        )
    return svcs


def _servicesPage(svcs: list[dict]) -> str:
    """The generated services.md: a table of every service, and the toctree that adds them."""
    lines = [
        "# Services",
        "",
        "Every service in the monorepo, generated from `services.toml`. Each is its own",
        "Synapse Advanced Power-Up, deployed and versioned on its own.",
        "",
        "| Service | Storm package | Version | Summary |",
        "| --- | --- | --- | --- |",
    ]
    for svc in svcs:
        pkg = next((ROOT / svc["src"]).glob("src/*/pkgproto/*.yaml"), None)
        pkgname = f"`{pkg.stem}`" if pkg else ""
        summary = svc["summary"].replace("|", "\\|")
        lines.append(
            f"| [{svc['name']}]({svc['key']}/index.md) | {pkgname} | {svc['version']} | {summary} |"
        )
    lines += ["", "```{toctree}", ":hidden: true", ":maxdepth: 2", ""]
    lines += [f"{svc['name']} <{svc['key']}/index>" for svc in svcs]
    lines += ["```", ""]
    return "\n".join(lines)


def stage(dest: pathlib.Path, svcs: list[dict]) -> None:
    """Assemble the Sphinx source tree in dest from docs/ and each service's docs/."""
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(DOCS, dest, ignore=shutil.ignore_patterns("_build", "__pycache__"))
    for svc in svcs:
        if not (svc["docs"] / "index.md").is_file():
            raise SystemExit(f"{svc['src']}/docs/index.md doesn't exist.")
        target = dest / svc["key"]
        if target.exists():
            raise SystemExit(f"docs/{svc['key']} collides with the {svc['key']} service's docs.")
        shutil.copytree(svc["docs"], target)
    (dest / "services.md").write_text(_servicesPage(svcs))
    meta = [{k: v for k, v in s.items() if k != "docs"} for s in svcs]
    (dest / "_services.json").write_text(json.dumps(meta, indent=2))


def build(src: pathlib.Path, out: pathlib.Path) -> int:
    """Run sphinx-build on the staged tree, with warnings as errors."""
    if out.exists():
        shutil.rmtree(out)
    # The doctree cache goes in the staging tree, so it isn't published with the site.
    cmd = [sys.executable, "-m", "sphinx", "-b", "dirhtml", "-W", "--keep-going", "-q"]
    cmd += ["-d", str(src / ".doctrees")]
    return subprocess.call([*cmd, str(src), str(out)])


def tar(out: pathlib.Path, path: pathlib.Path) -> None:
    """Write the built site to a gzipped tarball, its files at the archive's top level."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as fd:
        for child in sorted(out.iterdir()):
            fd.add(child, arcname=child.name)


def main(argv: list[str]) -> int:
    pars = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    pars.add_argument("--out", default="build/docs", help="Where to write the site.")
    pars.add_argument("--tar", help="Also write the site to this .tar.gz file.")
    pars.add_argument("services", nargs="*", help="Only build these services (their keys).")
    opts = pars.parse_args(argv)

    svcs = _services()
    if opts.services:
        unknown = set(opts.services) - {s["key"] for s in svcs}
        if unknown:
            pars.error(f"not in services.toml: {', '.join(sorted(unknown))}")
        svcs = [s for s in svcs if s["key"] in opts.services]

    out = (ROOT / opts.out).resolve()
    src = out.with_name(out.name + "-src")
    stage(src, svcs)
    code = build(src, out)
    if code:
        print(f"sphinx-build failed ({code}), see the warnings above.", file=sys.stderr)
        return code
    if opts.tar:
        tar(out, (ROOT / opts.tar).resolve())
    print(f"Built the docs site in {out.relative_to(ROOT)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

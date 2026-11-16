#!/usr/bin/env python3
"""Check every service under svcs/ against the repo's service contract.

The contract is what every service must do the same way: how it's registered and built in
CI, which Synapse and StormLib++ it's locked to, and which shared StormLib++ pieces it uses
instead of its own copy. It lives in code here, and its settings in the [contract] table of
services.toml, so it doesn't drift the way per-service copies and prose conventions did.

Each rule is either enforced (listed in [contract].enforce, a failure fails this script) or
reported (shown, but doesn't fail). A rule moves to enforce once every service passes it. A
service can be exempted from a rule in its services.toml entry, with a reason:

    [stormsvcs.capa.exempt]
    docker-tests = "The full capa rules are only in the image."

Usage:
    python3 scripts/check_svcs.py [--summary FILE] [--strict] [SERVICE ...]

--summary appends a Markdown report (ex. to $GITHUB_STEP_SUMMARY). --strict enforces every
rule. Only needs the standard library, Python 3.11 or later.
"""

import argparse
import dataclasses
import pathlib
import re
import sys
import tomllib
from collections.abc import Callable

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _vtuple(ver: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", ver)[:3])


@dataclasses.dataclass
class Svc:
    """One service under svcs/, and what the rules need to know about it."""

    dirname: str
    key: str | None  # Its key in services.toml, if it's listed.
    entry: dict

    @property
    def path(self) -> pathlib.Path:
        return ROOT / "svcs" / self.dirname

    def read(self, rel: str) -> str:
        path = self.path / rel
        return path.read_text() if path.is_file() else ""

    @property
    def pyproject(self) -> dict:
        return tomllib.loads(self.read("pyproject.toml") or "")

    @property
    def pkgdirs(self) -> list[pathlib.Path]:
        return sorted(p.parent for p in self.path.glob("src/*/__init__.py"))

    def locked(self, name: str) -> str | None:
        lock = tomllib.loads(self.read("uv.lock") or "")
        for pkg in lock.get("package", []):
            if _norm(pkg.get("name", "")) == _norm(name):
                return pkg.get("version")
        return None

    @property
    def workflow(self) -> pathlib.Path:
        rel = self.entry.get("workflow") or f".github/workflows/{self.dirname}.yml"
        return ROOT / rel

    def glob(self, pattern: str) -> list[pathlib.Path]:
        return sorted(self.path.glob(pattern))


# A rule returns a list of problems, empty when the service passes.
Rule = Callable[[Svc, dict], list[str]]
RULES: dict[str, tuple[str, Rule]] = {}


def rule(name: str, desc: str):
    def wrap(func: Rule) -> Rule:
        RULES[name] = (desc, func)
        return func

    return wrap


@rule("registered", "Listed in services.toml, with a workflow that _main.yml runs.")
def _registered(svc: Svc, contract: dict) -> list[str]:
    probs = []
    if svc.key is None:
        return [f"No [stormsvcs.*] entry in services.toml has src = 'svcs/{svc.dirname}/'."]
    if not svc.workflow.is_file():
        probs.append(f"Workflow {svc.workflow.relative_to(ROOT)} doesn't exist.")
    else:
        text = svc.workflow.read_text()
        if "./.github/workflows/_service.yml" not in text:
            probs.append(f"{svc.workflow.name} doesn't call _service.yml.")
        if not re.search(rf"^\s*service:\s*{re.escape(svc.dirname)}\s*$", text, re.MULTILINE):
            probs.append(f"{svc.workflow.name} doesn't pass service: {svc.dirname}.")
    main = (WORKFLOWS / "_main.yml").read_text()
    if f"./.github/workflows/{svc.workflow.name}" not in main:
        probs.append(f"_main.yml doesn't run {svc.workflow.name}.")
    return probs


@rule("workflow-paths", "The workflow's PR path filter covers everything its pipeline reads.")
def _workflowPaths(svc: Svc, contract: dict) -> list[str]:
    if not svc.workflow.is_file():
        return ["No workflow."]
    text = svc.workflow.read_text()
    need = [
        f"svcs/{svc.dirname}/**",
        f".github/workflows/{svc.workflow.name}",
        ".github/workflows/_service.yml",
        "pyproject.toml",
    ]
    return [
        f"pull_request.paths is missing {p!r}."
        for p in need
        if not re.search(rf"""^\s*-\s*["']{re.escape(p)}["']""", text, re.MULTILINE)
    ]


@rule("versions", "The version matches in pyproject.toml, __init__.py, pkgproto and uv.lock.")
def _versions(svc: Svc, contract: dict) -> list[str]:
    project = svc.pyproject.get("project", {})
    found = {"pyproject.toml": project.get("version")}
    for pkg in svc.pkgdirs:
        if m := re.search(
            r"""^__version__\s*=\s*["']([^"']+)["']""",
            (pkg / "__init__.py").read_text(),
            re.MULTILINE,
        ):
            found[f"{pkg.name}/__init__.py"] = m.group(1)
        for proto in sorted(pkg.glob("pkgproto/*.yaml")):
            if m := re.search(r"^version:\s*['\"]?([^\s'\"]+)", proto.read_text(), re.MULTILINE):
                found[f"pkgproto/{proto.name}"] = m.group(1)
    found["uv.lock"] = svc.locked(project.get("name", svc.dirname))
    if None in found.values() or len(set(found.values())) != 1:
        return ["Versions differ: " + ", ".join(f"{k}={v}" for k, v in found.items())]
    return []


@rule("pins", "Locked to the Synapse and StormLib++ versions in [contract].")
def _pins(svc: Svc, contract: dict) -> list[str]:
    probs = []
    want = contract.get("synapse")
    have = svc.locked("synapse")
    if want and have != want:
        probs.append(f"uv.lock has synapse {have}, the contract is {want}.")
    floor = contract.get("stormlibpp")
    have = svc.locked("stormlibpp")
    if floor and (have is None or _vtuple(have) < _vtuple(floor)):
        probs.append(f"uv.lock has stormlibpp {have}, the contract needs >= {floor}.")
    return probs


@rule("pkg-keys", "Storm packages don't use deprecated keys (synapse_minversion).")
def _pkgKeys(svc: Svc, contract: dict) -> list[str]:
    return [
        f"{p.relative_to(svc.path)} uses synapse_minversion, use synapse_version."
        for p in svc.glob("src/*/pkgproto/*.yaml")
        if re.search(r"^synapse_minversion:", p.read_text(), re.MULTILINE)
    ]


@rule("pytest-warnings", "pytest fails on the service's own DeprecationWarnings.")
def _pytestWarnings(svc: Svc, contract: dict) -> list[str]:
    opts = svc.pyproject.get("tool", {}).get("pytest", {})
    opts = opts.get("ini_options", opts)
    filters = opts.get("filterwarnings", [])
    return [
        f"pytest filterwarnings is missing 'error::DeprecationWarning:{pkg.name}'."
        for pkg in svc.pkgdirs
        if f"error::DeprecationWarning:{pkg.name}" not in filters
    ]


@rule(
    "docker-base-arg",
    "Prod and test Dockerfiles build FROM ${BASE_IMAGE}, so CI can test new images.",
)
def _dockerBaseArg(svc: Svc, contract: dict) -> list[str]:
    probs = []
    for rel in ("docker/prod/Dockerfile", "docker/test/Dockerfile"):
        text = svc.read(rel)
        if not text:
            probs.append(f"No {rel}.")
        elif not (
            re.search(r"^ARG BASE_IMAGE", text, re.MULTILINE) and "FROM ${BASE_IMAGE}" in text
        ):
            probs.append(f"{rel} doesn't take a BASE_IMAGE build arg.")
        else:
            # A FROM can only use an ARG declared before the first FROM (in the global scope).
            # Declared later, it's scoped to the stage above and ${BASE_IMAGE} is blank.
            arg = re.search(r"^ARG BASE_IMAGE", text, re.MULTILINE).start()
            first = re.search(r"^FROM\s", text, re.MULTILINE).start()
            if arg > first:
                probs.append(
                    f"{rel} declares ARG BASE_IMAGE after its first FROM, so FROM can't use it;"
                    " move it above the first FROM."
                )
    return probs


@rule("docker-tests", "The workflow runs the tests in the service's test image (docker_tests).")
def _dockerTests(svc: Svc, contract: dict) -> list[str]:
    text = svc.workflow.read_text() if svc.workflow.is_file() else ""
    if not re.search(r"^\s*docker_tests:\s*true\s*$", text, re.MULTILINE):
        return [f"{svc.workflow.name} doesn't set docker_tests: true."]
    return []


@rule("test-plugin", "tests/conftest.py uses the stormlibpp.testing plugin, not its own harness.")
def _testPlugin(svc: Svc, contract: dict) -> list[str]:
    text = svc.read("tests/conftest.py")
    probs = []
    if not re.search(r"""pytest_plugins\s*=.*["']stormlibpp\.testing["']""", text):
        probs.append("conftest.py doesn't set pytest_plugins = ['stormlibpp.testing'].")
    if "class _SynDeprecations" in text:
        probs.append("conftest.py still has its own copy of the deprecation harness.")
    return probs


@rule("version-test", "A test calls stormlibpp.testing's assertVersionsMatch().")
def _versionTest(svc: Svc, contract: dict) -> list[str]:
    if any("assertVersionsMatch(" in p.read_text() for p in svc.glob("tests/**/*.py")):
        return []
    return ["No test calls assertVersionsMatch()."]


@rule("main-test", "A test calls stormlibpp.testing's assertMainHelp() on the entry point.")
def _mainTest(svc: Svc, contract: dict) -> list[str]:
    if any("assertMainHelp(" in p.read_text() for p in svc.glob("tests/**/*.py")):
        return []
    return ["No test calls assertMainHelp()."]


@rule("retn-api", "The CellApi uses stormlibpp.svc.RetnApi, so errors can't escape to Storm.")
def _retnApi(svc: Svc, contract: dict) -> list[str]:
    srcs = svc.glob("src/*/*.py")
    if any(re.search(r"class \w+\(\s*RetnApi\b", p.read_text()) for p in srcs):
        return []
    return ["No CellApi subclasses stormlibpp.svc.RetnApi."]


def load() -> tuple[dict, list[Svc]]:
    conf = tomllib.loads((ROOT / "services.toml").read_text())
    entries = conf.get("stormsvcs", {})
    bysrc = {}
    for key, entry in entries.items():
        src = entry.get("src", "").strip("/")
        bysrc[src.removeprefix("svcs/")] = (key, entry)
    svcs = []
    for path in sorted((ROOT / "svcs").iterdir()):
        if path.is_dir() and (path / "pyproject.toml").is_file():
            key, entry = bysrc.get(path.name, (None, {}))
            svcs.append(Svc(path.name, key, entry))
    return conf.get("contract", {}), svcs


def main(argv: list[str]) -> int:
    pars = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    pars.add_argument("--summary", help="Append a Markdown report to this file.")
    pars.add_argument("--strict", action="store_true", help="Enforce every rule.")
    pars.add_argument("services", nargs="*", help="Only check these services (svcs/ names).")
    opts = pars.parse_args(argv)

    contract, svcs = load()
    if opts.services:
        svcs = [s for s in svcs if s.dirname in opts.services]
    enforce = set(RULES) if opts.strict else set(contract.get("enforce", []))
    unknown = enforce - set(RULES)
    if unknown:
        print(f"services.toml [contract].enforce has unknown rules: {sorted(unknown)}")
        return 2

    results: dict[str, dict[str, list[str] | str]] = {}
    failed = False
    for svc in svcs:
        exempt = svc.entry.get("exempt", {})
        results[svc.dirname] = {}
        for name, (_, func) in RULES.items():
            if name in exempt:
                results[svc.dirname][name] = f"exempt: {exempt[name]}"
                continue
            probs = func(svc, contract)
            results[svc.dirname][name] = probs
            if probs and name in enforce:
                failed = True

    for svc, res in results.items():
        bad = {n: p for n, p in res.items() if isinstance(p, list) and p}
        mark = "FAIL" if any(n in enforce for n in bad) else ("todo" if bad else "ok")
        print(f"{mark:4} {svc}")
        for name, probs in bad.items():
            level = "error" if name in enforce else "todo"
            for prob in probs:
                print(f"       [{level}] {name}: {prob}")

    if opts.summary:
        names = list(RULES)
        lines = [
            "## Service contract",
            "",
            "✅ passes · ❌ fails an enforced rule · ⏳ fails a rule that isn't enforced yet · ➖ exempt",
            "",
            "| Rule | " + " | ".join(results) + " |",
            "| --- | " + " | ".join("---" for _ in results) + " |",
        ]
        for name in names:
            cells = []
            for res in results.values():
                val = res[name]
                if isinstance(val, str):
                    cells.append("➖")
                elif not val:
                    cells.append("✅")
                else:
                    cells.append("❌" if name in enforce else "⏳")
            tag = "" if name in enforce else " (not enforced)"
            lines.append(f"| `{name}`{tag} | " + " | ".join(cells) + " |")
        lines += ["", "Rules:", ""]
        lines += [f"- `{n}`: {d}" for n, (d, _) in RULES.items()]
        with open(opts.summary, "a") as fd:
            fd.write("\n".join(lines) + "\n")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

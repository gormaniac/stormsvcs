# Storm Services GitHub Copilot Instructions

## Architecture Overview

The stormsvcs repo is a monorepo containing a collection of "Advanced Power-Ups" (or Storm Services) for The Vertex Project's Synapse framework. These Power-Ups are implemented as Python apps extending Synapse's Cell object. Each service comes with Storm code to expose the service's functionality to Synapse users. The services are designed to be run in a containerized environment, registered with a Synapse Cortex, and they communicate with a Storm runtime via Telepath.

### Core Components and Project Structure

As a monorepo, the stormsvcs repo contains multiple services, each with its own directory. Each service is considered self-contained and is expected to be able to run independently of the other services. The monorepo provides convenient organization, but it does not expose shared code for all services to rely on. Shared library code should be implemented in the StormLib++ project, a dependency all services must rely on. With that said, the monorepo does the following:
- A `services.toml` file for service metadata registration. Its `[contract]` table also sets the Synapse and StormLib++ versions every service must lock, and which contract rules CI enforces.
- `scripts/check_svcs.py`, which checks every service against the service contract (registration, versions, pins, Docker and CI setup, and use of the shared StormLib++ pieces). The Service Contract workflow runs it on every PR; run `python3 scripts/check_svcs.py` before opening one.
- A docker base image in `docker/` that all services must use as a starting point for their own Dockerfile (`FROM ${BASE_IMAGE}`, see the root README). It installs uv and system packages, not Synapse or StormLib++; each service locks its own.
- A global `pyproject.toml` and `uv.lock` file for the repo's development tools (ruff and its config).
- GitHub Actions workflows for building, testing, and publishing all services.
- All services located under the `svcs/` directory, with each service in its own subdirectory.

Each service in the stormsvcs repo typically consists of the following core components:

- Cell Implementation:
  - A Python class that extends `synapse.lib.cell.Cell` and implements the service's external-to-Synapse functionality.
  - Exposed to Synapse via Telepath RPC, so select service methods can be called from Storm code.
  - Located in the `src/<service_name>/svc.py` file. Relies on `defs.py` and `api.py` for service metadata and Telepath API definitions.
- Storm Code:
  - A "Rapid Power-Up" (Storm Package) that exposes the service's functionality to Synapse users as a collection of Storm commands and modules.
  - The goal is to have the Python service own as much of the compute as possible and the Storm code own the entrypoint to the service and the translation of the service's data into Synapse models.
  - Located in the `src/<service_name>/pkgproto` directory.
- Docker Image:
  - A Dockerfile that builds a container image for the service, allowing an all in one deployment of the service and its dependencies.
  - Located in the `docker/` directory.
- Tests:
  - Unit tests for the service's Python and Storm code.
  - Located in the `tests/` directory.
- Extras:
  - A service specific `pyproject.toml` and `uv.lock` file for service dependencies.
  - A `docs/` folder with the service's full documentation (MyST Markdown, starting at `docs/index.md`: deployment, commands, data model, API, and internals), built into https://docs.gormo.co/stormsvcs/ by `scripts/build_docs.py`. See `docs/dev/docs.md`.
  - A `README.md` file for service specific documentation, which names every Storm command. A copy lives at `src/<service_name>/pkgproto/README.md` so it's packaged into the service's Storm Package and shown to the Storm user; a test checks the two match.

## Key Patterns and Conventions

### Error Handling
- Python library code should raise exceptions and let the caller handle them. The service's `CellApi` must subclass `stormlibpp.svc.RetnApi`, which turns every exception into a `status=False` `TelepathRetn` so the Storm code can always report it. List the cell's methods in `RETN_METHS`/`GENR_METHS`, and the error types whose message is meant for the user in `RETN_ERRORS` (or subclass `stormlibpp.svc.SvcError`). Anything else is logged with its traceback and returned as "Unexpected error: ...". Override `_retnRedact()` to scrub secrets from error messages.
- Validate values from Storm that end up in a file path with `stormlibpp.svc.safeJoin()`, `checkName()` or `checkGuid()`.
- Storm code can raise exceptions where it makes sense, especially in library code, but should handle exceptions gracefully in user-facing code.
  - Errors should be logged via the Storm `$lib` functions, these allow for both user facing and application facing logging in one message.
  - Storm code should check for the `$lib.debug` flag and log additional information when it is set. This allows for more verbose logging in development and debugging scenarios without cluttering the logs in production.

### Coupling with StormLib++
- The `stormsvcs` repo should be thought as the "Advanced Power-Ups" extension of the StormLib++ project. All services should rely on StormLib++ for shared functionality and code reuse.
- Storm code that's better suited to be in a library should be implemented in the StormLib++ project's `slib.utils` Storm Package and imported into the service's storm package. This allows for a more modular design and encourages code reuse.
- Each service uses `stormlibpp.svc.RetnApi` for its Telepath API, `stormlibpp.telepath`'s `TelepathRetn` types for its return values, and the `stormlibpp.testing` pytest plugin in its tests. These primitives were designed to make Storm Service development easier.
- Since this is an extension of the StormLib++ project, all Storm Services and Storm Packages should rely on the `slib` prefix for names exposed to Synapse. 

### Storm Considerations
- Packages should be configurable by users via Storm command options. This allows for more flexibility and customization of the service's functionality. 
  - Such as tag prefixes, default values, and other options that can be set by the admin.
  - Validate settings when they're set, ex. a tag prefix with `$lib.trycast(syn:tag, $prefix)`, instead of letting every later use fail.
  - These should be gated behind an admin check to ensure only authorized users can modify them.
  - Sane defaults should be provided for all options, so the service can be used out of the box without requiring configuration.
- Storm is a custom language designed for the Synapse framework. While its primary purpose is as a query language, it's a fully featured programming language with functions, variables, control flow, and a limited built-in standard library. Storm code should be written in a way that is idiomatic to the language and takes advantage of its features. 
  - The Synapse project itself provides a SKILL.md file around the Storm language and its features. This should be used as a reference for writing Storm code. See [synapse/data/skills/storm/SKILL.md](https://raw.githubusercontent.com/vertexproject/synapse/refs/heads/master/synapse/data/skills/storm/SKILL.md).
- In the context of a Storm Service, storm code is the entrypoint to the service and should be responsible for translating the service's data into Synapse models. The Python code should own as much of the compute as possible, while the Storm code should be responsible for orchestrating the service's functionality and exposing it to the user.
- Storm can be called by the user in a CLI/UI context or programmatically by various automations. Storm code should be written in a way that is application friendly (module functions should raise exceptions) and user friendly (user facing code should handle exceptions gracefully and provide meaningful feedback to the user).
  - Storm commands should avoid raising raw exceptions or quitting the storm runtime unless this is explicitly the desired behavior. As commands are often called by both users and programs.

### Telepath API Return Object
A `TelepathRetn` object is a dictionary with the following keys:
  - `status`: A boolean indicating whether the call was successful or not.
  - `mesg`: A string containing the error message if the call was not successful.
  - `data`: The return data from the call if it was successful.

This concept was introduced in Synapse example code and old "how-tos" but is now codified by the StormLib++ project. All services should use this pattern for their Telepath API return objects. 

### Code Style
- Camel casing is preferred when writing both Storm and Python code in the context of Synapse. In fact, any Storm code (or Python functions exposed directly to the Storm runtime) must be written in camel case. This is to maintain consistency with the Synapse project and its codebase.
- All Python functions/classes should be full documented with docstrings. This is to ensure that the code is maintainable and understandable by other developers. The docstrings should follow the [PEP 257](https://peps.python.org/pep-0257/) conventions. 
  - Static names should also be documented with docstrings, especially if they are exposed to the Storm runtime. 
- Lines should be kept to a maximum of 100 characters.
  - The ruff config in the root `pyproject.toml` sets this, and targets Python 3.11 (the services' Python) so `ruff check --fix` and `ruff format` never produce newer syntax.
  - Ruff lints and format-checks tests too (CI runs it on each whole service dir). Tests ignore only a few rules that flag test idioms, listed with their reasons in the root `pyproject.toml`'s `per-file-ignores`.
- Use type hints for all function signatures in Python code.

### Testing
- All code paths should have unit tests. This includes both Python and Storm code. The goal is to have a high level of test coverage to ensure the code is reliable and maintainable.
- No tests should call out to external services or APIs unless explicitly gated behind a test flag. This is to ensure that the tests are reliable and do not fail due to external factors.
- Mock data should be used for testing external service calls.
  - Most services test against a fake upstream server in `tests/` (ex. `tests/fakevt.py`) that serves the API's real response shapes on localhost; keep the fakes as strict as the real API, since a forgiving fake hides bugs. `vcr` (record and replay) is another option, but it isn't a Synapse dependency, so a service that uses it must declare `vcrpy` in its dev dependencies.
- Storm code is fully testable via the `synapse.tests.utils.StormPkgTest` class. This allows for testing Storm code in isolation without requiring a full Synapse runtime. The `StormPkgTest` class provides a way to load and execute Storm code in a controlled environment, allowing for reliable and repeatable tests.
- Tests fail when they use a deprecated Synapse API. Synapse logs its deprecations (deprecated Storm libs like `$lib.dict()`, deprecated model props, package keys, Python APIs) instead of raising Python warnings, so StormLib++'s test plugin collects them per test and fails the test, and fails the run for deprecations logged outside of a test (ex. at import time). Every service's `tests/conftest.py` enables it with `pytest_plugins = ["stormlibpp.testing"]`; don't copy the harness. Use `({})`/`([])` literals, `synapse_version` (not `synapse_minversion`), and `cmdinputs` (not `forms`) in Storm packages.
  - A test that has to exercise a deprecated API on purpose can opt out with `@pytest.mark.allow_synapse_deprecations`.
  - Every service also calls `stormlibpp.testing`'s `assertVersionsMatch()` (the version in all four places, see CLAUDE.md) and `assertMainHelp()` (the entry point starts).
  - Each service's `[tool.pytest]` config also turns Python `DeprecationWarning`s raised from its own package into errors.
  - Synapse's Storm linter reports deprecated and 3.x-incompatible Storm statically: `uv run python -m synapse.tools.storm.lint src/` (add `--v3-ready` for the 3.x migration rules). CI runs it for every service; a service that lints clean sets `storm_lint: block` in its workflow so it stays clean.
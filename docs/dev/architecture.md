# Architecture

Every service in stormsvcs has the same shape. This page describes that shape and the
StormLib++ pieces it's built on. Each service's own **Internals** page covers what is specific
to that service.

## The moving parts

```text
 Storm user / automation
        |
        |  slib.<svc>.* commands and modules (the service's Storm package)
        v
 +------------------+     Telepath (TLS or tcp, port 27492)     +---------------------+
 |  Synapse Cortex  | <---------------------------------------> |  Storm Service      |
 |  (Storm runtime) |   $lib.service.get(<name>).<meth>(...)    |  (a synapse Cell)   |
 +------------------+         returns TelepathRetn               +---------------------+
        |                                                               |        |
        | Axon (file bytes)                                             |        | HTTPS / Postgres / engines
        +-------------------------------------------------------------->|        v
                                                                        |   upstream API,
                                                    /vertex/storage  <--+   database or tool
```

- **The Cell** (`src/<pkg>/svc.py`) is a subclass of `synapse.lib.cell.Cell`. It holds the
  service's state (in `/vertex/storage`, a Docker volume), its upstream clients, and its
  config (`confdefs`). Everything expensive happens here: HTTP calls, parsing, running an
  analysis engine, normalising upstream data into node shapes.
- **The Telepath API** (`src/<pkg>/api.py`) is the Cell's `CellApi`: the methods the Cortex
  can call. It's also a `synapse.lib.stormsvc.StormSvc`, which is how the Cortex finds the
  Storm package and the service events to install when the service is added.
- **The Storm package** (`src/<pkg>/pkgproto/`): a Rapid Power-Up in YAML plus `.storm`
  files, loaded by `stormlibpp.StormPkg` (`src/<pkg>/defs.py`). It's the user's entry point.
  Its commands call the service, then turn the returned data into nodes, tags and edges. The
  goal is for Python to do as much of the computing as possible and for Storm to only orchestrate and model.
- **The image** (`docker/prod/Dockerfile`) is built on the repo's base image and runs
  `python -m <pkg> /vertex/storage` under `tini`.

## The Telepath contract: `TelepathRetn` and `RetnApi`

Storm can only report an error it gets back. If a Telepath method raises, the user sees an
opaque remote exception, and a Storm command that was halfway through a pipeline dies. So
**no API method raises**. Every method returns a `TelepathRetn`, or yields them if it's a
generator:

```python
class TelepathRetn(TypedDict):
    status: bool   # False means it failed
    mesg: str      # Set when status is False, the message to show the user
    data: Any      # The result when status is True
```

`stormlibpp.telepath` also defines typed subclasses (`BoolRetn`, `ListRetn`, `DictRetn`, ...)
so a method's signature says what `data` holds.

Every service's `CellApi` subclasses `stormlibpp.svc.RetnApi`, put first in the bases:

```python
from stormlibpp.svc import RetnApi

class MySvcApi(RetnApi, s_cell.CellApi, s_stormsvc.StormSvc):
    _storm_svc_name = SVC_NAME          # ex. "slib.vt"
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS          # Storm run on the "add" event, ex. a meta:source node
    _storm_svc_pkgs = PKGDEFS           # The Storm package(s), from defs.py

    RETN_METHS = ("lookup", "search")   # Cell coroutines, each result wrapped in a TelepathRetn
    GENR_METHS = ("export",)            # Cell async generators, each item wrapped
    RETN_ERRORS = (MySvcError,)         # Errors whose message goes to the user as-is

    def _retnRedact(self, mesg: str) -> str:
        return mesg.replace(self.cell.apikey, "<redacted>")
```

What `RetnApi` does when the class is defined:

- Each name in `RETN_METHS` gets an API method that awaits `self.cell.<name>(*args, **kwargs)`
  and returns `TelepathRetn(status=True, mesg="", data=<result>)`.
- Each name in `GENR_METHS` gets an async generator that yields one `status=True` item for
  each item the cell yields. An error ends the generator after one `status=False` item.
- Every public coroutine or async generator that the subclass defines itself is **guarded**
  too. If it raises, it returns or yields a `status=False` retn instead. These hand-written
  methods are for when a plain call isn't enough, for example a permission check (yarastorm's
  `slib.yara.admin`). They build their own `TelepathRetn` when they succeed. A name in
  `RETN_METHS` that the class defines itself is left alone.

How an error becomes a message (`stormlibpp.svc.errRetn`):

| Error | `mesg` |
| --- | --- |
| One of `RETN_ERRORS` (default `SvcError`), or Synapse `AuthDeny` | The error's own message (`err.mesg` if set) |
| `ValueError`, `TypeError`, Synapse `BadArg` | `Invalid input: <message>` |
| Anything else | `Unexpected error: <Type>: <message>`, logged with its traceback by the `stormlibpp.svc` logger |

`_retnRedact()` runs on every message, so an API key that an HTTP library put into an
exception never reaches Storm. Values from Storm that end up in a file path go through
`stormlibpp.svc.checkName()`, `checkGuid()` or `safeJoin()`. These raise `SvcError` for
anything that could escape the service's storage, such as `..` or a separator.

On the Storm side, the convention is:

```text
$svc = $lib.service.get("slib.example")
$retn = $svc.lookup($valu)
if (not $retn.status) {
    $lib.warn("slib.example: {mesg}", mesg=$retn.mesg)
    return()
}
// ... model $retn.data ...
```

Commands warn and move on instead of raising, because they run in a user's pipeline and in
automation. Library modules can raise. Storm checks `$lib.debug` to log more detail.

## Naming

Everything a service exposes to Synapse lives under the StormLib++ `slib` namespace: the
service name (`slib.vt`, `slib.yara`), its Storm package, commands (`slib.vt.file`), modules
and permissions (`slib.yara.admin`). stormsvcs is the Advanced Power-Up companion to the
[StormLib++](https://docs.gormo.co/stormlibpp/) Rapid Power-Ups, which use the same
namespace. Check StormLib++ for names that are already taken before you pick one.

Storm code, and Python that Storm calls directly, uses camelCase, as Synapse does.

## A service's files

```text
svcs/<svc>/
  pyproject.toml        # The service's own project: deps, version, pytest config
  uv.lock               # Its own lock (Synapse, StormLib++ pins: see the contract)
  README.md             # The user README, copied into the Storm package
  LICENSE -> ../../LICENSE
  docs/                 # Its pages on this site (see Writing Docs)
  docker/
    prod/Dockerfile     # FROM ${BASE_IMAGE}, the published service image
    prod/entrypoint.sh  # uv run --no-sync ... python -O -m <pkg> /vertex/storage
    test/Dockerfile     # FROM ${BASE_IMAGE} (the prod image), runs the tests in it
    test/entrypoint.sh
  src/<pkg>/
    __init__.py         # __version__, exports the Cell
    __main__.py         # asyncio.run(<Cell>.execmain(sys.argv[1:]))
    svc.py              # The Cell
    api.py              # The CellApi (RetnApi)
    defs.py             # Names, version, perms, service events, the StormPkg
    client.py, norm.py  # Typically: the upstream client and the data normaliser
    pkgproto/
      <storm pkg>.yaml  # The Rapid Power-Up proto
      README.md         # A copy of ../../README.md (a test checks they match)
      storm/commands/*.storm, storm/modules/*.storm
  tests/
    conftest.py         # pytest_plugins = ["stormlibpp.testing"]
    fake<svc>.py        # A fake upstream on localhost, where there is one
    test_*.py
```

There is no shared code between services in this repo. Anything that two services need
belongs in StormLib++: in Python (`stormlibpp.svc`, `stormlibpp.testing`, `stormlibpp.node`,
...) or in Storm (the `slib.utils` package). Every service can be built, deployed and
upgraded on its own.

## The images

```text
vertexproject/vtx-base-image:py311 (pinned by digest, bumped by Dependabot)
  -> ghcr.io/gormaniac/stormsvcs/base      docker/Dockerfile
       + uv and uvx (from ghcr.io/astral-sh/uv)
       + /opt/stormsvcs/{README.md,LICENSE}
       + SYN_LOG_LEVEL=INFO, EXPOSE 4443 27492, VOLUME /vertex/storage
       + apt-get upgrade
     -> ghcr.io/gormaniac/stormsvcs/<svc>  svcs/<svc>/docker/prod/Dockerfile
          + uv sync --no-dev --locked of the service (its own Synapse and StormLib++)
          + any system tools it needs (ex. capa's rules, pcap's engines)
```

The base image doesn't install Synapse or StormLib++. Each service locks its own, so a
service can upgrade separately. The `[contract]` table in `services.toml` makes sure they
all agree on the Synapse version anyway. Each service image is tagged `latest`, its
`pyproject.toml` version, and the commit SHA. See {doc}`ci`.

All service images listen on the base image's ports: Telepath on `27492` and HTTPS on `4443`.
Their healthcheck runs `synapse.tools.service.healthcheck` against `cell:///vertex/storage/`.

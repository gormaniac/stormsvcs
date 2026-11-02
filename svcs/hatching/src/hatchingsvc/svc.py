"""The slib.hatching service.

Every Hatching Triage API endpoint has a method on ``HatchingSvc``, built on the
pyhatching client. These methods return the API's data as plain dicts (or bytes,
for downloads) and raise ``HatchingApiError`` on failure. ``HatchingCellApi`` wraps
them in the standard ``TelepathRetn`` convention for Storm.
"""

import asyncio
import collections
import contextlib
import urllib.parse
from collections.abc import AsyncIterator
from typing import Any

import pyhatching
import pyhatching.errors as p_errors
import pyhatching.utils as p_utils
import synapse.lib.cell as s_cell
from pyhatching import base as p_base

from . import norm
from .api import HatchingCellApi
from .errors import HatchingApiError

TERMINAL = ("reported", "failed")
"""The sample statuses that end an analysis."""

UNAVAILABLE = ("NOT_FOUND", "REPORT_NOT_AVAILABLE", "NOT_AVAILABLE")
"""API error names meaning a report doesn't exist (yet), rather than that the request failed."""

MAX_TIMEOUT = 3600
"""The longest analysis timeout, in seconds, the Triage API accepts."""

MAX_CLIENTS = 32
"""The most per-API-key pyhatching clients kept open at once."""


def dump(obj: Any) -> Any:
    """Turn pyhatching models (and lists of them) into plain, msgpack safe, values."""

    if isinstance(obj, list):
        return [dump(o) for o in obj]
    if isinstance(obj, p_base.TriageModel):
        return obj.model_dump(mode="json", by_alias=True, exclude_none=True)
    return obj


def profileList(profiles: list | None) -> list[dict] | None:
    """Normalize Storm's profile selections (``"profile"``, ``"profile:pick"``, or dicts)."""

    if not profiles:
        return None
    ret = []
    for item in profiles:
        if isinstance(item, dict):
            ret.append({k: v for k, v in item.items() if k in ("profile", "pick") and v})
            continue
        profile, _, pick = str(item).partition(":")
        ret.append({k: v for k, v in (("profile", profile), ("pick", pick)) if v})
    return ret


class HatchingSvc(s_cell.Cell):
    """The Cell implementation for the slib.hatching service."""

    cellapi = HatchingCellApi

    confdefs = {
        "hatching:apikey": {
            "type": ["string", "null"],
            "default": None,
            "description": (
                "A Hatching Triage API key used when neither the calling user nor the "
                "service's stored key (set with slib.hatching.admin.apikey) provides one."
            ),
        },
        "hatching:url": {
            "type": "string",
            "default": pyhatching.BASE_URL,
            "description": (
                "The Hatching Triage URL, ex. https://tria.ge (public cloud), "
                "https://private.tria.ge (private cloud), or a self-hosted instance."
            ),
        },
        "hatching:api_path": {
            "type": "string",
            "default": pyhatching.API_PATH,
            "description": "The path the versioned (/v0, /v1) API endpoints live under.",
        },
        "hatching:timeout": {
            "type": "number",
            "default": 60,
            "description": "Timeout, in seconds, for a single Hatching Triage API request.",
        },
        "hatching:maxsize": {
            "type": "integer",
            "default": 104857600,
            "description": "The largest file, in bytes, the service will submit or download.",
        },
    }

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)

        self.hatchinginfo = self.slab.getSafeKeyVal("slib:hatching")
        self.maxsize = self.conf.get("hatching:maxsize")
        self.clients: collections.OrderedDict[str, pyhatching.PyHatchingClient] = (
            collections.OrderedDict()
        )
        # How many calls are using each client, so evicted clients are only closed once idle.
        self.inuse: collections.Counter = collections.Counter()
        self.retired: set[pyhatching.PyHatchingClient] = set()
        self.onfini(self._closeClients)

    async def _closeClients(self) -> None:
        for client in list(self.clients.values()) + list(self.retired):
            await client.close()
        self.clients.clear()
        self.retired.clear()

    # ---- API key management ----

    def getApiKey(self, apikey: str | None = None) -> str | None:
        """Resolve the API key to use: the caller's, then the stored key, then the config."""

        return apikey or self.hatchinginfo.get("apikey") or self.conf.get("hatching:apikey")

    async def setApiKey(self, apikey: str | None) -> bool:
        """Set (or clear, with None/empty) the service-wide Hatching Triage API key."""

        if apikey:
            self.hatchinginfo.set("apikey", apikey)
        else:
            self.hatchinginfo.pop("apikey")
        return True

    async def hasApiKey(self) -> bool:
        """Whether the service has a stored or configured API key."""

        return bool(self.getApiKey())

    async def maxSize(self) -> int:
        """The largest file, in bytes, the service will submit or download."""

        return self.maxsize

    async def getClient(self, apikey: str | None = None) -> pyhatching.PyHatchingClient:
        """A started pyhatching client for the resolved API key (cached per key)."""

        key = self.getApiKey(apikey)
        if not key:
            raise HatchingApiError(
                "No Hatching Triage API key is available. Set your own with slib.hatching.apikey, "
                "or ask an admin to set one with slib.hatching.admin.apikey."
            )

        client = self.clients.get(key)
        if client is not None:
            self.clients.move_to_end(key)
            return client

        client = pyhatching.PyHatchingClient(
            key,
            url=self.conf.get("hatching:url"),
            timeout=self.conf.get("hatching:timeout"),
            raise_on_api_err=True,
            api_path=self.conf.get("hatching:api_path"),
        )
        await client.start()
        self.clients[key] = client
        while len(self.clients) > MAX_CLIENTS:
            _, old = self.clients.popitem(last=False)
            if self.inuse[old]:
                # Still running a request or stream, it's closed when that finishes.
                self.retired.add(old)
            else:
                await old.close()
        return client

    @contextlib.asynccontextmanager
    async def useClient(self, apikey: str | None = None):
        """Yield a client for the resolved API key, keeping it open while it's in use.

        pyhatching errors are raised as ``HatchingApiError``.
        """

        client = await self.getClient(apikey)
        self.inuse[client] += 1
        try:
            yield client
        except p_errors.PyHatchingApiError as err:
            mesg = f"Hatching Triage: {err.error or 'error'} - {err.message or err}"
            if err.status:
                mesg += f" (HTTP {err.status})"
            raise HatchingApiError(mesg, error=err.error, status=err.status) from err
        except p_errors.PyHatchingError as err:
            raise HatchingApiError(f"Hatching Triage: {err}") from err
        finally:
            self.inuse[client] -= 1
            if not self.inuse[client]:
                del self.inuse[client]
                if client in self.retired:
                    self.retired.discard(client)
                    await client.close()

    async def _call(self, apikey: str | None, meth: str, *args, **kwargs) -> Any:
        """Call a pyhatching client method, returning its dumped result."""

        async with self.useClient(apikey) as client:
            return dump(await getattr(client, meth)(*args, **kwargs))

    async def _genr(self, apikey: str | None, meth: str, *args, **kwargs) -> AsyncIterator[Any]:
        """Iterate a pyhatching client generator, yielding dumped results."""

        async with self.useClient(apikey) as client:
            async for item in getattr(client, meth)(*args, **kwargs):
                yield dump(item)

    async def _bytes(self, apikey: str | None, meth: str, *args) -> AsyncIterator[bytes]:
        """Stream a download in chunks, enforcing ``hatching:maxsize``."""

        size = 0
        async for chunk in self._genr(apikey, meth, *args):
            size += len(chunk)
            if size > self.maxsize:
                raise HatchingApiError(
                    f"The download is larger than the max of {self.maxsize} bytes."
                )
            yield chunk

    async def resolve(self, sample: str, apikey: str | None = None) -> str:
        """Resolve a sample ID, or a hash of a submitted file, to a sample ID.

        For a hash, the newest reported sample is preferred, so a file that was just
        submitted again still resolves to its finished analysis.
        """

        sample = str(sample).strip()
        if not p_utils.is_hash(sample):
            return sample

        query = f"{p_utils.hash_type(sample)}:{sample}"
        async with self.useClient(apikey) as client:
            page = await client.search_page(query, limit=20)
        if not page.data:
            raise HatchingApiError(f"Hatching Triage has no sample for {sample}.")
        for item in page.data:
            if getattr(item.status, "value", item.status) == "reported":
                return item.id
        return page.data[0].id

    async def rawRequest(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        json_data: Any = None,
        apikey: str | None = None,
    ) -> Any:
        """Send an arbitrary request (ex. ``get /v0/samples``) and return its JSON. An escape hatch."""

        if not path.startswith("/"):
            path = "/" + path
        async with self.useClient(apikey) as client:
            resp, data = await client._request(  # pylint: disable=W0212
                method.lower(), path, params=params, json=json_data
            )
        if resp.status >= 400:
            if isinstance(data, dict):
                raise HatchingApiError(
                    f"Hatching Triage: {data.get('error')} - {data.get('message')} "
                    f"(HTTP {resp.status})",
                    error=data.get("error"),
                    status=resp.status,
                )
            raise HatchingApiError(f"Hatching Triage: HTTP {resp.status}", status=resp.status)
        return data

    # ---- Samples ----

    async def search(self, query: str, limit: int = 20, apikey: str | None = None) -> list[dict]:
        """GET /v0/search - up to ``limit`` samples (0 for every result)."""
        return await self._call(apikey, "search", query, limit=limit)

    async def samples(
        self, subset: str = "owned", limit: int = 20, apikey: str | None = None
    ) -> list[dict]:
        """GET /v0/samples - up to ``limit`` samples of a subset (owned, org, or public)."""
        return await self._call(apikey, "get_samples", subset, limit=limit)

    async def sample(self, sample: str, apikey: str | None = None) -> dict:
        """GET /v0/samples/{id} - by sample ID or file hash."""
        return await self._call(apikey, "get_sample", await self.resolve(sample, apikey))

    async def summary(self, sample: str, apikey: str | None = None) -> dict:
        """GET /v0/samples/{id}/summary"""
        return await self._call(apikey, "sample_summary", await self.resolve(sample, apikey))

    async def deleteSample(self, sample: str, apikey: str | None = None) -> bool:
        """DELETE /v0/samples/{id}"""
        await self._call(apikey, "delete_sample", await self.resolve(sample, apikey))
        return True

    async def setProfile(
        self,
        sample: str,
        profiles: list | None = None,
        auto: bool = False,
        pick: list | None = None,
        apikey: str | None = None,
    ) -> bool:
        """POST /v0/samples/{id}/profile - pick profiles for an interactive submission.

        ``profiles`` items are a profile name, ``"profile:pick"``, or a ``{profile, pick}`` dict.
        """
        sid = await self.resolve(sample, apikey)
        profiles = profileList(profiles)
        if not profiles and not auto and not pick:
            raise HatchingApiError("Pick at least one profile, a file to analyze, or auto.")
        if pick and not profiles:
            # Picking files without profiles lets the sandbox pick the profiles for them.
            auto = True
        await self._call(
            apikey, "set_sample_profile", sid, profiles=profiles, auto=auto, pick=list(pick or [])
        )
        return True

    async def magicLink(self, sample: str, apikey: str | None = None) -> str:
        """GET /v0/samples/{id}/magic - a shareable link to a sample's analysis.

        Magic links must be enabled for the organization (see ``setMagicLinks``).
        """

        sid = await self.resolve(sample, apikey)
        token = await self._call(apikey, "magic_token", sid)
        if not token:
            raise HatchingApiError(f"Hatching Triage returned no magic link token for {sid}.")
        return f"{self.conf.get('hatching:url').rstrip('/')}/{sid}/magic/{token}"

    @staticmethod
    def _checkNetwork(timeout: int | None, network: str | None, geolocation: str | None) -> None:
        """Validate the timeout, network, and geolocation of a submission or profile."""

        if timeout is not None and not 0 < int(timeout) <= MAX_TIMEOUT:
            raise HatchingApiError(f"The timeout must be between 1 and {MAX_TIMEOUT} seconds.")
        if geolocation and network != "vpn":
            raise HatchingApiError("A geolocation requires the vpn network.")

    def _submitReq(
        self,
        kind: str,
        url: str | None = None,
        name: str | None = None,
        interactive: bool = False,
        password: str | None = None,
        profiles: list | None = None,
        tags: list | None = None,
        timeout: int | None = None,
        network: str | None = None,
        geolocation: str | None = None,
    ) -> p_base.SubmissionRequest:
        self._checkNetwork(timeout, network, geolocation)
        if profiles and interactive:
            raise HatchingApiError(
                "Profiles can't be picked for an interactive submission, pick them with "
                "slib.hatching.sample.profile once its static analysis is done."
            )
        defaults = {
            k: v
            for k, v in (("timeout", timeout), ("network", network), ("geolocation", geolocation))
            if v
        }
        try:
            return p_base.SubmissionRequest(
                kind=kind,
                url=url,
                target=name or None,
                interactive=interactive or None,
                password=password or None,
                profiles=profileList(profiles),
                user_tags=list(tags) if tags else None,
                defaults=defaults or None,
            )
        except ValueError as err:
            raise HatchingApiError(f"Invalid submission: {err}") from err

    async def submitUrl(
        self,
        url: str,
        fetch: bool = False,
        interactive: bool = False,
        profiles: list | None = None,
        tags: list | None = None,
        timeout: int | None = None,
        network: str | None = None,
        geolocation: str | None = None,
        apikey: str | None = None,
    ) -> dict:
        """POST /v0/samples - analyze a URL, or with ``fetch``, the file the sandbox downloads from it."""

        req = self._submitReq(
            "fetch" if fetch else "url",
            url=url,
            interactive=interactive,
            profiles=profiles,
            tags=tags,
            timeout=timeout,
            network=network,
            geolocation=geolocation,
        )
        return await self._call(apikey, "submit_sample", req)

    async def importSample(self, sample: str, apikey: str | None = None) -> dict:
        """POST /v0/samples (kind ``import``) - copy a public tria.ge sample into a private cloud.

        ``sample`` is the public sample's ID or tria.ge URL.
        """

        req = self._submitReq("import", url=str(sample).strip())
        return await self._call(apikey, "submit_sample", req)

    async def submitFile(
        self,
        chunks: list[bytes],
        name: str,
        interactive: bool = False,
        password: str | None = None,
        profiles: list | None = None,
        tags: list | None = None,
        timeout: int | None = None,
        network: str | None = None,
        geolocation: str | None = None,
        apikey: str | None = None,
    ) -> dict:
        """POST /v0/samples - submit a file, given as a list of chunks (as read from an Axon)."""

        byts = b"".join(chunks)
        if len(byts) > self.maxsize:
            raise HatchingApiError(
                f"The file is {len(byts)} bytes, larger than the max of {self.maxsize}."
            )
        if not byts:
            raise HatchingApiError("The file is empty.")
        req = self._submitReq(
            "file",
            name=name or "sample",
            interactive=interactive,
            password=password,
            profiles=profiles,
            tags=tags,
            timeout=timeout,
            network=network,
            geolocation=geolocation,
        )
        return await self._call(apikey, "submit_sample", req, byts)

    async def wait(self, sample: str, timeout: float = 600, apikey: str | None = None) -> dict:
        """Wait (up to ``timeout`` seconds) for a sample's analysis to finish, using its events.

        Returns the sample's metadata, check ``status`` to see if it finished.
        """

        sid = await self.resolve(sample, apikey)
        info = await self._call(apikey, "get_sample", sid)
        if info.get("status") in TERMINAL:
            return info

        async def follow():
            async for event in self._genr(apikey, "sample_events", sid):
                if event.get("status") in TERMINAL:
                    return

        try:
            await asyncio.wait_for(follow(), timeout=timeout)
        except TimeoutError:
            pass
        return await self._call(apikey, "get_sample", sid)

    async def sampleEvents(
        self,
        sample: str | None = None,
        limit: int = 100,
        timeout: float = 600,
        apikey: str | None = None,
    ) -> AsyncIterator[dict]:
        """Yield sample status changes (GET /samples/{id}/events, or every sample's with no sample).

        Stops after ``limit`` events (0 for no limit) or ``timeout`` seconds.
        """

        if sample:
            genr = self._genr(apikey, "sample_events", await self.resolve(sample, apikey))
        else:
            genr = self._genr(apikey, "samples_events")

        queue: asyncio.Queue = asyncio.Queue()

        async def pump():
            try:
                async for event in genr:
                    await queue.put((True, event))
            except Exception as err:  # pylint: disable=W0718
                await queue.put((False, err))
            await queue.put(None)

        task = self.schedCoro(pump())
        count = 0
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        try:
            while True:
                left = end - loop.time()
                if left <= 0:
                    return
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=left)
                except TimeoutError:
                    return
                if item is None:
                    return
                ok, valu = item
                if not ok:
                    raise valu
                yield valu
                count += 1
                if limit and count >= limit:
                    return
        finally:
            task.cancel()

    # ---- Reports ----

    async def overview(self, sample: str, apikey: str | None = None) -> dict:
        """GET /v1/samples/{id}/overview.json"""
        return await self._call(apikey, "overview", await self.resolve(sample, apikey))

    async def staticReport(self, sample: str, apikey: str | None = None) -> dict:
        """GET /v0/samples/{id}/reports/static"""
        return await self._call(apikey, "static_report", await self.resolve(sample, apikey))

    async def taskReport(self, sample: str, task: str, apikey: str | None = None) -> dict:
        """GET /v0/samples/{id}/{task}/report_triage.json"""
        return await self._call(apikey, "task_report", await self.resolve(sample, apikey), task)

    async def urlscanReport(
        self, sample: str, task: str = "urlscan1", apikey: str | None = None
    ) -> dict:
        """GET /v0/samples/{id}/{task}/report_urlscan.json - a URL sample's UrlScan report."""
        return await self._call(apikey, "urlscan_report", await self.resolve(sample, apikey), task)

    async def kernelReport(
        self,
        sample: str,
        task: str,
        log: str | None = None,
        limit: int = 1000,
        apikey: str | None = None,
    ) -> AsyncIterator[dict]:
        """Yield up to ``limit`` (0 for all) kernel monitor events of a task."""

        sid = await self.resolve(sample, apikey)
        count = 0
        async for event in self._genr(apikey, "kernel_report", sid, task, log=log):
            yield event
            count += 1
            if limit and count >= limit:
                return

    @staticmethod
    def behavioralTasks(sid: str, overview: dict) -> list[str]:
        """The names of a sample's reported behavioral (dynamic analysis) tasks."""

        ret = []
        for task in overview.get("tasks") or []:
            name = task.get("name") or ""
            if name.startswith(f"{sid}-"):
                name = name[len(sid) + 1 :]
            behavioral = task.get("kind") == "behavioral" or name.startswith("behavioral")
            if behavioral and task.get("status") in (None, "reported"):
                ret.append(name)
        return ret

    async def normSample(self, sample: str, tasks: bool = False, apikey: str | None = None) -> dict:
        """Get a reported sample's reports and normalize them for modeling (see ``hatchingsvc.norm``).

        Uses the overview and static reports, and with ``tasks``, every behavioral task report.
        A task report that can't be retrieved is skipped and described in ``errors``.
        """

        sid = await self.resolve(sample, apikey)
        info = await self._call(apikey, "get_sample", sid)
        if info.get("status") != "reported":
            raise HatchingApiError(
                f"Sample {sid} isn't reported yet (its status is {info.get('status')})."
            )

        overview = await self._call(apikey, "overview", sid)
        reports, errors = {}, []
        try:
            static = await self._call(apikey, "static_report", sid)
        except HatchingApiError as err:
            # Samples without a static task (ex. URLs) have no static report.
            if err.error not in UNAVAILABLE:
                raise
            static = None

        names = self.behavioralTasks(sid, overview) if tasks else []
        for name, report in zip(names, await self._taskReports(sid, names, apikey)):
            if isinstance(report, HatchingApiError):
                errors.append(f"The {name} report of {sid} is unavailable: {report.mesg}")
            else:
                reports[name] = report

        ret = norm.normSample(info, overview, static, reports)
        ret["errors"] = errors + ret.pop("reported")
        return ret

    async def _taskReports(self, sid: str, names: list[str], apikey: str | None = None) -> list:
        """Get several task reports concurrently. Failed reports are returned as their error."""

        reports = await asyncio.gather(
            *(self._call(apikey, "task_report", sid, name) for name in names),
            return_exceptions=True,
        )
        for report in reports:
            if isinstance(report, BaseException) and not isinstance(report, HatchingApiError):
                raise report
        return reports

    async def dumpedFiles(self, sample: str, apikey: str | None = None) -> list[dict]:
        """The files dropped during a sample's behavioral tasks, that can be downloaded.

        Returns ``[{task, name, path, sha256, size}]``.
        """

        sid = await self.resolve(sample, apikey)
        overview = await self._call(apikey, "overview", sid)
        names = self.behavioralTasks(sid, overview)
        ret = []
        for task, report in zip(names, await self._taskReports(sid, names, apikey)):
            if isinstance(report, HatchingApiError):
                raise report
            for item in report.get("dumped") or []:
                if item.get("sha256") and item.get("name") and item.get("kind") != "region":
                    ret.append(
                        {
                            "task": task,
                            "name": item["name"],
                            "path": item.get("path"),
                            "sha256": item["sha256"].lower(),
                            "size": item.get("size"),
                        }
                    )
        return ret

    # ---- Downloads (async generators of byte chunks) ----

    async def downloadSample(self, sample: str, apikey: str | None = None) -> AsyncIterator[bytes]:
        """GET /v0/samples/{id}/sample"""
        sid = await self.resolve(sample, apikey)
        async for chunk in self._bytes(apikey, "iter_sample", sid):
            yield chunk

    async def downloadTaskFile(
        self, sample: str, task: str, name: str, apikey: str | None = None
    ) -> AsyncIterator[bytes]:
        """GET /v0/samples/{id}/{task}/{name} - ex. dump.pcap, dump.pcapng, or a dumped file."""
        sid = await self.resolve(sample, apikey)
        async for chunk in self._bytes(apikey, "iter_task_file", sid, task, name):
            yield chunk

    async def downloadArchive(
        self, sample: str, fmt: str = "tar", apikey: str | None = None
    ) -> AsyncIterator[bytes]:
        """GET /v0/samples/{id}/archive (tar) or /archive.zip"""
        sid = await self.resolve(sample, apikey)
        async for chunk in self._bytes(apikey, "iter_sample_archive", sid, fmt):
            yield chunk

    # ---- Profiles ----

    async def profiles(self, apikey: str | None = None) -> list[dict]:
        """GET /v0/profiles - every page."""
        return await self._call(apikey, "get_profiles")

    async def profile(self, profile: str, apikey: str | None = None) -> dict:
        """GET /v0/profiles/{id or name}"""
        return await self._call(apikey, "get_profile", profile)

    async def addProfile(
        self,
        name: str,
        tags: list | None = None,
        timeout: int | None = None,
        network: str | None = None,
        geolocation: str | None = None,
        apikey: str | None = None,
    ) -> dict:
        """POST /v0/profiles"""
        self._checkNetwork(timeout, network, geolocation)
        return await self._call(
            apikey,
            "submit_profile",
            name,
            list(tags or []),
            timeout,
            network,
            geolocation=geolocation,
        )

    async def editProfile(
        self,
        profile: str,
        name: str | None = None,
        tags: list | None = None,
        timeout: int | None = None,
        network: str | None = None,
        geolocation: str | None = None,
        apikey: str | None = None,
    ) -> dict:
        """PUT /v0/profiles/{id or name} - unset values keep their current value.

        The API overwrites the whole profile, so the current values are sent for the unset
        ones. The geolocation is dropped when the network changes from ``vpn``.
        """

        cur = await self.profile(profile, apikey=apikey)
        new = {
            "name": name or cur.get("name"),
            "tags": list(tags) if tags is not None else cur.get("tags") or [],
            "timeout": timeout or cur.get("timeout"),
            "network": network if network is not None else cur.get("network", ""),
        }
        geo = geolocation or (cur.get("geolocation") if new["network"] == "vpn" else None)
        self._checkNetwork(new["timeout"], new["network"], geo)
        await self._call(
            apikey,
            "update_profile",
            new["tags"],
            new["timeout"],
            new["network"],
            new["name"],
            cur.get("id") or profile,
            geolocation=geo,
        )
        ret = dict(cur, **new)
        ret.pop("geolocation", None)
        if geo:
            ret["geolocation"] = geo
        return ret

    async def delProfile(self, profile: str, apikey: str | None = None) -> bool:
        """DELETE /v0/profiles/{id or name}"""
        await self._call(apikey, "delete_profile", profile)
        return True

    # ---- Yara ----

    async def rules(self, apikey: str | None = None) -> list[dict]:
        """GET /v0/yara"""
        return (await self._call(apikey, "get_rules")).get("rules") or []

    async def rule(self, name: str, apikey: str | None = None) -> dict:
        """GET /v0/yara/{name}"""
        return await self._call(apikey, "get_rule", name)

    async def addRule(self, name: str, text: str, apikey: str | None = None) -> bool:
        """POST /v0/yara"""
        await self._call(apikey, "submit_rule", name, text)
        return True

    async def editRule(self, name: str, text: str, apikey: str | None = None) -> bool:
        """PUT /v0/yara/{name}"""
        await self._call(apikey, "update_rule", name, text)
        return True

    async def renameRule(
        self, name: str, newname: str, text: str | None = None, apikey: str | None = None
    ) -> bool:
        """PUT /v0/yara/{name} with a new name (and optionally new rule text)."""

        if text is None:
            text = (await self.rule(name, apikey=apikey)).get("rule")
        async with self.useClient(apikey) as client:
            resp, data = await client._request(  # pylint: disable=W0212
                "put",
                f"/v0/yara/{urllib.parse.quote(str(name), safe='')}",
                json={"name": newname, "rule": text},
            )
            if resp.status >= 400 or (isinstance(data, dict) and "error" in data):
                client.convert_resp(p_base.ErrorResponse, resp, data)
        return True

    async def delRule(self, name: str, apikey: str | None = None) -> bool:
        """DELETE /v0/yara/{name}"""
        await self._call(apikey, "delete_rule", name)
        return True

    # ---- Users and API keys (private and self-hosted instances) ----

    async def users(self, limit: int | None = None, apikey: str | None = None) -> list[dict]:
        """GET /v0/users - up to ``limit`` users (None or 0 for all of them), every page."""
        return await self._call(apikey, "get_users", limit=limit or None)

    async def user(self, user: str, apikey: str | None = None) -> dict:
        """GET /v0/users/{id}"""
        return await self._call(apikey, "get_user", user)

    async def addUser(
        self,
        login: str,
        password: str | None = None,
        name: str | None = None,
        role: str | None = None,
        confirmed: bool = False,
        apikey: str | None = None,
    ) -> dict:
        """POST /v0/users - create a user in your organization.

        ``login`` is an email address, or a username (no ``@``), which Triage turns into a
        ``<username>@triage.local`` login. ``confirmed`` confirms the email address so the
        user can sign in right away. ``role`` is ex. ``org_basic``, see the users docs.
        """

        login = str(login).strip()
        if not login:
            raise HatchingApiError("A username or email address is required.")
        if "@" in login:
            kwargs = {"email": login, "email_confirmed": True if confirmed else None}
        else:
            kwargs = {"username": login}
        return await self._call(
            apikey, "create_user", password=password, name=name, role=role, **kwargs
        )

    async def delUser(self, user: str, apikey: str | None = None) -> bool:
        """DELETE /v0/users/{id}"""
        await self._call(apikey, "delete_user", user)
        return True

    async def userKeys(self, user: str, apikey: str | None = None) -> list[dict]:
        """GET /v0/users/{id}/apikeys"""
        return await self._call(apikey, "get_user_apikeys", user)

    async def addUserKey(self, user: str, name: str, apikey: str | None = None) -> dict:
        """POST /v0/users/{id}/apikeys"""
        return await self._call(apikey, "create_user_apikey", user, name)

    async def delUserKey(self, user: str, name: str, apikey: str | None = None) -> bool:
        """DELETE /v0/users/{id}/apikeys/{name}"""
        await self._call(apikey, "delete_user_apikey", user, name)
        return True

    # ---- Resources, geolocations, stats, and organization settings ----

    async def resources(self, apikey: str | None = None) -> list[dict]:
        """GET /v0/resources - the analysis environments, and the tags that pick them."""
        return [
            res
            for group in await self._call(apikey, "get_resources")
            for res in group.get("resources") or []
        ]

    async def geolocations(self, apikey: str | None = None) -> list[dict]:
        """GET /v0/geolocations - the regions VPN analyses can exit from."""
        return [
            geo
            for group in await self._call(apikey, "get_geolocations")
            for geo in group.get("geolocations") or []
        ]

    async def stats(self, org: bool = False, apikey: str | None = None) -> dict:
        """GET /v0/stats/user, or /v0/stats/org with ``org``."""
        return await self._call(apikey, "org_stats" if org else "user_stats")

    async def orgSettings(self, apikey: str | None = None) -> dict:
        """GET /v0/org/settings (requires the manage_company permission)."""
        return await self._call(apikey, "get_org_settings")

    async def setMagicLinks(self, enabled: bool, apikey: str | None = None) -> bool:
        """PUT /v0/org/settings/magic - allow (or stop) creating magic links."""
        await self._call(apikey, "set_magic_link", bool(enabled))
        return True

"""The slib.hatching service.

Every Hatching Triage API endpoint has a method on ``HatchingSvc``, built on the
pyhatching client. These methods return the API's data as plain dicts (or bytes,
for downloads) and raise ``HatchingApiError`` on failure. ``HatchingCellApi`` wraps
them in the standard ``TelepathRetn`` convention for Storm.
"""


import asyncio
import collections
from collections.abc import AsyncIterator
from typing import Any

import pyhatching
import pyhatching.errors as p_errors
from pyhatching import base as p_base
import synapse.lib.cell as s_cell

from . import norm
from .api import HatchingCellApi
from .errors import HatchingApiError


TERMINAL = ("reported", "failed")
"""The sample statuses that end an analysis."""

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
        self.onfini(self._closeClients)

    async def _closeClients(self) -> None:
        for client in list(self.clients.values()):
            await client.close()
        self.clients.clear()

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
            await old.close()
        return client

    async def _call(self, apikey: str | None, meth: str, *args, **kwargs) -> Any:
        """Call a pyhatching client method, returning its dumped result."""

        client = await self.getClient(apikey)
        try:
            return dump(await getattr(client, meth)(*args, **kwargs))
        except p_errors.PyHatchingError as err:
            raise HatchingApiError(f"Hatching Triage: {err}") from err

    async def _genr(self, apikey: str | None, meth: str, *args, **kwargs) -> AsyncIterator[Any]:
        """Iterate a pyhatching client generator, yielding dumped results."""

        client = await self.getClient(apikey)
        try:
            async for item in getattr(client, meth)(*args, **kwargs):
                yield dump(item)
        except p_errors.PyHatchingError as err:
            raise HatchingApiError(f"Hatching Triage: {err}") from err

    async def _bytes(self, apikey: str | None, meth: str, *args) -> AsyncIterator[bytes]:
        """Stream a download in chunks, enforcing ``hatching:maxsize``."""

        size = 0
        async for chunk in self._genr(apikey, meth, *args):
            size += len(chunk)
            if size > self.maxsize:
                raise HatchingApiError(f"The download is larger than the max of {self.maxsize} bytes.")
            yield chunk

    async def resolve(self, sample: str, apikey: str | None = None) -> str:
        """Resolve a sample ID, or a hash of a submitted file, to a sample ID."""

        sample = str(sample).strip()
        client = await self.getClient(apikey)
        try:
            sid = await client.norm_sample(sample)
        except p_errors.PyHatchingError as err:
            raise HatchingApiError(f"Hatching Triage: {err}") from err
        if sid is None:
            raise HatchingApiError(f"Hatching Triage has no sample for {sample}.")
        return sid

    async def rawRequest(self, method: str, path: str, params: dict | None = None,
                         json_data: Any = None, apikey: str | None = None) -> Any:
        """Send an arbitrary request (ex. ``get /v0/samples``) and return its JSON. An escape hatch."""

        if not path.startswith("/"):
            path = "/" + path
        client = await self.getClient(apikey)
        try:
            resp, data = await client._request(  # pylint: disable=W0212
                method.lower(), path, params=params, json=json_data
            )
        except p_errors.PyHatchingError as err:
            raise HatchingApiError(f"Hatching Triage: {err}") from err
        if resp.status >= 400:
            if isinstance(data, dict):
                raise HatchingApiError(
                    f"Hatching Triage: {resp.status} {data.get('error')} - {data.get('message')}"
                )
            raise HatchingApiError(f"Hatching Triage: HTTP {resp.status}")
        return data

    # ---- Samples ----

    async def search(self, query: str, limit: int = 20, apikey: str | None = None) -> list[dict]:
        """GET /v0/search - up to ``limit`` samples (0 for every result)."""
        return await self._call(apikey, "search", query, limit=limit)

    async def samples(self, subset: str = "owned", limit: int = 20,
                      apikey: str | None = None) -> list[dict]:
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

    async def setProfile(self, sample: str, profiles: list | None = None, auto: bool = False,
                         pick: list | None = None, apikey: str | None = None) -> bool:
        """POST /v0/samples/{id}/profile - pick profiles for an interactive submission.

        ``profiles`` items are a profile name, ``"profile:pick"``, or a ``{profile, pick}`` dict.
        """
        sid = await self.resolve(sample, apikey)
        await self._call(apikey, "set_sample_profile", sid, profiles=profileList(profiles),
                         auto=auto, pick=list(pick or []))
        return True

    def _submitReq(self, kind: str, url: str | None = None, name: str | None = None,
                   interactive: bool = False, password: str | None = None,
                   profiles: list | None = None, tags: list | None = None,
                   timeout: int | None = None, network: str | None = None) -> p_base.SubmissionRequest:
        defaults = {k: v for k, v in (("timeout", timeout), ("network", network)) if v}
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

    async def submitUrl(self, url: str, fetch: bool = False, interactive: bool = False,
                        profiles: list | None = None, tags: list | None = None,
                        timeout: int | None = None, network: str | None = None,
                        apikey: str | None = None) -> dict:
        """POST /v0/samples - analyze a URL, or with ``fetch``, the file the sandbox downloads from it."""

        req = self._submitReq("fetch" if fetch else "url", url=url, interactive=interactive,
                              profiles=profiles, tags=tags, timeout=timeout, network=network)
        return await self._call(apikey, "submit_sample", req)

    async def submitFile(self, chunks: list[bytes], name: str, interactive: bool = False,
                         password: str | None = None, profiles: list | None = None,
                         tags: list | None = None, timeout: int | None = None,
                         network: str | None = None, apikey: str | None = None) -> dict:
        """POST /v0/samples - submit a file, given as a list of chunks (as read from an Axon)."""

        byts = b"".join(chunks)
        if len(byts) > self.maxsize:
            raise HatchingApiError(f"The file is {len(byts)} bytes, larger than the max of {self.maxsize}.")
        if not byts:
            raise HatchingApiError("The file is empty.")
        req = self._submitReq("file", name=name or "sample", interactive=interactive,
                              password=password, profiles=profiles, tags=tags, timeout=timeout,
                              network=network)
        return await self._call(apikey, "submit_sample", req, byts)

    async def wait(self, sample: str, timeout: float = 600, apikey: str | None = None) -> dict:
        """Wait (up to ``timeout`` seconds) for a sample's analysis to finish, using its events.

        Returns the sample's metadata, check ``status`` to see if it finished.
        """

        sid = await self.resolve(sample, apikey)

        async def follow():
            async for event in self._genr(apikey, "sample_events", sid):
                if event.get("status") in TERMINAL:
                    return

        try:
            await asyncio.wait_for(follow(), timeout=timeout)
        except asyncio.TimeoutError:
            pass
        return await self._call(apikey, "get_sample", sid)

    async def sampleEvents(self, sample: str | None = None, limit: int = 100,
                           timeout: float = 600, apikey: str | None = None) -> AsyncIterator[dict]:
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
                except asyncio.TimeoutError:
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

    async def kernelReport(self, sample: str, task: str, log: str | None = None, limit: int = 1000,
                           apikey: str | None = None) -> AsyncIterator[dict]:
        """Yield up to ``limit`` (0 for all) kernel monitor events of a task."""

        sid = await self.resolve(sample, apikey)
        count = 0
        async for event in self._genr(apikey, "kernel_report", sid, task, log=log):
            yield event
            count += 1
            if limit and count >= limit:
                return

    async def behavioralTasks(self, sid: str, overview: dict, apikey: str | None = None) -> list[str]:
        """The names of a sample's reported behavioral (dynamic analysis) tasks."""

        ret = []
        for task in overview.get("tasks") or []:
            name = task.get("name") or ""
            if name.startswith(f"{sid}-"):
                name = name[len(sid) + 1:]
            if task.get("kind") == "behavioral" or name.startswith("behavioral"):
                if task.get("status") in (None, "reported"):
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
        try:
            static = await self._call(apikey, "static_report", sid)
        except HatchingApiError:
            static = None

        reports, errors = {}, []
        names = await self.behavioralTasks(sid, overview, apikey) if tasks else []
        for name in names:
            try:
                reports[name] = await self._call(apikey, "task_report", sid, name)
            except HatchingApiError as err:
                errors.append(f"The {name} report of {sid} is unavailable: {err.mesg}")

        ret = norm.normSample(info, overview, static, reports)
        ret["errors"] = errors
        return ret

    async def dumpedFiles(self, sample: str, apikey: str | None = None) -> list[dict]:
        """The files dropped during a sample's behavioral tasks, that can be downloaded.

        Returns ``[{task, name, path, sha256, size}]``.
        """

        sid = await self.resolve(sample, apikey)
        overview = await self._call(apikey, "overview", sid)
        ret = []
        for task in await self.behavioralTasks(sid, overview, apikey):
            report = await self._call(apikey, "task_report", sid, task)
            for item in report.get("dumped") or []:
                if item.get("sha256") and item.get("name") and item.get("kind") != "region":
                    ret.append({
                        "task": task,
                        "name": item["name"],
                        "path": item.get("path"),
                        "sha256": item["sha256"].lower(),
                        "size": item.get("size"),
                    })
        return ret

    # ---- Downloads (async generators of byte chunks) ----

    async def downloadSample(self, sample: str, apikey: str | None = None) -> AsyncIterator[bytes]:
        """GET /v0/samples/{id}/sample"""
        sid = await self.resolve(sample, apikey)
        async for chunk in self._bytes(apikey, "iter_sample", sid):
            yield chunk

    async def downloadTaskFile(self, sample: str, task: str, name: str,
                               apikey: str | None = None) -> AsyncIterator[bytes]:
        """GET /v0/samples/{id}/{task}/{name} - ex. dump.pcap, dump.pcapng, or a dumped file."""
        sid = await self.resolve(sample, apikey)
        async for chunk in self._bytes(apikey, "iter_task_file", sid, task, name):
            yield chunk

    async def downloadArchive(self, sample: str, fmt: str = "tar",
                              apikey: str | None = None) -> AsyncIterator[bytes]:
        """GET /v0/samples/{id}/archive (tar) or /archive.zip"""
        sid = await self.resolve(sample, apikey)
        async for chunk in self._bytes(apikey, "iter_sample_archive", sid, fmt):
            yield chunk

    # ---- Profiles ----

    async def profiles(self, apikey: str | None = None) -> list[dict]:
        """GET /v0/profiles"""
        return await self._call(apikey, "get_profiles")

    async def profile(self, profile: str, apikey: str | None = None) -> dict:
        """GET /v0/profiles/{id or name}"""
        return await self._call(apikey, "get_profile", profile)

    async def addProfile(self, name: str, tags: list | None = None, timeout: int | None = None,
                         network: str | None = None, apikey: str | None = None) -> dict:
        """POST /v0/profiles"""
        return await self._call(apikey, "submit_profile", name, list(tags or []), timeout, network)

    async def editProfile(self, profile: str, name: str | None = None, tags: list | None = None,
                          timeout: int | None = None, network: str | None = None,
                          apikey: str | None = None) -> dict:
        """PUT /v0/profiles/{id or name} - unset values keep their current value."""

        cur = await self.profile(profile, apikey=apikey)
        new = {
            "name": name or cur.get("name"),
            "tags": list(tags) if tags is not None else cur.get("tags") or [],
            "timeout": timeout or cur.get("timeout"),
            "network": network if network is not None else cur.get("network", ""),
        }
        await self._call(apikey, "update_profile", new["tags"], new["timeout"], new["network"],
                         new["name"], cur.get("id") or profile)
        return dict(cur, **new)

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

    async def delRule(self, name: str, apikey: str | None = None) -> bool:
        """DELETE /v0/yara/{name}"""
        await self._call(apikey, "delete_rule", name)
        return True

    # ---- Users and API keys (private and self-hosted instances) ----

    async def users(self, limit: int | None = None, apikey: str | None = None) -> list[dict]:
        """GET /v0/users"""
        return await self._call(apikey, "get_users", limit=limit)

    async def user(self, user: str, apikey: str | None = None) -> dict:
        """GET /v0/users/{id}"""
        return await self._call(apikey, "get_user", user)

    async def addUser(self, username: str, email: str, password: str | None = None,
                      first: str | None = None, last: str | None = None,
                      permissions: list | None = None, apikey: str | None = None) -> dict:
        """POST /v0/users"""
        return await self._call(apikey, "create_user", username, email, password=password,
                                first_name=first, last_name=last,
                                permissions=list(permissions) if permissions else None)

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


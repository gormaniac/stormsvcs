"""The slib.anyrun service.

``AnyRunSvc`` has a method per ANY.RUN API endpoint (and a few that combine them, ex.
``wait`` and ``yaraRun``). They return plain, msgpack safe, values and raise
``AnyRunApiError`` on failure; ``AnyRunCellApi`` wraps them in the standard ``TelepathRetn``
convention for Storm.
"""

import asyncio
import contextlib
import datetime
import hashlib
import re
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlsplit

import aiohttp
import synapse.lib.cell as s_cell

from . import client as c_client
from . import norm
from .api import AnyRunCellApi
from .client import AnyRunApiError, AnyRunClient

FEEDS = {
    "full": "3dce855a-c044-5d49-9334-533c24678c5a",
    "ip": "55cda200-e261-5908-b910-f0e18909ef3d",
    "domain": "2e0aa90a-5526-5a43-84ad-3db6f4549a09",
    "url": "05bfa343-e79f-57ec-8677-3122ca33d352",
}
"""ANY.RUN's TAXII collections (stable IDs): every indicator, or only IPs, domains, or URLs."""

FEED_PAGE = 1000
"""How many TAXII objects to request per page."""

SUMMARY_FORMATS = ("stix", "misp", "brief", "tier1", "json")
"""The JSON report formats under /report/{uuid}/summary/."""

YARA_TERMINAL = ("done", "failed", "cancelled", "expired")
"""YARA Search statuses that end a search."""

OSES = ("windows", "linux", "android", "macos")
PRIVACY = ("public", "bylink", "owner", "byteam")
AUTODELETE = ("day", "week", "2 weeks", "month")
ENV_TYPES = ("complete", "development")
TOR_GEOS = ("fastest", "AU", "BR", "CH", "DE", "FR", "GB", "IT", "KR", "RU", "US")
START_FOLDERS = ("desktop", "home", "downloads", "appdata", "temp", "windows", "root")
BROWSERS = ("Internet Explorer", "Microsoft Edge", "Google Chrome", "Mozilla Firefox", "Safari")
TAGRE = re.compile(r"^[A-Za-z0-9-]{1,16}$")

# Submission options: the Storm option name, the API's field name, and the submission kinds
# (f)ile, (u)rl, (d)ownload, and (r)erun that take it.
SUBMIT_OPTS = (
    ("os", "env_os", "fudr"),
    ("version", "env_version", "fudr"),
    ("bitness", "env_bitness", "fudr"),
    ("envtype", "env_type", "fudr"),
    ("locale", "env_locale", "fudr"),
    ("timeout", "opt_timeout", "fudr"),
    ("network", "opt_network_connect", "fudr"),
    ("fakenet", "opt_network_fakenet", "fudr"),
    ("tor", "opt_network_tor", "fudr"),
    ("geo", "opt_network_geo", "fudr"),
    ("mitm", "opt_network_mitm", "fudr"),
    ("residential", "opt_network_residential_proxy", "fudr"),
    ("residential_geo", "opt_network_residential_proxy_geo", "fudr"),
    ("privacy", "opt_privacy_type", "fudr"),
    ("interactive", "opt_automated_interactivity", "fudr"),
    ("autodelete", "opt_auto_delete_after", "fudr"),
    ("startfolder", "obj_ext_startfolder", "fdr"),
    ("cmd", "obj_ext_cmd", "fdr"),
    ("browser", "obj_ext_browser", "ur"),
    ("useragent", "obj_ext_useragent", "dr"),
    ("elevate", "obj_force_elevation", "fdr"),
    ("uac", "auto_confirm_uac", "fdr"),
    ("root", "run_as_root", "fdr"),
    ("extension", "obj_ext_extension", "fdr"),
    ("hidesource", "opt_privacy_hidesource", "dr"),
)

KIND_NAMES = {"f": "file", "u": "url", "d": "download", "r": "rerun"}


def taskArg(task: Any) -> str:
    """A task UUID from a UUID or an app.any.run task link."""

    uuid = norm.taskId(task)
    if not uuid:
        raise AnyRunApiError(f"{task!r} isn't an ANY.RUN task ID (a UUID) or task link.")
    return uuid


def submitParams(kind: str, opts: dict | None) -> dict:
    """Validate the Storm submission options and return them as API fields (unset ones dropped)."""

    opts = {k: v for k, v in (opts or {}).items() if v is not None and v != "" and v != []}
    known = {name for name, _, _ in SUBMIT_OPTS} | {"tags"}
    unknown = set(opts) - known
    if unknown:
        raise AnyRunApiError(f"Unknown submission options: {', '.join(sorted(unknown))}.")

    if "os" in opts:
        opts["os"] = str(opts["os"]).lower()
        if opts["os"] not in OSES:
            raise AnyRunApiError(f"The OS must be one of {', '.join(OSES)}.")
    if "bitness" in opts:
        opts["bitness"] = int(opts["bitness"])
        if opts["bitness"] not in (32, 64):
            raise AnyRunApiError("The bitness must be 32 or 64.")
        if opts["bitness"] == 32 and opts.get("os", "windows") != "windows":
            raise AnyRunApiError("Only Windows environments can be 32 bit.")
    if "version" in opts:
        opts["version"] = str(opts["version"])
    if "envtype" in opts and opts["envtype"] not in ENV_TYPES:
        raise AnyRunApiError(f"The environment type must be one of {', '.join(ENV_TYPES)}.")
    if "timeout" in opts:
        opts["timeout"] = int(opts["timeout"])
        if not 10 <= opts["timeout"] <= 1200:
            raise AnyRunApiError("The timeout must be between 10 and 1200 seconds.")
    if "privacy" in opts and opts["privacy"] not in PRIVACY:
        raise AnyRunApiError(f"The privacy must be one of {', '.join(PRIVACY)}.")
    if "autodelete" in opts and opts["autodelete"] not in AUTODELETE:
        raise AnyRunApiError(f"The auto delete period must be one of {', '.join(AUTODELETE)}.")
    if "geo" in opts:
        geo = str(opts["geo"])
        opts["geo"] = geo.lower() if geo.lower() == "fastest" else geo.upper()
        if opts["geo"] not in TOR_GEOS:
            raise AnyRunApiError(f"The TOR geo must be one of {', '.join(TOR_GEOS)}.")
        opts.setdefault("tor", True)
    if "residential_geo" in opts:
        geo = str(opts["residential_geo"])
        opts["residential_geo"] = geo.lower() if geo.lower() == "fastest" else geo.upper()
        opts.setdefault("residential", True)
    if "startfolder" in opts and opts["startfolder"] not in START_FOLDERS:
        raise AnyRunApiError(f"The start folder must be one of {', '.join(START_FOLDERS)}.")
    if "browser" in opts and opts["browser"] not in BROWSERS:
        raise AnyRunApiError(f"The browser must be one of {', '.join(BROWSERS)}.")
    if (opts.get("tor") or "geo" in opts) and opts.get("network") is False:
        raise AnyRunApiError("TOR needs the network to be connected.")

    params = {}
    for name, field, kinds in SUBMIT_OPTS:
        if name not in opts:
            continue
        if kind not in kinds:
            raise AnyRunApiError(
                f"The {name} option can't be used with a {KIND_NAMES[kind]} submission."
            )
        params[field] = opts[name]

    tags = opts.get("tags")
    if tags:
        tags = [tags] if isinstance(tags, str) else [str(t).strip() for t in tags]
        tags = norm.uniq(t for tag in tags for t in tag.split(","))
        bad = [t for t in tags if not TAGRE.match(t)]
        if bad:
            raise AnyRunApiError(
                f"Invalid tags: {', '.join(bad)}. Tags are up to 16 letters, numbers, and dashes."
            )
        if len(tags) > 8:
            raise AnyRunApiError("ANY.RUN takes at most 8 tags.")
        params["user_tags"] = ",".join(tags)
    return params


def contentPath(url: str) -> str:
    """The path (and query) of a content.any.run URL from a report."""

    parts = urlsplit(str(url))
    if not parts.path.startswith("/tasks/"):
        raise AnyRunApiError(f"{url} isn't an ANY.RUN task download URL.")
    return parts.path + (f"?{parts.query}" if parts.query else "")


class AnyRunSvc(s_cell.Cell):
    """The Cell implementation for the slib.anyrun service."""

    cellapi = AnyRunCellApi

    confdefs = {
        "anyrun:apikey": {
            "type": ["string", "null"],
            "default": None,
            "description": (
                "An ANY.RUN API key used when neither the calling user nor the service's "
                "stored key (set with slib.anyrun.admin.apikey) provides one."
            ),
        },
        "anyrun:url": {
            "type": "string",
            "default": c_client.BASE_URL,
            "description": "The ANY.RUN API URL (the Sandbox, report, and TI endpoints).",
        },
        "anyrun:content_url": {
            "type": "string",
            "default": c_client.CONTENT_URL,
            "description": "The ANY.RUN URL samples, PCAPs, and dropped files are downloaded from.",
        },
        "anyrun:timeout": {
            "type": "number",
            "default": 60,
            "description": "Timeout, in seconds, for a single ANY.RUN API request.",
        },
        "anyrun:maxsize": {
            "type": "integer",
            "default": 104857600,
            "description": "The largest file, in bytes, the service will submit or download.",
        },
        "anyrun:poll": {
            "type": "number",
            "default": 3,
            "description": "Seconds between polls of a YARA search (and reconnects of task monitors).",
        },
    }

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)

        self.anyruninfo = self.slab.getSafeKeyVal("slib:anyrun")
        self.maxsize = self.conf.get("anyrun:maxsize")
        self.poll = max(float(self.conf.get("anyrun:poll")), 0.0)
        self.session = aiohttp.ClientSession(trust_env=True)

        async def fini():
            await self.session.close()

        self.onfini(fini)

    # ---- API keys and the client ----

    def getApiKey(self, apikey: str | None = None) -> str | None:
        """Resolve the API key to use: the caller's, then the stored key, then the config."""

        return apikey or self.anyruninfo.get("apikey") or self.conf.get("anyrun:apikey")

    async def setApiKey(self, apikey: str | None) -> bool:
        """Set (or clear, with None/empty) the service-wide ANY.RUN API key."""

        if apikey:
            self.anyruninfo.set("apikey", apikey)
        else:
            self.anyruninfo.pop("apikey")
        return True

    async def hasApiKey(self) -> bool:
        """Whether the service has a stored or configured API key."""

        return bool(self.getApiKey())

    async def maxSize(self) -> int:
        """The largest file, in bytes, the service will submit or download."""

        return self.maxsize

    def client(self, apikey: str | None = None) -> AnyRunClient:
        """A client for the resolved API key."""

        key = self.getApiKey(apikey)
        if not key:
            raise AnyRunApiError(
                "No ANY.RUN API key is available. Set your own with slib.anyrun.apikey, "
                "or ask an admin to set one with slib.anyrun.admin.apikey."
            )
        return AnyRunClient(
            self.session,
            key,
            url=self.conf.get("anyrun:url"),
            content=self.conf.get("anyrun:content_url"),
            timeout=self.conf.get("anyrun:timeout"),
        )

    async def _req(self, apikey: str | None, method: str, path: str, **kwargs) -> Any:
        """Send a request and return its JSON."""

        _, data = await self.client(apikey).request(method, path, **kwargs)
        return data

    async def _data(self, apikey: str | None, method: str, path: str, **kwargs) -> Any:
        """Send a Sandbox API request and return the ``data`` of its ``{error, data}`` envelope."""

        data = await self._req(apikey, method, path, **kwargs)
        if isinstance(data, dict) and data.get("error") is True:
            raise AnyRunApiError(f"ANY.RUN: {data.get('message') or 'error'}")
        if isinstance(data, dict) and "data" in data:
            return data["data"]
        return data

    async def rawRequest(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        json_data: Any = None,
        apikey: str | None = None,
    ) -> Any:
        """Send an arbitrary request (ex. ``get /v1/user``) and return its JSON. An escape hatch."""

        if not str(path).startswith("/"):
            path = "/" + str(path)
        return await self._req(apikey, method, path, params=params, json_data=json_data)

    # ---- Account ----

    async def limits(self, apikey: str | None = None) -> dict:
        """GET /v1/user - the API key's request limits and parallel task slots."""

        data = await self._data(apikey, "get", "/v1/user")
        return data.get("limits", data) if isinstance(data, dict) else data

    async def environments(self, apikey: str | None = None) -> list[dict]:
        """GET /v1/environment - the analysis environments (OSes, versions, and software)."""

        data = await self._data(apikey, "get", "/v1/environment")
        return data.get("environments", []) if isinstance(data, dict) else data or []

    async def presets(self, apikey: str | None = None) -> list[dict]:
        """GET /v1/user/presets - the user's saved analysis presets."""

        return await self._req(apikey, "get", "/v1/user/presets") or []

    # ---- Tasks ----

    async def history(
        self, team: bool = False, skip: int = 0, limit: int = 25, apikey: str | None = None
    ) -> list[dict]:
        """GET /v1/analysis - the newest tasks of the user (or with team, their team)."""

        limit = int(limit)
        if not 0 < limit <= 100:
            raise AnyRunApiError("The limit must be between 1 and 100.")
        params = {"team": bool(team), "skip": max(int(skip), 0), "limit": limit}
        data = await self._data(apikey, "get", "/v1/analysis", params=params)
        tasks = data.get("tasks", []) if isinstance(data, dict) else []
        return [norm.normTask(t) for t in tasks if isinstance(t, dict)]

    async def report(self, task: str, apikey: str | None = None) -> dict:
        """GET /v1/analysis/{uuid} - a task's full report."""

        return await self._data(apikey, "get", f"/v1/analysis/{c_client.seg(taskArg(task))}")

    async def normReport(self, task: str, reads: bool = False, apikey: str | None = None) -> dict:
        """A task's report, normalized for modeling (see ``norm.normReport``).

        With ``reads``, also includes the file and registry reads.
        """

        return norm.normReport(await self.report(task, apikey=apikey) or {}, reads=bool(reads))

    async def iocs(self, task: str, reputation: int = 0, apikey: str | None = None) -> list[dict]:
        """GET /report/{uuid}/ioc/json - a task's IOCs with at least a reputation.

        Reputations are 0 (unknown), 1 (suspicious), and 2 (malicious).
        """

        data = await self._req(apikey, "get", f"/report/{c_client.seg(taskArg(task))}/ioc/json")
        reputation = int(reputation)
        return [
            i
            for i in data or []
            if isinstance(i, dict) and (norm.toInt(i.get("reputation")) or 0) >= reputation
        ]

    async def aiSummary(self, task: str, apikey: str | None = None) -> dict:
        """GET /report/{uuid}/ai - a task's AI summary and recommendations."""

        return await self._req(apikey, "get", f"/report/{c_client.seg(taskArg(task))}/ai") or {}

    async def summary(self, task: str, fmt: str = "brief", apikey: str | None = None) -> Any:
        """GET /report/{uuid}/summary/{fmt} - a task's report as STIX, MISP, brief, tier1, or json."""

        if fmt not in SUMMARY_FORMATS:
            raise AnyRunApiError(f"The report format must be one of {', '.join(SUMMARY_FORMATS)}.")
        return await self._req(
            apikey, "get", f"/report/{c_client.seg(taskArg(task))}/summary/{fmt}"
        )

    async def addTime(self, task: str, apikey: str | None = None) -> str:
        """PATCH /v1/analysis/addtime/{uuid} - give a running task 60 more seconds."""

        path = f"/v1/analysis/addtime/{c_client.seg(taskArg(task))}"
        data = await self._req(apikey, "patch", path)
        return (data or {}).get("message") or "Added time to the task."

    async def stopTask(self, task: str, apikey: str | None = None) -> str:
        """PATCH /v1/analysis/stop/{uuid} - stop a running task."""

        data = await self._req(apikey, "patch", f"/v1/analysis/stop/{c_client.seg(taskArg(task))}")
        return (data or {}).get("message") or "Stopped the task."

    async def deleteTask(self, task: str, apikey: str | None = None) -> str:
        """DELETE /v1/analysis/delete/{uuid} - delete a finished task."""

        path = f"/v1/analysis/delete/{c_client.seg(taskArg(task))}"
        data = await self._req(apikey, "delete", path)
        return (data or {}).get("message") or "Deleted the task."

    # ---- Task status ----

    async def _statuses(self, task: str, apikey: str | None = None) -> AsyncIterator[dict]:
        """Yield the normalized events of one connection to a task's monitor stream."""

        uuid = taskArg(task)
        path = f"/v1/analysis/monitor/{c_client.seg(uuid)}"
        async for event in self.client(apikey).events(path):
            status = norm.normStatus(event)
            if status["uuid"] is None:
                status["uuid"] = uuid
            yield status

    async def status(self, task: str, timeout: float = 30, apikey: str | None = None) -> dict:
        """A task's current status (the first event of its monitor stream).

        ``task`` may also be the queue ID of a queued submission.
        """

        async def first():
            async with contextlib.aclosing(self._statuses(task, apikey=apikey)) as genr:
                async for status in genr:
                    return status
            raise AnyRunApiError(f"ANY.RUN sent no status for task {task}.")

        try:
            return await asyncio.wait_for(first(), timeout=timeout)
        except TimeoutError as err:
            raise AnyRunApiError(f"ANY.RUN sent no status for task {task} in {timeout}s.") from err

    async def monitor(
        self, task: str, limit: int = 100, timeout: float = 600, apikey: str | None = None
    ) -> AsyncIterator[dict]:
        """Yield a task's status events until it finishes, or ``limit`` events or ``timeout`` seconds."""

        queue: asyncio.Queue = asyncio.Queue()
        done = object()

        async def pump():
            try:
                async for status in self._follow(task, apikey=apikey):
                    await queue.put(status)
            except Exception as err:  # pylint: disable=W0718
                await queue.put(err)
            await queue.put(done)

        loop = asyncio.get_running_loop()
        deadline = loop.time() + float(timeout)
        pumper = asyncio.create_task(pump())
        count = 0
        try:
            while not limit or count < limit:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    return
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=remaining)
                except TimeoutError:
                    return
                if item is done:
                    return
                if isinstance(item, Exception):
                    raise item
                count += 1
                yield item
        finally:
            pumper.cancel()

    async def _follow(self, task: str, apikey: str | None = None) -> AsyncIterator[dict]:
        """Yield a task's status events until it completes or fails, reconnecting as needed."""

        while True:
            async with contextlib.aclosing(self._statuses(task, apikey=apikey)) as genr:
                async for status in genr:
                    # A queued task's events switch to its real UUID once it starts.
                    if status["uuid"]:
                        task = status["uuid"]
                    yield status
                    if status["state"] in ("completed", "failed"):
                        return
            await asyncio.sleep(self.poll)

    async def wait(self, task: str, timeout: float = 600, apikey: str | None = None) -> dict:
        """Wait up to ``timeout`` seconds for a task to finish and return its last status.

        Check ``state`` (``completed``, ``failed``, or still ``running``...) for the outcome.
        """

        last = None
        async for status in self.monitor(task, limit=0, timeout=timeout, apikey=apikey):
            last = status
        if last is None:
            raise AnyRunApiError(f"ANY.RUN sent no status for task {task} in {timeout}s.")
        return last

    # ---- Submissions ----

    @staticmethod
    def _submitted(status: int, data: Any) -> dict:
        """The result of a submission: its task ID, or its queue ID if it was queued."""

        body = data.get("data") if isinstance(data, dict) else None
        body = body if isinstance(body, dict) else {}
        task = norm.taskId(body.get("taskid") or body.get("taskId"))
        queue = norm.taskId(body.get("queueTaskId"))
        if not task and not queue:
            raise AnyRunApiError("ANY.RUN accepted the submission but returned no task ID.")
        return {
            "task": task,
            "queue": queue,
            "queued": task is None,
            "link": f"{c_client.APP_URL}/tasks/{task}" if task else None,
            "message": (data or {}).get("message") or "",
        }

    async def submitFile(
        self, chunks: list[bytes], name: str, opts: dict | None = None, apikey: str | None = None
    ) -> dict:
        """POST /v1/analysis (``obj_type=file``) - submit a file, given as a list of chunks."""

        byts = b"".join(chunks)
        if not byts:
            raise AnyRunApiError("The file is empty.")
        if len(byts) > self.maxsize:
            raise AnyRunApiError(
                f"The file is {len(byts)} bytes, larger than the max of {self.maxsize}."
            )
        params = submitParams("f", opts)
        form = aiohttp.FormData()
        form.add_field("obj_type", "file")
        for key, valu in params.items():
            # Multipart fields are sent the way ANY.RUN's SDK sends them (str(), so True/False).
            form.add_field(key, str(valu))
        form.add_field(
            "file", byts, filename=name or "sample", content_type="application/octet-stream"
        )
        status, data = await self.client(apikey).request("post", "/v1/analysis", form=form)
        return self._submitted(status, data)

    async def _submitJson(self, apikey: str | None, body: dict) -> dict:
        status, data = await self.client(apikey).request("post", "/v1/analysis", json_data=body)
        return self._submitted(status, data)

    @staticmethod
    def _checkUrl(url: str) -> str:
        url = str(url).strip()
        if not re.match(r"^https?://", url, re.IGNORECASE):
            raise AnyRunApiError(f"{url} isn't an http(s) URL.")
        if not 5 <= len(url) <= 512:
            raise AnyRunApiError("ANY.RUN only takes URLs of 5 to 512 characters.")
        return url

    async def submitUrl(
        self, url: str, opts: dict | None = None, apikey: str | None = None
    ) -> dict:
        """POST /v1/analysis (``obj_type=url``) - open a URL in a browser."""

        body = {"obj_type": "url", "obj_url": self._checkUrl(url)}
        body.update(submitParams("u", opts))
        return await self._submitJson(apikey, body)

    async def submitDownload(
        self, url: str, opts: dict | None = None, apikey: str | None = None
    ) -> dict:
        """POST /v1/analysis (``obj_type=download``) - download a file from a URL and run it."""

        body = {"obj_type": "download", "obj_url": self._checkUrl(url)}
        body.update(submitParams("d", opts))
        return await self._submitJson(apikey, body)

    async def rerun(self, task: str, opts: dict | None = None, apikey: str | None = None) -> dict:
        """POST /v1/analysis (``obj_type=rerun``) - run a task again, optionally with new options."""

        body = {"obj_type": "rerun", "task_rerun_uuid": taskArg(task)}
        body.update(submitParams("r", opts))
        return await self._submitJson(apikey, body)

    # ---- Downloads (async generators of byte chunks) ----

    async def _fetch(self, apikey: str | None, path: str) -> bytes:
        """Download a content path into memory, enforcing ``anyrun:maxsize``."""

        chunks = []
        size = 0
        content = self.conf.get("anyrun:content_url").rstrip("/")
        async for chunk in self.client(apikey).stream(content + path):
            size += len(chunk)
            if size > self.maxsize:
                raise AnyRunApiError(
                    f"The download is larger than the max of {self.maxsize} bytes."
                )
            chunks.append(chunk)
        return b"".join(chunks)

    def _unpack(self, byts: bytes, sha256: str | None, what: str) -> bytes:
        """The file in a download: the bytes themselves, or the file in ANY.RUN's zip.

        With an expected SHA256, the download (or a file in its zip) must match it.
        """

        if sha256 and hashlib.sha256(byts).hexdigest() == sha256:
            return byts
        if c_client.isZip(byts):
            files = c_client.unzip(byts, maxsize=self.maxsize)
            if sha256:
                for _, data in files:
                    if hashlib.sha256(data).hexdigest() == sha256:
                        return data
                raise AnyRunApiError(f"The {what} download doesn't contain {sha256}.")
            if len(files) == 1:
                return files[0][1]
            raise AnyRunApiError(f"The {what} download has {len(files)} files, expected one.")
        if sha256:
            raise AnyRunApiError(f"The {what} download doesn't match {sha256}.")
        return byts

    @staticmethod
    def _chunked(byts: bytes, size: int = 1024 * 1024) -> list[bytes]:
        return [byts[i : i + size] for i in range(0, len(byts), size)] or [b""]

    async def downloadSample(self, task: str, apikey: str | None = None) -> AsyncIterator[bytes]:
        """Download a task's sample (its main object, unzipped and checked against its SHA256)."""

        report = await self.report(task, apikey=apikey) or {}
        main = norm.dget(report, "analysis", "content", "mainObject") or {}
        if main.get("type") not in ("file", "download"):
            raise AnyRunApiError(f"Task {taskArg(task)} analyzed a URL, it has no sample file.")
        if norm.dget(report, "analysis", "options", "privateSample") is True:
            raise AnyRunApiError(f"Task {taskArg(task)}'s sample is private.")
        url = main.get("permanentUrl")
        if not url:
            raise AnyRunApiError(f"Task {taskArg(task)} has no sample to download.")
        sha256 = norm.hashes(main.get("hashes")).get("sha256")
        byts = self._unpack(await self._fetch(apikey, contentPath(url)), sha256, "sample")
        for chunk in self._chunked(byts):
            yield chunk

    async def downloadPcap(self, task: str, apikey: str | None = None) -> AsyncIterator[bytes]:
        """Download a task's network capture (unzipped, if ANY.RUN zipped it)."""

        path = f"/tasks/{c_client.seg(taskArg(task))}/download/pcap"
        byts = self._unpack(await self._fetch(apikey, path), None, "PCAP")
        for chunk in self._chunked(byts):
            yield chunk

    async def downloadScreenshot(
        self, task: str, screen: str, apikey: str | None = None
    ) -> AsyncIterator[bytes]:
        """Download one of a task's screenshots (a JPEG) by its UUID."""

        uuid = norm.taskId(screen)
        if not uuid:
            raise AnyRunApiError(f"{screen!r} isn't a screenshot ID (a UUID).")
        path = f"/tasks/{c_client.seg(taskArg(task))}/download/screens/{uuid}/image.jpeg"
        for chunk in self._chunked(await self._fetch(apikey, path)):
            yield chunk

    async def downloadVideo(self, task: str, apikey: str | None = None) -> AsyncIterator[bytes]:
        """Download a task's video recording (an MP4)."""

        path = f"/tasks/{c_client.seg(taskArg(task))}/download/mp4"
        for chunk in self._chunked(await self._fetch(apikey, path)):
            yield chunk

    async def droppedFiles(self, task: str, apikey: str | None = None) -> list[dict]:
        """The files a task created or changed that can be downloaded (``modified.files``)."""

        report = norm.normReport(await self.report(task, apikey=apikey) or {})
        return [f for f in report["files"] if f.get("url") and f.get("sha256")]

    async def downloadDropped(
        self, task: str, sha256: str, apikey: str | None = None
    ) -> AsyncIterator[bytes]:
        """Download a file the task created or changed, by its SHA256."""

        sha256 = str(sha256).strip().lower()
        for file in await self.droppedFiles(task, apikey=apikey):
            if file["sha256"] == sha256:
                byts = self._unpack(
                    await self._fetch(apikey, contentPath(file["url"])), sha256, "file"
                )
                for chunk in self._chunked(byts):
                    yield chunk
                return
        raise AnyRunApiError(f"Task {taskArg(task)} has no downloadable file {sha256}.")

    # ---- TI Lookup ----

    @staticmethod
    def _dates(start: str | None, end: str | None, days: int | None) -> dict:
        body = {}
        if days and not start:
            today = datetime.datetime.now(datetime.UTC).date()
            start = (today - datetime.timedelta(days=int(days))).isoformat()
        for name, valu in (("startDate", start), ("endDate", end)):
            if not valu:
                continue
            try:
                body[name] = datetime.date.fromisoformat(str(valu)[:10]).isoformat()
            except ValueError as err:
                raise AnyRunApiError(f"{valu} isn't a YYYY-MM-DD date.") from err
        return body

    async def lookup(
        self,
        query: str,
        start: str | None = None,
        end: str | None = None,
        days: int | None = 180,
        apikey: str | None = None,
    ) -> dict:
        """POST /v1/intelligence/api/search - a TI Lookup query (an indicator, or ``field:"value"`` terms).

        Searches the last ``days`` days unless ``start`` (YYYY-MM-DD) is given.
        """

        query = str(query or "").strip()
        if not query:
            raise AnyRunApiError("The TI Lookup query is empty.")
        body = {"query": query}
        body.update(self._dates(start, end, days))
        return await self._req(apikey, "post", "/v1/intelligence/api/search", json_data=body)

    async def lookupIndicator(
        self,
        valu: str,
        field: str | None = None,
        start: str | None = None,
        end: str | None = None,
        days: int | None = 180,
        apikey: str | None = None,
    ) -> dict:
        """TI Lookup an indicator (an IP, domain, URL, or hash) and normalize the results.

        The indicator's field is detected unless ``field`` is given.
        """

        valu = str(valu).strip()
        field = field or norm.lookupField(valu)
        if not field:
            raise AnyRunApiError(f"Can't tell what kind of indicator {valu} is.")
        query = norm.lookupQuery(field, valu)
        resp = await self.lookup(query, start=start, end=end, days=days, apikey=apikey)
        ret = norm.normLookup(resp or {})
        ret["query"] = query
        return ret

    async def normLookup(
        self,
        query: str,
        start: str | None = None,
        end: str | None = None,
        days: int | None = 180,
        apikey: str | None = None,
    ) -> dict:
        """A TI Lookup query's results, normalized for modeling."""

        resp = await self.lookup(query, start=start, end=end, days=days, apikey=apikey)
        ret = norm.normLookup(resp or {})
        ret["query"] = query
        return ret

    # ---- YARA Search ----

    async def yaraSearch(self, rule: str, apikey: str | None = None) -> dict:
        """POST /v1/intelligence/yara-lookup/search - start a YARA search, returns its job info."""

        if not str(rule or "").strip():
            raise AnyRunApiError("The YARA rule is empty.")
        return await self._req(
            apikey, "post", "/v1/intelligence/yara-lookup/search", json_data={"query": str(rule)}
        )

    async def yaraStatus(self, search: str, apikey: str | None = None) -> dict:
        """GET /v1/intelligence/yara-lookup/search/{id}/count - a search's status and match count."""

        path = f"/v1/intelligence/yara-lookup/search/{c_client.seg(search)}/count"
        return await self._req(apikey, "get", path)

    async def yaraResults(
        self,
        search: str,
        offset: int = 0,
        limit: int = 100,
        sort: str | None = None,
        apikey: str | None = None,
    ) -> dict:
        """GET /v1/intelligence/yara-lookup/search/{id} - a page of a search's matches."""

        if sort not in (None, "firstNew", "firstOld"):
            raise AnyRunApiError("The sort must be firstNew or firstOld.")
        params = {"offset": int(offset), "limit": int(limit), "sort": sort}
        path = f"/v1/intelligence/yara-lookup/search/{c_client.seg(search)}"
        return await self._req(apikey, "get", path, params=params)

    async def yaraStop(self, search: str, apikey: str | None = None) -> dict:
        """DELETE /v1/intelligence/yara-lookup/search/{id} - stop a search."""

        path = f"/v1/intelligence/yara-lookup/search/{c_client.seg(search)}"
        return await self._req(apikey, "delete", path)

    async def yaraRun(
        self, rule: str, timeout: float = 600, limit: int = 100, apikey: str | None = None
    ) -> dict:
        """Run a YARA search: start it, then ``yaraGet`` its matches (see ``yaraGet``)."""

        info = await self.yaraSearch(rule, apikey=apikey)
        search = info.get("queryId") if isinstance(info, dict) else None
        if not search:
            raise AnyRunApiError("ANY.RUN started the YARA search but returned no ID.")
        return await self.yaraGet(search, timeout=timeout, limit=limit, apikey=apikey)

    async def yaraGet(
        self, search: str, timeout: float = 0, limit: int = 100, apikey: str | None = None
    ) -> dict:
        """Wait up to ``timeout`` seconds for a YARA search to finish, then get up to ``limit`` matches.

        Returns ``{"search", "rule", "text", "status", "found", "done", "matches"}`` with
        normalized matches. A search that's still running is returned with ``done`` false (and
        no matches).
        """

        loop = asyncio.get_running_loop()
        deadline = loop.time() + float(timeout)
        while True:
            count = await self.yaraStatus(search, apikey=apikey)
            info = count.get("searchInfo") if isinstance(count, dict) else None
            info = info if isinstance(info, dict) else {}
            status = info.get("status")
            if status in YARA_TERMINAL or loop.time() + self.poll > deadline:
                break
            await asyncio.sleep(self.poll)

        ret = {
            "search": search,
            "rule": info.get("ruleName"),
            "text": info.get("query"),
            "status": status,
            "found": norm.toInt(count.get("foundMatches")),
            "done": status == "done",
            "matches": [],
        }
        if status != "done":
            return ret

        limit = int(limit)
        offset = 0
        while not limit or len(ret["matches"]) < limit:
            size = min(100, limit - len(ret["matches"])) if limit else 100
            page = await self.yaraResults(search, offset=offset, limit=size, apikey=apikey)
            matches = (page.get("matches") or []) if isinstance(page, dict) else []
            for match in matches:
                item = norm.normYaraMatch(match) if isinstance(match, dict) else None
                if item:
                    ret["matches"].append(item)
            offset += len(matches)
            if len(matches) < size:
                break
        if ret["found"] is None:
            ret["found"] = len(ret["matches"])
        return ret

    # ---- TI Feeds (TAXII 2.1) ----

    async def feeds(self, apikey: str | None = None) -> list[dict]:
        """GET /v1/feeds/taxii2/api1/collections/ - the TAXII collections the key can read."""

        data = await self._req(apikey, "get", "/v1/feeds/taxii2/api1/collections/")
        return data.get("collections", []) if isinstance(data, dict) else []

    async def feedObjects(
        self,
        feed: str = "full",
        added: str | None = None,
        modified: str | None = None,
        limit: int = 1000,
        types: str | None = "indicator",
        apikey: str | None = None,
    ) -> AsyncIterator[dict]:
        """Yield up to ``limit`` normalized objects from a TAXII collection, following its pages.

        ``feed`` is ``full``, ``ip``, ``domain``, ``url``, or a collection ID. ``added`` and
        ``modified`` only get objects added/modified after a time (ISO 8601).
        """

        collection = FEEDS.get(str(feed).lower(), str(feed))
        if not norm.TASKRE.fullmatch(collection):
            raise AnyRunApiError(f"Unknown feed {feed}, use one of {', '.join(FEEDS)} or an ID.")
        limit = int(limit)
        path = f"/v1/feeds/taxii2/api1/collections/{c_client.seg(collection)}/objects/"
        client = self.client(apikey)
        cursor = None
        count = 0
        while True:
            size = min(FEED_PAGE, limit - count) if limit else FEED_PAGE
            params = {
                "limit": size,
                "added_after": added or None,
                "modified_after": modified or None,
                "match[type]": types or None,
                "match[spec_version]": "2.1",
                "next": cursor,
            }
            _, data = await client.request("get", path, params=params)
            data = data if isinstance(data, dict) else {}
            for obj in data.get("objects") or []:
                item = norm.normStix(obj)
                if item is None:
                    continue
                yield item
                count += 1
                if limit and count >= limit:
                    return
            cursor = data.get("next")
            if not cursor or data.get("more") is False:
                return

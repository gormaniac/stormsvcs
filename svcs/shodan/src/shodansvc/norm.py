"""Normalize raw Shodan responses into flat dicts that are easy to model in Storm.

Shodan banners are large, deeply nested, and vary by module. Doing the
reshaping here keeps the Storm modeling code short, and lets it be unit tested
without a Cortex.
"""

import base64
import binascii
import hashlib
import ipaddress
import re
import urllib.parse
from typing import Any


def _ts(valu: str | None) -> str | None:
    """Make a Shodan timestamp parseable by Synapse's time type.

    Shodan uses ``2024-01-01T00:00:00.123456`` (no zone, UTC). Synapse
    handles that, but not the occasional trailing ``+00:00``.
    """

    if not valu:
        return None
    return valu.replace("+00:00", "").rstrip("Z")


def _list(valu: Any) -> list:
    if valu is None:
        return []
    if isinstance(valu, (list, tuple, set)):
        return [v for v in valu if v not in (None, "")]
    return [valu]


def _rotl32(valu: int, bits: int) -> int:
    return ((valu << bits) | (valu >> (32 - bits))) & 0xFFFFFFFF


# The kinds of file hashes Shodan can search for, and the filter for each.
FILE_HASH_FILTERS = {
    "favicon": "http.favicon.hash",
    "html": "http.html_hash",
}


def bannerHash(text: str) -> int:
    """Calculate Shodan's banner ``hash`` for a banner's text (its ``data``).

    Shodan's hash is a signed 32-bit MurmurHash3 (x86_32, seed 0) of the UTF-8
    encoded banner text, the same as ``mmh3.hash(text)``.
    """

    return murmur3(text.encode("utf-8"))


def faviconHash(byts: bytes) -> int:
    """Calculate Shodan's ``http.favicon.hash`` for a favicon file.

    It is the MurmurHash3 of the file's base64 with a newline every 76 characters and a
    trailing newline (Python's ``base64.encodebytes()``), not of the raw bytes.
    """

    return murmur3(base64.encodebytes(byts))


def htmlHash(byts: bytes) -> int:
    """Calculate Shodan's ``http.html_hash`` for an HTML file: the MurmurHash3 of its raw bytes."""

    return murmur3(byts)


def fileHash(byts: bytes, kind: str) -> int:
    """Calculate Shodan's hash of a file's bytes, ``kind`` is one of ``FILE_HASH_FILTERS``."""

    if kind == "favicon":
        return faviconHash(byts)
    if kind == "html":
        return htmlHash(byts)
    raise ValueError(
        f"Unknown file hash kind {kind!r}, expected one of: {', '.join(FILE_HASH_FILTERS)}"
    )


def murmur3(data: bytes) -> int:
    """A signed 32-bit MurmurHash3 (x86_32, seed 0), the same as ``mmh3.hash(data)``."""

    size = len(data)
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    h1 = 0

    tail = size - (size % 4)
    for i in range(0, tail, 4):
        k1 = int.from_bytes(data[i : i + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = _rotl32(k1, 15)
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = _rotl32(h1, 13)
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    rest = size % 4
    if rest:
        k1 = int.from_bytes(data[tail:], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = _rotl32(k1, 15)
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= size
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def _sshKeyAlgo(blob: bytes) -> str | None:
    """Read the key algorithm (ex. ``ssh-rsa``), the first string in an SSH public key blob."""

    if len(blob) < 4:
        return None
    size = int.from_bytes(blob[:4], "big")
    if not 0 < size <= 64 or len(blob) < 4 + size:
        return None
    try:
        algo = blob[4 : 4 + size].decode("ascii")
    except UnicodeDecodeError:
        return None
    if not re.fullmatch(r"[\x21-\x7e]+", algo):
        return None
    return algo


def normSshKey(ssh: dict) -> dict | None:
    """Build the SSH server's public key file from a banner's ``ssh`` data.

    The file is the key the way OpenSSH saves it to disk, ex. in a ``.pub`` or
    ``known_hosts`` file: ``<algo> <base64 key>`` and a newline. Returns the
    file's text, size, and hashes, or None if there is no valid key.
    """

    key = "".join((ssh.get("key") or "").split())
    if not key:
        return None
    try:
        blob = base64.b64decode(key, validate=True)
    except (binascii.Error, ValueError):
        return None

    algo = _sshKeyAlgo(blob) or ssh.get("type")
    if not algo:
        return None

    text = f"{algo} {key}\n"
    byts = text.encode("ascii")
    return {
        "text": text,
        "algo": algo,
        "size": len(byts),
        "md5": hashlib.md5(byts).hexdigest(),
        "sha1": hashlib.sha1(byts).hexdigest(),
        "sha256": hashlib.sha256(byts).hexdigest(),
        "sha512": hashlib.sha512(byts).hexdigest(),
    }


def normCpe(cpe: str) -> str:
    """Pad a CPE 2.3 string to all 13 components, as Synapse's it:sec:cpe requires.

    Shodan's banners use shortened CPEs like ``cpe:2.3:a:f5:nginx:1.25.3``.
    CPE 2.2 URIs (``cpe:/a:...``) are returned as-is.
    """

    cpe = cpe.strip()
    if not cpe.lower().startswith("cpe:2.3:"):
        return cpe

    parts = cpe.split(":")
    if len(parts) < 13:
        parts.extend(["*"] * (13 - len(parts)))
    return ":".join(parts)


def normCpes(cpes: Any) -> list[str]:
    return [normCpe(c) for c in _list(cpes) if isinstance(c, str)]


def _cpeInfo(cpe: str) -> tuple[str | None, str | None]:
    """Return the (part, version) of a CPE 2.3 or 2.2 string. Wildcard versions are None."""

    # CPE 2.3 escapes colons inside a component as "\:".
    parts = re.split(r"(?<!\\):", cpe)
    if cpe.lower().startswith("cpe:2.3:"):
        part = parts[2] if len(parts) > 2 else None
        vers = parts[5] if len(parts) > 5 else None
    else:
        part = parts[1].lstrip("/") if len(parts) > 1 else None
        vers = parts[4] if len(parts) > 4 else None
    if vers in ("", "*", "-"):
        vers = None
    return part, vers


def normSoftvers(cpes: list[str], product: str | None, version: str | None) -> list[dict]:
    """Pair a banner's CPEs with its product/version, for modeling it:prod:softver nodes.

    Banners list every CPE Shodan detected, ex. ``["cpe:2.3:a:openbsd:openssh:6.6.1p1",
    "cpe:2.3:o:canonical:ubuntu_linux"]``, but the product/version only describe one of
    them. They're only paired with the application CPE whose version matches, so OS CPEs
    and version-less CPEs (shared by every version) don't get another product's name and
    version. When no CPE matches, the product/version get their own entry without a CPE.
    """

    # Prefer a CPE whose version is the banner's exact version, then one whose version is a
    # prefix of it at a word boundary (ex. "6.6.1p1" for "6.6.1p1 Ubuntu 2ubuntu2.13", but
    # not "1.1" for "1.18.0").
    match = None
    if product and version:
        lvers = str(version).lower()
        candidates = []
        for cpe in cpes:
            part, vers = _cpeInfo(cpe)
            if part == "a" and vers:
                candidates.append((cpe, vers.lower()))

        exact = [cpe for cpe, vers in candidates if vers == lvers]
        prefix = [
            cpe
            for cpe, vers in candidates
            if len(lvers) > len(vers)
            and lvers.startswith(vers)
            and not (lvers[len(vers)].isalnum() or lvers[len(vers)] == ".")
        ]
        match = (exact or prefix or [None])[0]

    retn = []
    for cpe in cpes:
        if cpe == match:
            retn.append({"cpe": cpe, "product": product, "version": version})
        else:
            retn.append({"cpe": cpe, "product": None, "version": None})

    if product and match is None:
        retn.append({"cpe": None, "product": product, "version": version})

    return retn


def normVulns(vulns: Any) -> list[dict]:
    """Normalize the ``vulns`` field into a list of dicts.

    Banners use ``{"CVE-X": {"cvss": 9.8, "verified": false, "summary": ...}}``,
    host and InternetDB results use ``["CVE-X", ...]``.
    """

    retn = []
    if isinstance(vulns, dict):
        for cve, info in vulns.items():
            info = info if isinstance(info, dict) else {}
            retn.append(
                {
                    "cve": cve.upper(),
                    "cvss": info.get("cvss"),
                    "verified": bool(info.get("verified", False)),
                    "summary": info.get("summary"),
                }
            )
    else:
        for cve in _list(vulns):
            retn.append({"cve": str(cve).upper(), "cvss": None, "verified": False, "summary": None})

    return [v for v in retn if v["cve"].startswith("CVE-")]


def normLocation(loc: dict | None) -> dict | None:
    if not loc:
        return None

    lat = loc.get("latitude")
    lon = loc.get("longitude")

    return {
        "city": loc.get("city"),
        "region": loc.get("region_code"),
        "country": loc.get("country_name"),
        "country_code": (loc.get("country_code") or "").lower() or None,
        "lat": lat,
        "lon": lon,
        "latlong": (lat, lon) if lat is not None and lon is not None else None,
    }


def normCert(ssl: dict | None) -> dict | None:
    """Normalize the ``ssl`` field of a banner into a flat cert dict."""

    if not ssl:
        return None

    cert = ssl.get("cert") or {}
    fprint = cert.get("fingerprint") or {}
    if not fprint.get("sha256"):
        return None

    subject = cert.get("subject") or {}
    issuer = cert.get("issuer") or {}

    def _dn(parts: dict) -> str | None:
        if not parts:
            return None
        return ", ".join(f"{k}={v}" for k, v in parts.items())

    serial = cert.get("serial")
    if isinstance(serial, int):
        # Synapse wants the serial as a hex string.
        serial = format(serial, "x")

    jarm = ssl.get("jarm")
    ja3s = ssl.get("ja3s")

    return {
        "sha256": fprint.get("sha256"),
        "sha1": fprint.get("sha1"),
        "subject": _dn(subject),
        "subject_cn": subject.get("CN"),
        "issuer": _dn(issuer),
        "issuer_cn": issuer.get("CN"),
        "serial": str(serial) if serial is not None else None,
        "notbefore": _certTime(cert.get("issued")),
        "notafter": _certTime(cert.get("expires")),
        "selfsigned": subject == issuer if subject else None,
        "sigalg": cert.get("sig_alg"),
        "version": cert.get("version"),
        "expired": cert.get("expired"),
        "jarm": jarm,
        "ja3s": ja3s,
        "versions": _list(ssl.get("versions")),
    }


def _certTime(valu: str | None) -> str | None:
    """Convert an ASN.1 time (``20240101000000Z``) into ``2024/01/01 00:00:00``."""

    if not valu or len(valu) < 14:
        return None
    return f"{valu[0:4]}/{valu[4:6]}/{valu[6:8]} {valu[8:10]}:{valu[10:12]}:{valu[12:14]}"


# HTTP response headers that aren't modeled, they change every time a server is scanned.
SKIP_HTTP_HEADERS = frozenset({"date"})


def normHttpHeaders(text: str) -> list[dict]:
    """Parse the HTTP response headers out of a banner's text (its ``data``).

    Shodan's HTTP banners are the response's status line and headers, ex.
    ``HTTP/1.1 200 OK\\r\\nServer: nginx\\r\\n\\r\\n``. Returns a list of
    ``{"name": <lowercase name>, "value": <value>}`` dicts in the order they were sent,
    without duplicates or the headers in ``SKIP_HTTP_HEADERS`` (ex. ``Date``). Banners
    that aren't HTTP responses have no headers.
    """

    if not text.startswith("HTTP/"):
        return []

    lines = re.split(r"\r?\n", text)
    headers: list[list[str]] = []
    for line in lines[1:]:
        if not line.strip():
            break
        # Obsolete line folding, a continuation of the previous header's value.
        if line[0] in " \t":
            if headers:
                headers[-1][1] = f"{headers[-1][1]} {line.strip()}".strip()
            continue
        name, sep, valu = line.partition(":")
        name = name.strip().lower()
        if not sep or not name or re.search(r"\s", name):
            continue
        headers.append([name, valu.strip()])

    retn = []
    seen = set()
    for name, valu in headers:
        if name in SKIP_HTTP_HEADERS or (name, valu) in seen:
            continue
        seen.add((name, valu))
        retn.append({"name": name, "value": valu})
    return retn


def _httpStatus(text: str) -> tuple[int | None, str | None]:
    """Parse the (code, reason) out of an HTTP response's status line, ex. ``HTTP/1.1 200 OK``."""

    match = re.match(r"HTTP/\S+[ \t]+(\d{3})(?:[ \t]+([^\r\n]*))?", text)
    if not match:
        return None, None
    return int(match.group(1)), (match.group(2) or "").strip() or None


def _httpBody(text: str) -> str:
    """The body of a raw HTTP response, everything after the blank line that ends the headers."""

    _, sep, body = text.partition("\r\n\r\n")
    if not sep:
        _, sep, body = text.partition("\n\n")
    return body if sep else ""


def _isIp(valu: str) -> bool:
    """Whether a string is an IPv4 or IPv6 address (ex. the host of a URL)."""

    try:
        ipaddress.ip_address(valu.strip("[]"))
    except ValueError:
        return False
    return True


def _urlHost(host: str) -> str:
    """A host as it's written in a URL, IPv6 addresses go in brackets."""

    return f"[{host}]" if ":" in host and not host.startswith("[") else host


# The port each URL scheme uses when the URL doesn't name one.
DEFAULT_PORTS = {"http": 80, "https": 443}


def _httpUrl(scheme: str, host: str, port: int | None, location: str | None) -> str:
    """Build the URL of a request to ``host``:``port``, ``location`` is a path or a full URL."""

    location = location or "/"
    if re.match(r"(?i)https?://", location):
        return location
    if not location.startswith("/"):
        location = f"/{location}"
    hostport = _urlHost(host)
    if port and port != DEFAULT_PORTS.get(scheme):
        hostport = f"{hostport}:{port}"
    return f"{scheme}://{hostport}{location}"


def _mimeType(headers: list[dict], default: str) -> str:
    """The MIME type from a response's Content-Type header (without parameters), or ``default``."""

    for header in headers:
        if header["name"] == "content-type":
            mime = header["value"].split(";", 1)[0].strip().lower()
            if re.fullmatch(r"[\w.+-]+/[\w.+-]+", mime):
                return mime
    return default


# Magic bytes of the image formats favicons are saved as, and their MIME types.
IMAGE_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\x00\x00\x01\x00", "image/x-icon"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"BM", "image/bmp"),
)


def _imageMime(byts: bytes) -> str:
    """Guess an image's MIME type from its magic bytes. Favicons are ``image/x-icon`` otherwise."""

    for magic, mime in IMAGE_MAGIC:
        if byts.startswith(magic):
            return mime
    if byts[:12].startswith(b"RIFF") and byts[8:12] == b"WEBP":
        return "image/webp"
    if b"<svg" in byts[:1024].lower():
        return "image/svg+xml"
    return "image/x-icon"


def normFile(byts: bytes, mime: str, kind: str, url: str | None = None, local: bool = True) -> dict:
    """Describe a file a server returned, for modeling a file:bytes (and the bytes for the Axon).

    ``kind`` says what the file is (ex. ``html``, ``favicon``), ``url`` is where it was fetched
    from if known, and ``local`` is whether the server the banner is for returned it (a favicon
    can be on another server). ``b64`` is the bytes as standard base64, without newlines.
    """

    name = None
    if url:
        base = urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1]
        name = urllib.parse.unquote(base).strip() or None

    return {
        "kind": kind,
        "url": url,
        "local": local,
        "name": name,
        "mime": mime,
        "b64": base64.b64encode(byts).decode("ascii"),
        "size": len(byts),
        "md5": hashlib.md5(byts).hexdigest(),
        "sha1": hashlib.sha1(byts).hexdigest(),
        "sha256": hashlib.sha256(byts).hexdigest(),
        "sha512": hashlib.sha512(byts).hexdigest(),
    }


# The files Shodan fetches from every web server besides the page itself: the http field each
# file's text is in, the path it's fetched from, and its MIME type.
HTTP_TEXT_FILES = (
    ("robots", "/robots.txt", "text/plain"),
    ("securitytxt", "/.well-known/security.txt", "text/plain"),
    ("sitemap", "/sitemap.xml", "application/xml"),
)


def normHttp(banner: dict, text: str) -> dict | None:
    """Normalize a banner's ``http`` field into the HTTP requests and files the server returned.

    ``text`` is the banner's ``data``: the final response's status line and headers. Returns
    the final request (``url``, ``status``, ``reason``, ``headers``, ``title``, and its ``body``
    file), the ``redirects`` Shodan followed to get there (the same keys, oldest first), and
    every ``files`` the server returned (the body, robots.txt, security.txt, the sitemap, the
    favicon, and redirect bodies). See ``normFile`` for the files. ``listing`` is the URL of
    each file and folder in an open directory the page lists (Shodan's ``open_dir``). Returns
    None without an ``http`` field.
    """

    http = banner.get("http")
    if not isinstance(http, dict) or not http:
        return None

    ip = banner.get("ip_str") or ""
    port = banner.get("port")
    # TLS servers have an ssl field, even when Shodan couldn't parse the cert. The module name
    # doesn't say, ex. "https-simple-new" scans plain HTTP servers too.
    scheme = "https" if banner.get("ssl") is not None else "http"
    host = (http.get("host") or ip).strip().lower()
    # The names a URL can use for this server, to tell if a favicon came from it.
    names = {ip.lower(), host, *(h.lower() for h in _list(banner.get("hostnames")))}

    headers = normHttpHeaders(text)
    code, reason = _httpStatus(text)
    status = http.get("status") if isinstance(http.get("status"), int) else code
    url = _httpUrl(scheme, host, port, http.get("location"))

    files = []

    body = None
    html = http.get("html")
    if isinstance(html, str) and html:
        body = normFile(html.encode("utf-8"), _mimeType(headers, "text/html"), "html", url)
        files.append(body)

    for field, path, mime in HTTP_TEXT_FILES:
        valu = http.get(field)
        if isinstance(valu, str) and valu:
            fileurl = _httpUrl(scheme, host, port, path)
            files.append(normFile(valu.encode("utf-8"), mime, field, fileurl))

    favicon = http.get("favicon") or {}
    if isinstance(favicon, dict) and favicon.get("data"):
        try:
            byts = base64.b64decode(favicon["data"])
        except (binascii.Error, ValueError):
            byts = b""
        if byts:
            favurl = favicon.get("location") or None
            local = True
            if favurl:
                parts = urllib.parse.urlsplit(favurl)
                try:
                    favport = parts.port or DEFAULT_PORTS.get(parts.scheme.lower())
                except ValueError:
                    favport = None
                local = (parts.hostname or "").lower() in names and favport == port
            files.append(normFile(byts, _imageMime(byts), "favicon", favurl, local))

    # An open directory's entries are listed by the page, so they're under its URL's directory.
    listing = []
    opendir = banner.get("open_dir") or {}
    entries = opendir.get("data") if isinstance(opendir, dict) else None
    if isinstance(entries, dict):
        parts = urllib.parse.urlsplit(url)
        base = urllib.parse.urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path if parts.path.endswith("/") else f"{parts.path}/",
                "",
                "",
            )
        )
        for name in entries:
            if isinstance(name, str) and name.strip("/"):
                listing.append(urllib.parse.urljoin(base, urllib.parse.quote(name.lstrip("/"))))

    redirects = []
    for hop in _list(http.get("redirects")):
        if not isinstance(hop, dict):
            continue
        data = hop.get("data") if isinstance(hop.get("data"), str) else ""
        hopheaders = normHttpHeaders(data)
        hopcode, hopreason = _httpStatus(data)
        hophost = (hop.get("host") or host).strip().lower()
        hopurl = _httpUrl(scheme, hophost, port, hop.get("location"))
        hopbody = None
        byts = _httpBody(data).encode("utf-8")
        if byts:
            hopbody = normFile(byts, _mimeType(hopheaders, "text/html"), "redirect", hopurl)
            files.append(hopbody)
        redirects.append(
            {
                "url": hopurl,
                "host": None if _isIp(hophost) else hophost or None,
                "path": urllib.parse.urlsplit(hopurl).path or "/",
                "status": hopcode,
                "reason": hopreason,
                "headers": hopheaders,
                "body": hopbody,
            }
        )

    return {
        "url": url,
        "host": None if _isIp(host) else host or None,
        "path": urllib.parse.urlsplit(url).path or "/",
        "status": status,
        "reason": reason,
        "headers": headers,
        "title": http.get("title") or None,
        "server": http.get("server"),
        "favicon": favicon.get("hash") if isinstance(favicon, dict) else None,
        "body": body,
        "redirects": redirects,
        "files": files,
        "listing": listing,
    }


def normBanner(banner: dict) -> dict:
    """Normalize a single Shodan banner (from host lookups, search, or streams)."""

    shodan = banner.get("_shodan") or {}
    ssh = banner.get("ssh") or {}

    shodanopts = shodan.get("options") or {}

    # Large fields Shodan removed from the banner (ex. historical banners, minified searches).
    truncated = [str(f) for f in _list((banner.get("metadata") or {}).get("truncated"))]

    # Never truncated by us, so the inet:banner:text is Shodan's exact data and bannerHash() of it
    # matches Shodan's banner hash. If Shodan truncated it, it's dropped: a partial text would be a
    # different inet:banner, with a hash that doesn't match Shodan's.
    text = "" if "data" in truncated else banner.get("data") or ""

    cpes = normCpes(banner.get("cpe23")) or normCpes(banner.get("cpe"))

    return {
        "ip": banner.get("ip_str"),
        "port": banner.get("port"),
        "transport": (banner.get("transport") or "tcp").lower(),
        "timestamp": _ts(banner.get("timestamp")),
        "module": shodan.get("module"),
        "crawler": shodan.get("crawler"),
        "id": shodan.get("id"),
        # The ID of the on-demand scan that produced the banner, if any.
        "scan": shodanopts.get("scan"),
        # Shodan documents the crawler's region in both places.
        "region": shodan.get("region") or shodanopts.get("region"),
        "truncated": truncated,
        "hash": banner.get("hash"),
        "product": banner.get("product"),
        "version": banner.get("version"),
        "info": banner.get("info"),
        "os": banner.get("os"),
        "cpes": cpes,
        "softvers": normSoftvers(cpes, banner.get("product"), banner.get("version")),
        "data": text,
        "http_headers": normHttpHeaders(text),
        "hostnames": [h.lower() for h in _list(banner.get("hostnames"))],
        "domains": [d.lower() for d in _list(banner.get("domains"))],
        "tags": _list(banner.get("tags")),
        "vulns": normVulns(banner.get("vulns")),
        "asn": banner.get("asn"),
        "org": banner.get("org"),
        "isp": banner.get("isp"),
        "location": normLocation(banner.get("location")),
        "cert": normCert(banner.get("ssl")),
        "http": normHttp(banner, text),
        "ssh": {
            "type": ssh.get("type"),
            "fingerprint": ssh.get("fingerprint"),
            "key": ssh.get("key"),
            "pubkey": normSshKey(ssh),
        }
        if ssh
        else None,
    }


def normHost(host: dict) -> dict:
    """Normalize a ``/shodan/host/{ip}`` response."""

    banners = [normBanner(b) for b in host.get("data") or []]

    # Hosts report vulns as a list, banners report detailed vuln dicts - prefer
    # the details when a banner has them.
    vulns = {v["cve"]: v for v in normVulns(host.get("vulns"))}
    for banner in banners:
        for vuln in banner["vulns"]:
            vulns[vuln["cve"]] = vuln

    return {
        "ip": host.get("ip_str"),
        "asn": host.get("asn"),
        "org": host.get("org"),
        "isp": host.get("isp"),
        "os": host.get("os"),
        "last_update": _ts(host.get("last_update")),
        "hostnames": [h.lower() for h in _list(host.get("hostnames"))],
        "domains": [d.lower() for d in _list(host.get("domains"))],
        "tags": _list(host.get("tags")),
        "ports": sorted(set(_list(host.get("ports")))),
        "cpes": [],
        "vulns": list(vulns.values()),
        "location": normLocation(host),
        "banners": banners,
    }


def normInternetDb(data: dict) -> dict:
    """Normalize an InternetDB response so it can share the host modeling code."""

    return {
        "ip": data.get("ip"),
        "asn": None,
        "org": None,
        "isp": None,
        "os": None,
        "last_update": None,
        "hostnames": [h.lower() for h in _list(data.get("hostnames"))],
        "domains": [],
        "tags": _list(data.get("tags")),
        "ports": sorted(set(_list(data.get("ports")))),
        "cpes": normCpes(data.get("cpes")),
        "vulns": normVulns(data.get("vulns")),
        "location": None,
        "banners": [],
    }


def normDnsRecords(data: dict) -> list[dict]:
    """Normalize a ``/dns/domain/{domain}`` response into a list of DNS records."""

    domain = (data.get("domain") or "").lower()
    retn = []
    for rec in data.get("data") or []:
        sub = rec.get("subdomain") or ""
        fqdn = f"{sub}.{domain}" if sub else domain
        retn.append(
            {
                "fqdn": fqdn.lower(),
                "type": (rec.get("type") or "").upper(),
                "value": rec.get("value"),
                "seen": _ts(rec.get("last_seen")),
            }
        )
    return retn


def _refs(refs: Any) -> list[str]:
    """Reference URLs, which are strings in CVEs and ``{"type": ..., "url": ...}`` dicts in GHSAs."""

    urls = [r.get("url") if isinstance(r, dict) else r for r in _list(refs)]
    return [u for u in urls if isinstance(u, str) and "://" in u]


def normCve(data: dict) -> dict:
    """Normalize a CVEDB CVE (``/cve/{id}`` or an item from ``/cves``).

    Also accepts the ``cve`` object nested in GHSA/EUVD responses, which uses
    ``id`` instead of ``cve_id``.
    """

    # GHSA/EUVD IDs that CVEDB has linked to this CVE.
    aliases = []
    for key in ("ghsa", "euvd"):
        info = data.get(key) or {}
        if info.get("id"):
            aliases.append(info["id"].upper())

    return {
        "cve": (data.get("cve_id") or data.get("id") or "").upper(),
        "aliases": aliases,
        "summary": data.get("summary"),
        "cvss": data.get("cvss"),
        "cvss_version": data.get("cvss_version"),
        "cvss_v2": data.get("cvss_v2"),
        "cvss_v3": data.get("cvss_v3"),
        "cvss_v4": data.get("cvss_v4"),
        "epss": data.get("epss"),
        "ranking_epss": data.get("ranking_epss"),
        "kev": bool(data.get("kev")),
        "propose_action": data.get("propose_action"),
        "ransomware_campaign": data.get("ransomware_campaign"),
        "references": _refs(data.get("references")),
        "published": _ts(data.get("published_time")),
        "cpes": normCpes(data.get("cpes")),
        "cwes": [],
    }


def normAdvisory(data: dict) -> dict:
    """Normalize a CVEDB ``/ghsa/{id}`` or ``/euvd/{id}`` response into the ``normCve`` shape.

    When CVEDB links the advisory to a CVE the CVE's details are used, with the
    advisory's ID(s) as aliases. Otherwise ``cve`` is empty and the advisory's own
    details are used.
    """

    advid = (data.get("euvd_id") or data.get("id") or "").upper()

    if data.get("cve"):
        retn = normCve(data["cve"])
    else:
        retn = normCve(
            {
                "summary": data.get("summary") or data.get("description"),
                "cvss": data.get("cvss"),
                "epss": data.get("epss"),
                "published_time": data.get("published_time"),
            }
        )

    aliases = [advid]
    for key in ("ghsa", "euvd"):
        info = data.get(key) or {}
        if info.get("id"):
            aliases.append(info["id"].upper())
    retn["aliases"] = sorted(set(retn["aliases"] + aliases))

    retn["references"] = sorted(set(retn["references"] + _refs(data.get("references"))))
    retn["cwes"] = [c.upper() for c in _list(data.get("cwe_ids")) if isinstance(c, str)]
    if not retn["summary"]:
        retn["summary"] = data.get("summary") or data.get("description")

    return retn

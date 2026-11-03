"""The slib.bgphe service.

Queries Hurricane Electric's BGP Toolkit (https://bgp.he.net) and normalizes the results for
the slib.bgphe Storm package to model:

- Certificates (from CT logs) by domain, the subdomains with certificates, and the hostnames
  on certificates that resolve to IPs in a prefix.
- Domain whois records.
- ASN whois records (the organization behind an ASN) and the prefixes an ASN originates.

Nothing is stored, every call is a fresh query.
"""

import datetime
import logging
from collections.abc import AsyncIterator

import aiohttp
import synapse.lib.cell as s_cell

from . import certs, norm, whois
from .api import BgpHeCellApi
from .client import CERT_PAGE_SIZE, BgpHeClient

logger = logging.getLogger(__name__)

MAX_CERTS = 10_000
"""The most certificates a single certificate lookup returns (50 pages)."""


class BgpHeSvcError(Exception):
    """A service operation failed."""

    def __init__(self, mesg: str):
        super().__init__(mesg)
        self.mesg = mesg


def _now() -> int:
    """The current time in epoch millis."""

    return int(datetime.datetime.now(datetime.UTC).timestamp() * 1000)


def isValid(details: dict, now: int) -> bool:
    """Whether a certificate's validity period includes now."""

    notbefore = details.get("notbefore")
    notafter = details.get("notafter")
    if notafter is None or notafter < now:
        return False
    return notbefore is None or notbefore <= now


class BgpHeSvc(s_cell.Cell):
    """The Cell implementation for the slib.bgphe service."""

    cellapi = BgpHeCellApi

    confdefs = {
        "bgphe:url": {
            "type": "string",
            "default": "https://bgp.he.net",
            "description": "The base URL of Hurricane Electric's BGP Toolkit.",
        },
        "bgphe:interval": {
            "type": "number",
            "default": 1.0,
            "minimum": 0,
            "description": "The minimum number of seconds between two requests to bgp.he.net.",
        },
        "bgphe:timeout": {
            "type": "number",
            "default": 60,
            "minimum": 1,
            "description": "Timeout, in seconds, for a single bgp.he.net request.",
        },
        "bgphe:backoff": {
            "type": "number",
            "default": 2.0,
            "minimum": 0,
            "description": "The base, in seconds, of the exponential backoff between retries.",
        },
    }

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)

        self.session = aiohttp.ClientSession(trust_env=True)
        self.onfini(self.session.close)

        self.client = BgpHeClient(
            self.session,
            url=self.conf.get("bgphe:url"),
            interval=self.conf.get("bgphe:interval"),
            timeout=self.conf.get("bgphe:timeout"),
            backoff=self.conf.get("bgphe:backoff"),
        )

    # ---- Certificates ----

    async def certs(
        self, domain: str, limit: int = CERT_PAGE_SIZE, valid: bool = False, precerts: bool = True
    ) -> AsyncIterator[dict]:
        """Yield the CT log certificates for a domain, with all of their details parsed.

        The certificates are those with the domain itself in their SANs or subject (not its
        subdomains, use ``subdomains()`` to find those).

        Parameters
        ----------
        domain : str
            The domain.
        limit : int
            The most certificates to yield (at most ``MAX_CERTS``). bgp.he.net pages
            certificates 200 at a time, so this also caps the requests: ``limit / 200``.
        valid : bool
            Only yield certificates that are currently valid.
        precerts : bool
            Also yield precertificates.

        Yields
        ------
        dict
            ``{"type": "cert", "cert": <details>}`` for each certificate (see
            ``certs.heCert``), then one ``{"type": "summary", ...}`` with the domain's
            ``total`` certificates in bgp.he.net, the ``returned`` and ``skipped`` (filtered)
            counts, the ``pages`` read, and whether there are ``more``.
        """

        domain = self._norm(norm.normDomain, domain)
        limit = self._limit(limit, MAX_CERTS)
        now = _now()

        seen = set()
        returned = skipped = invalid = pages = 0
        total = None
        more = False
        page = 1

        while returned < limit:
            data = await self.client.certsByDomain(domain, page=page)
            pages += 1
            pagination = data.get("pagination") or {}
            if total is None:
                total = pagination.get("total_certificates")
            totalpages = pagination.get("total_pages") or 0

            for item in data["certificates"]:
                if returned >= limit:
                    more = True
                    break
                details = certs.heCert(item) if isinstance(item, dict) else None
                if details is None:
                    invalid += 1
                    continue
                key = certs.certKey(details)
                if key in seen:
                    continue
                seen.add(key)
                if (valid and not isValid(details, now)) or (not precerts and details["precert"]):
                    skipped += 1
                    continue
                returned += 1
                yield {"type": "cert", "cert": details}

            if not data["certificates"] or page >= totalpages:
                break
            if returned >= limit:
                more = True
                break
            page += 1

        yield {
            "type": "summary",
            "domain": domain,
            "total": total,
            "returned": returned,
            "skipped": skipped,
            "invalid": invalid,
            "pages": pages,
            "more": more,
        }

    async def subdomains(self, domain: str) -> dict:
        """The domain and its subdomains that have certificates, with how many each has.

        Returns ``{"domain", "domains": [{"fqdn", "certs"}], "certs", "truncated"}`` (see
        ``norm.normSubdomains``).
        """

        domain = self._norm(norm.normDomain, domain)
        return norm.normSubdomains(domain, await self.client.certDomains(domain))

    async def hosts(self, valu: str) -> dict:
        """The hostnames, from certificates, that resolve to the IPs in an IP or CIDR.

        Returns ``{"prefix", "entries": [{"ip", "version", "fqdns"}], "ips", "hostnames",
        "truncated"}`` (see ``norm.normHosts``). bgp.he.net returns a sample of up to ~1000
        hostnames per query, ``truncated`` says when there are more.
        """

        prefix = self._norm(norm.normPrefix, valu)
        data = await self.client.certsByPrefix(prefix["addr"], prefix["len"])
        return norm.normHosts(prefix, data)

    # ---- Whois ----

    async def whoisDomain(self, domain: str) -> dict:
        """A domain's whois record, as ``{"fqdn", "text", "rec": <parsed>}``.

        See ``whois.parseDomain`` for the parsed record. bgp.he.net caches whois records, the
        record's ``asof`` is when the registry answered, if the record says.
        """

        domain = self._norm(norm.normDomain, domain)
        text = whois.fixText(await self.client.whoisDomain(domain)).strip("\n")
        return {"fqdn": domain, "text": text, "rec": whois.parseDomain(domain, text)}

    async def whoisAsn(self, asn: int | str) -> dict:
        """An ASN's whois record, from its RIR, as ``{"asn", "text", "rec": <parsed>}``.

        See ``whois.parseAsn`` for the parsed record.
        """

        asn = self._norm(norm.normAsn, asn)
        text = whois.fixText(await self.client.whoisAsn(asn)).strip("\n")
        return {"asn": asn, "text": text, "rec": whois.parseAsn(asn, text)}

    # ---- BGP ----

    async def prefixes(self, asn: int | str) -> dict:
        """The prefixes an ASN originates, according to HE's Super Looking Glass.

        Returns ``{"asn", "prefixes": [{"prefix", "version", "count", "total"}], "v4", "v6"}``
        (see ``norm.normPrefixes``).
        """

        asn = self._norm(norm.normAsn, asn)
        rows = norm.normPrefixes(await self.client.prefixesOriginated(asn))
        return {
            "asn": asn,
            "prefixes": rows,
            "v4": sum(1 for row in rows if row["version"] == 4),
            "v6": sum(1 for row in rows if row["version"] == 6),
        }

    # ---- Helpers ----

    @staticmethod
    def _norm(func, valu):
        try:
            return func(valu)
        except norm.BadValu as err:
            raise BgpHeSvcError(err.mesg) from None

    @staticmethod
    def _limit(limit, most: int) -> int:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise BgpHeSvcError(f"Invalid limit: {limit!r}, it must be a positive integer.")
        return min(limit, most)

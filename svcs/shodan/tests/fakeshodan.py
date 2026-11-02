"""A fake Shodan HTTP server for tests.

Serves canned responses for every Shodan API under a per-API path prefix (ex.
``/api/shodan/host/8.8.8.8``, ``/cvedb/cve/CVE-2021-44228``) and records every
request so tests can assert exactly what the service sent.
"""

import contextlib
import json
from typing import Any

from aiohttp import web


HOST_8888 = {
    "ip_str": "8.8.8.8",
    "asn": "AS15169",
    "org": "Google LLC",
    "isp": "Google LLC",
    "os": None,
    "last_update": "2026-10-01T12:00:00.000000",
    "hostnames": ["dns.google"],
    "domains": ["dns.google"],
    "tags": ["cloud", "honeypot"],
    "ports": [53, 443],
    "vulns": ["CVE-2021-44228"],
    "country_code": "US",
    "country_name": "United States",
    "city": "Mountain View",
    "region_code": "CA",
    "latitude": 37.4056,
    "longitude": -122.0775,
    "data": [
        {
            "ip_str": "8.8.8.8",
            "port": 443,
            "transport": "tcp",
            "timestamp": "2026-10-01T12:00:00.000000",
            "product": "nginx",
            "version": "1.25.3",
            # Real banners list OS CPEs alongside the product's.
            "cpe23": ["cpe:2.3:a:f5:nginx:1.25.3", "cpe:2.3:o:linux:linux_kernel"],
            "data": "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
            "hostnames": ["dns.google"],
            "domains": ["dns.google"],
            "tags": ["cdn"],
            "asn": "AS15169",
            "org": "Google LLC",
            "vulns": {
                "CVE-2021-44228": {"cvss": 10.0, "verified": False, "summary": "Log4Shell"},
            },
            "location": {
                "city": "Mountain View",
                "region_code": "CA",
                "country_code": "US",
                "country_name": "United States",
                "latitude": 37.4056,
                "longitude": -122.0775,
            },
            "http": {"title": "Google DNS", "server": "nginx", "status": 200},
            "ssl": {
                "cert": {
                    "fingerprint": {
                        "sha256": "a" * 64,
                        "sha1": "b" * 40,
                    },
                    "serial": 1234567890,
                    "subject": {"CN": "dns.google"},
                    "issuer": {"CN": "GTS CA 1C3", "O": "Google Trust Services"},
                    "issued": "20260901000000Z",
                    "expires": "20261201000000Z",
                    "sig_alg": "sha256WithRSAEncryption",
                    "version": 2,
                },
                "versions": ["TLSv1.2", "TLSv1.3"],
                "jarm": "29d29d00029d29d00041d41d0000005",
            },
            "_shodan": {"module": "https", "id": "abc", "crawler": "xyz"},
        },
        {
            "ip_str": "8.8.8.8",
            "port": 53,
            "transport": "udp",
            "timestamp": "2026-09-30T12:00:00.000000",
            "data": "Recursion: enabled",
            "tags": [],
            "_shodan": {"module": "dns-udp"},
        },
    ],
}

# Trimmed from a real Shodan host lookup of scanme.nmap.org. The banner "hash" is Shodan's own.
SSH_KEY_B64 = 'AAAAB3NzaC1yc2EAAAADAQABAAABAQC6afooTZ9mVUGFNEhkMoRR1Btzu64XXwElhCsHw/zVlIx/\nHXylNbb9+11dm2VgJQ21pxkWDs+L6+EbYyDnvRURTrMTgHL0xseB0EkNqexs9hYZSiqtMx4jtGNt\nHvsMxZnbxvVUk2dasWvtBkn8J5JagSbzWTQo4hjKMOI1SUlXtiKxAs2F8wiq2EdSuKw/KNk8GfIp\n1TA+8ccGeAtnsVptTJ4D/8MhAWsROkQzOowQvnBBz2/8ecEvoMScaf+kDfNQowK3gENtSSOqYw9J\nLOza6YJBPL/aYuQQ0nJ74Rr5vL44aNIlrGI9jJc2x0bV7BeNA5kVuXsmhyfWbbkB8yGd\n'
HOST_SSH = {
    "ip_str": "45.33.32.156",
    "last_update": "2026-11-01T14:21:51.848593",
    "hostnames": ["scanme.nmap.org"],
    "ports": [22],
    "data": [
        {
            "ip_str": "45.33.32.156",
            "port": 22,
            "transport": "tcp",
            "timestamp": "2026-10-30T03:23:08.176003",
            "product": "OpenSSH",
            "version": "6.6.1p1 Ubuntu 2ubuntu2.13",
            "data": 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13\nKey type: ssh-rsa\nKey: AAAAB3NzaC1yc2EAAAADAQABAAABAQC6afooTZ9mVUGFNEhkMoRR1Btzu64XXwElhCsHw/zVlIx/\nHXylNbb9+11dm2VgJQ21pxkWDs+L6+EbYyDnvRURTrMTgHL0xseB0EkNqexs9hYZSiqtMx4jtGNt\nHvsMxZnbxvVUk2dasWvtBkn8J5JagSbzWTQo4hjKMOI1SUlXtiKxAs2F8wiq2EdSuKw/KNk8GfIp\n1TA+8ccGeAtnsVptTJ4D/8MhAWsROkQzOowQvnBBz2/8ecEvoMScaf+kDfNQowK3gENtSSOqYw9J\nLOza6YJBPL/aYuQQ0nJ74Rr5vL44aNIlrGI9jJc2x0bV7BeNA5kVuXsmhyfWbbkB8yGd\nFingerprint: 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2\n\nKex Algorithms:\n\tcurve25519-sha256@libssh.org\n\tecdh-sha2-nistp256\n\tecdh-sha2-nistp384\n\tecdh-sha2-nistp521\n\tdiffie-hellman-group-exchange-sha256\n\tdiffie-hellman-group-exchange-sha1\n\tdiffie-hellman-group14-sha1\n\tdiffie-hellman-group1-sha1\n\nServer Host Key Algorithms:\n\tssh-rsa\n\tssh-dss\n\tecdsa-sha2-nistp256\n\tssh-ed25519\n\nEncryption Algorithms:\n\taes128-ctr\n\taes192-ctr\n\taes256-ctr\n\tarcfour256\n\tarcfour128\n\taes128-gcm@openssh.com\n\taes256-gcm@openssh.com\n\tchacha20-poly1305@openssh.com\n\taes128-cbc\n\t3des-cbc\n\tblowfish-cbc\n\tcast128-cbc\n\taes192-cbc\n\taes256-cbc\n\tarcfour\n\trijndael-cbc@lysator.liu.se\n\nMAC Algorithms:\n\thmac-md5-etm@openssh.com\n\thmac-sha1-etm@openssh.com\n\tumac-64-etm@openssh.com\n\tumac-128-etm@openssh.com\n\thmac-sha2-256-etm@openssh.com\n\thmac-sha2-512-etm@openssh.com\n\thmac-ripemd160-etm@openssh.com\n\thmac-sha1-96-etm@openssh.com\n\thmac-md5-96-etm@openssh.com\n\thmac-md5\n\thmac-sha1\n\tumac-64@openssh.com\n\tumac-128@openssh.com\n\thmac-sha2-256\n\thmac-sha2-512\n\thmac-ripemd160\n\thmac-ripemd160@openssh.com\n\thmac-sha1-96\n\thmac-md5-96\n\nCompression Algorithms:\n\tnone\n\tzlib@openssh.com\n',
            "hash": -145740310,
            "ssh": {
                "type": "ssh-rsa",
                "fingerprint": "20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2",
                "key": SSH_KEY_B64,
                "hassh": "ba6d3d2aecbd0d91b01dfa7828110d70",
            },
            "_shodan": {"module": "ssh"},
        }
    ],
}

# From a real Shodan host lookup of scanme.nmap.org port 80, with Shodan's hashes of them.
# FAVICON_B64 is Shodan's http.favicon.data as-is, base64 with a newline every 76 characters.
FAVICON_B64 = 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAActJREFUOMvV\nk01IFAEYhp+Z0d2ddpxiVjeTwXL/aMEKXWopQsFIzOokdIjAk1EXb+XRPQQGXSKiiI5RVofcwlOC\n2w8RQUSxhDKEgWVRjq3pbrO7zs50iA5bndxTz/Hj/d7D+72fABBXelzWwUx+WhDWu/wbkRqp2aDu\nz0G9IpM82kWyfy96WMfj82J+NnmVecnTe4/4NrdQpa/KILx/F6cuDBPRg5y/PVklPHOsn4JV4kH6\nMfdHr2OXytUGg1dG6Ovdw8WJhwBEd3TwwcwB0Ko1YLzNAnD6SA9LywXGBlOYxjxSm96ZOnt3jERn\njEzWYOhQN17Zj1Mu8/zODXIzr2luDZGIxzjetZvprEGjqnD4RB8fP5kI1yZfuKtiBUkSGdjXgQu8\neTePVbZJj99C9npIHuiluamRnaEWREEkk51lwVwhEWtDEgtNqWB7HC2goW6Q8dVLFO0KhaKNti3K\nxqCOqjYQUP0EVIUfaw45q4JVckhfGv+VgVAn4VMVDp4bJtIeJdGi8iWX5+v3PACaXya8RePJ3CKL\ny6tMjV5mafY9zprNX03ctD1E98hJNke24pFEcF0qQNEq8ezqTYyJKXDcf5/x/6yyUOs7/wQ4uKBj\nWXYJDwAAAABJRU5ErkJggg==\n'
FAVICON_HASH = 536238901
SCANME_HTML = '<!DOCTYPE html>\n<html lang="en">\n<head>\n<title>Go ahead and ScanMe!</title>\n<meta name="viewport" content="width=device-width,initial-scale=1">\n<meta name="theme-color" content="#2A0D45">\n<link rel="preload" as="image" href="/images/sitelogo.png" imagesizes="168px" imagesrcset="/images/sitelogo.png, /images/sitelogo-2x.png 2x">\n<link rel="preload" as="image" href="/shared/images/nst-icons.svg">\n<link rel="stylesheet" href="/shared/css/nst.css?v=2">\n<script async src="/shared/js/nst.js?v=2"></script>\n<link rel="stylesheet" href="/shared/css/nst-foot.css?v=2" media="print" onload="this.media=\'all\'">\n<link rel="stylesheet" href="/site.css">\n<!--Google Analytics Code-->\n<link rel="preload" href="https://www.google-analytics.com/analytics.js" as="script">\n<script>\n(function(i,s,o,g,r,a,m){i[\'GoogleAnalyticsObject\']=r;i[r]=i[r]||function(){\n(i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),\nm=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)\n})(window,document,\'script\',\'//www.google-analytics.com/analytics.js\',\'ga\');\nga(\'create\', \'UA-11009417-1\', \'auto\');\nga(\'send\', \'pageview\');\n</script>\n<!--END Google Analytics Code-->\n<META NAME="ROBOTS" CONTENT="NOARCHIVE">\n<link rel="shortcut icon" href="/shared/images/tiny-eyeicon.png" type="image/png">\n</head>\n<body><div id="nst-wrapper">\n\n<div id="menu">\n <div class="blur">\n  <header id="nst-head">\n\n    <a id="menu-open" href="#menu" aria-label="Open menu">\n     <img width="44" height="44" alt="" aria-hidden="true"\n      src="/shared/images/nst-icons.svg#menu">\n    </a>\n    <a id="menu-close" href="#" aria-label="Close menu">\n     <img width="44" height="44" alt="" aria-hidden="true"\n      src="/shared/images/nst-icons.svg#close">\n    </a>\n\n   <a id="nst-logo" href="/" aria-label="Home page">\n    <img alt="Home page logo" srcset="/images/sitelogo.png, /images/sitelogo-2x.png 2x" src="/images/sitelogo.png" onerror="this.onerror=null;this.srcset=this.src" height=90 width=168></a>\n\n   <nav id="nst-gnav">\n    <a class="nlink" href="https://nmap.org/">Nmap.org</a>\n    <a class="nlink" href="https://npcap.com/">Npcap.com</a>\n    <a class="nlink" href="https://seclists.org/">Seclists.org</a>\n    <a class="nlink" href="https://sectools.org">Sectools.org</a>\n    <a class="nlink" href="https://insecure.org/">Insecure.org</a>\n   </nav>\n\n   <form class="nst-search" id="nst-head-search" action="/search/">\n    <input class="nst-search-q" name="q" type="search" placeholder="Site Search">\n    <button class="nst-search-button" title="Search">\n     <img style="width:100%;aspect-ratio:1/1;" alt="" aria-hidden="true"\n      src="/shared/images/nst-icons.svg#search">\n     </button>\n   </form>\n\n  </header>\n </div>\n</div>\n\n<main id="nst-content">\n\n<p>Hello, and welcome to Scanme.Nmap.Org, a service provided by the <a href="https://nmap.org">Nmap Security Scanner Project</a>.\n\n<p>We set up this machine to help folks learn about Nmap and also to test and make sure that their Nmap installation (or Internet connection) is working properly.  You are authorized to scan this machine with Nmap or other port scanners.  Try not to hammer on the server too hard.  A few scans in a day is fine, but don\'t scan 100 times a day or use this site to test your ssh brute-force password cracking tool.\n\n<p>Thanks<br>\n-<a href="https://insecure.org/fyodor">Fyodor</a>\n</main><!-- content -->\n\n<footer id="nst-foot">\n   <form class="nst-search" id="nst-foot-search" action="/search/">\n    <input class="nst-search-q" name="q" type="search" placeholder="Site Search">\n    <button class="nst-search-button" title="Search">\n     <img style="width:100%;aspect-ratio:1/1;" alt="" aria-hidden="true"\n      src="/shared/images/nst-icons.svg#search">\n     </button>\n   </form>\n<div class="flexlists">\n<div class="fl-unit">\n<h2><a class="nlink" href="https://nmap.org/">Nmap Security Scanner</a></h2>\n<ul>\n<li><a class="nlink" href="https://nmap.org/book/man.html">Ref Guide</a>\n<li><a class="nlink" href="https://nmap.org/book/install.html">Install Guide</a>\n<li><a class="nlink" href="https://nmap.org/docs.html">Docs</a>\n<li><a class="nlink" href="https://nmap.org/download.html">Download</a>\n<li><a class="nlink" href="https://nmap.org/oem/">Nmap OEM</a>\n</ul>\n</div>\n<div class="fl-unit">\n<h2><a class="nlink" href="https://npcap.com/">Npcap packet capture</a></h2>\n<ul>\n<li><a class="nlink" href="https://npcap.com/guide/">User\'s Guide</a>\n<li><a class="nlink" href="https://npcap.com/guide/npcap-devguide.html#npcap-api">API docs</a>\n<li><a class="nlink" href="https://npcap.com/#download">Download</a>\n<li><a class="nlink" href="https://npcap.com/oem/">Npcap OEM</a>\n</ul>\n</div>\n<div class="fl-unit">\n<h2><a class="nlink" href="https://seclists.org/">Security Lists</a></h2>\n<ul>\n<li><a class="nlink" href="https://seclists.org/nmap-announce/">Nmap Announce</a>\n<li><a class="nlink" href="https://seclists.org/nmap-dev/">Nmap Dev</a>\n<li><a class="nlink" href="https://seclists.org/fulldisclosure/">Full Disclosure</a>\n<li><a class="nlink" href="https://seclists.org/oss-sec/">Open Source Security</a>\n<li><a class="nlink" href="https://seclists.org/dataloss/">BreachExchange</a>\n</ul>\n</div>\n<div class="fl-unit">\n<h2><a class="nlink" href="https://sectools.org">Security Tools</a></h2>\n<ul>\n<li><a class="nlink" href="https://sectools.org/tag/vuln-scanners/">Vuln scanners</a>\n<li><a class="nlink" href="https://sectools.org/tag/pass-audit/">Password audit</a>\n<li><a class="nlink" href="https://sectools.org/tag/web-scanners/">Web scanners</a>\n<li><a class="nlink" href="https://sectools.org/tag/wireless/">Wireless</a>\n<li><a class="nlink" href="https://sectools.org/tag/sploits/">Exploitation</a>\n</ul>\n</div>\n<div class="fl-unit">\n<h2><a class="nlink" href="https://insecure.org/">About</a></h2>\n<ul>\n<li><a class="nlink" href="https://insecure.org/fyodor/">About/Contact</a>\n<li><a class="nlink" href="https://insecure.org/privacy.html">Privacy</a>\n<li><a class="nlink" href="https://insecure.org/advertising.html">Advertising</a>\n<li><a class="nlink" href="https://nmap.org/npsl/">Nmap Public Source License</a>\n</ul>\n</div>\n<div class="fl-unit social-links">\n<a class="nlink" href="https://twitter.com/nmap" title="Visit us on Twitter">\n <img width="32" height="32" src="/shared/images/nst-icons.svg#twitter" alt="" aria-hidden="true">\n </a>\n<a class="nlink" href="https://facebook.com/nmap" title="Visit us on Facebook">\n <img width="32" height="32" src="/shared/images/nst-icons.svg#facebook" alt="" aria-hidden="true">\n </a>\n<a class="nlink" href="https://github.com/nmap/" title="Visit us on Github">\n <img width="32" height="32" src="/shared/images/nst-icons.svg#github" alt="" aria-hidden="true">\n </a>\n<a class="nlink" href="https://reddit.com/r/nmap/" title="Discuss Nmap on Reddit">\n <img width="32" height="32" src="/shared/images/nst-icons.svg#reddit" alt="" aria-hidden="true">\n </a>\n</div>\n</div>\n</footer>\n\n</div><!-- wrapper -->\n</body>\n</html>\n\n'
SCANME_HTML_HASH = 1386351316

INTERNETDB_1111 = {
    "ip": "1.1.1.1",
    "ports": [53, 80],
    "hostnames": ["one.one.one.one"],
    "cpes": ["cpe:/a:cloudflare:cloudflare"],
    "vulns": ["CVE-2023-44487"],
    "tags": ["cdn"],
}

CVE_LOG4SHELL = {
    "cve_id": "CVE-2021-44228",
    "summary": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
    "cvss": 10.0,
    "cvss_version": 3.1,
    "cvss_v2": 9.3,
    "cvss_v3": 10.0,
    "epss": 0.97,
    "ranking_epss": 0.99,
    "kev": True,
    "propose_action": "Apply updates per vendor instructions.",
    "ransomware_campaign": "Known",
    "references": ["https://logging.apache.org/log4j/2.x/security.html"],
    "published_time": "2021-12-10T10:15:09",
    "cpes": ["cpe:2.3:a:apache:log4j:2.0:-:*:*:*:*:*:*"],
}

# Trimmed from real CVEDB responses.
GHSA_LOG4SHELL = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "summary": "Remote code injection in Log4j",
    "details": "# Summary\n\nLog4j versions prior to 2.16.0 are subject to a remote code execution vulnerability.",
    "published_time": "2021-12-10T00:40:56Z",
    "modified_time": "2025-10-22T19:13:24Z",
    "withdrawn_time": None,
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
    "affected": [],
    "references": [
        {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
        {"type": "WEB", "url": "https://logging.apache.org/log4j/2.x/security.html"},
    ],
    "cwe_ids": ["CWE-20", "CWE-502"],
    "github_severity": "CRITICAL",
    "github_reviewed": True,
    "cve": {
        "id": "CVE-2021-44228",
        "summary": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
        "cvss": 10.0,
        "cvss_version": 3.0,
        "cvss_v2": 9.3,
        "cvss_v3": 10.0,
        "cvss_v4": None,
        "epss": 0.99999,
        "ranking_epss": 1.0,
        "kev": True,
        "propose_action": None,
        "ransomware_campaign": "Known",
        "references": ["https://logging.apache.org/log4j/2.x/security.html"],
        "published_time": "2021-12-10T10:15:09",
        "cpes": ["cpe:2.3:a:apache:log4j:2.0:-:*:*:*:*:*:*"],
    },
    "euvd": {"id": "EUVD-2021-34768", "description": "Apache Log4j2 JNDI features..."},
}

# An advisory that CVEDB hasn't linked to a CVE.
EUVD_NO_CVE = {
    "euvd_id": "EUVD-2099-0001",
    "description": "A made up advisory without a CVE.",
    "published_time": "2099-01-01T00:00:00",
    "cvss": 7.5,
    "cvss_version": "3.1",
    "epss": 0.01,
    "assigner": "mitre",
    "references": ["https://example.com/advisory"],
    "products": ["n/a"],
    "vendors": ["n/a"],
    "cve": None,
    "ghsa": None,
}

SEARCH_PAGE = {
    "total": 2,
    "matches": [
        dict(HOST_8888["data"][0]),
        {
            "ip_str": "2001:4860:4860::8888",
            "port": 443,
            "transport": "tcp",
            "timestamp": "2026-10-01T12:00:00.000000",
            "data": "HTTP/1.1 200 OK",
            "_shodan": {"module": "https"},
        },
    ],
    "facets": {"country": [{"value": "US", "count": 2}]},
}

DNS_DOMAIN = {
    "domain": "vertex.link",
    "tags": ["ipv6"],
    "subdomains": ["www", "api"],
    "more": False,
    "data": [
        {
            "subdomain": "",
            "type": "A",
            "value": "1.2.3.4",
            "last_seen": "2026-10-01T00:00:00.000000",
        },
        {
            "subdomain": "www",
            "type": "CNAME",
            "value": "vertex.link",
            "last_seen": "2026-10-01T00:00:00.000000",
        },
        {
            "subdomain": "",
            "type": "MX",
            "value": "mx.vertex.link",
            "last_seen": "2026-10-01T00:00:00.000000",
        },
        {
            "subdomain": "",
            "type": "NS",
            "value": "ns1.vertex.link",
            "last_seen": "2026-10-01T00:00:00.000000",
        },
        {
            "subdomain": "",
            "type": "TXT",
            "value": "v=spf1 -all",
            "last_seen": "2026-10-01T00:00:00.000000",
        },
        {
            "subdomain": "api",
            "type": "AAAA",
            "value": "2001:db8::1",
            "last_seen": "2026-10-01T00:00:00.000000",
        },
    ],
}

API_INFO = {
    "plan": "dev",
    "query_credits": 99,
    "scan_credits": 98,
    "monitored_ips": 1,
    "unlocked": True,
    "unlocked_left": 99,
    "https": True,
    "telnet": False,
    "usage_limits": {"query_credits": 100, "scan_credits": 100, "monitored_ips": 16},
}

ALERT = {
    "id": "ALERT1",
    "name": "corp",
    "created": "2026-10-01T00:00:00",
    "expires": 0,
    "expired": False,
    "filters": {"ip": ["1.2.3.0/24"]},
    "triggers": {"new_service": {}},
    "notifiers": [{"id": "default"}],
}

# Canned responses keyed by (method, path). Values are (status, body) or a callable(request) -> (status, body).
ROUTES: dict[tuple[str, str], Any] = {
    ("GET", "/api/shodan/host/8.8.8.8"): (200, HOST_8888),
    ("GET", "/api/shodan/host/45.33.32.156"): (200, HOST_SSH),
    ("GET", "/api/shodan/host/10.0.0.1"): (404, {"error": "No information available for that IP."}),
    ("GET", "/api/shodan/host/count"): (
        200,
        {"total": 1234, "facets": {"port": [{"value": 443, "count": 1000}]}},
    ),
    ("GET", "/api/shodan/host/search"): (200, SEARCH_PAGE),
    ("GET", "/api/shodan/host/search/facets"): (200, ["country", "port"]),
    ("GET", "/api/shodan/host/search/filters"): (200, ["port", "product"]),
    ("GET", "/api/shodan/host/search/tokens"): (
        200,
        {"filters": ["port"], "string": "nginx", "attributes": {"ports": [80]}},
    ),
    ("GET", "/api/shodan/ports"): (200, [22, 80, 443]),
    ("GET", "/api/shodan/protocols"): (200, {"https": "HTTPS banner grabber"}),
    ("GET", "/api/shodan/services"): (200, {"22": "SSH", "443": "HTTPS"}),
    ("POST", "/api/shodan/scan"): (200, {"id": "SCAN1", "count": 1, "credits_left": 97}),
    ("POST", "/api/shodan/scan/internet"): (200, {"id": "ISCAN1"}),
    ("GET", "/api/shodan/scans"): (
        200,
        {
            "total": 1,
            "matches": [
                {
                    "id": "SCAN1",
                    "status": "DONE",
                    "size": 1,
                    "credits_left": 97,
                    "created": "2026-10-01",
                }
            ],
        },
    ),
    ("GET", "/api/shodan/scan/SCAN1"): (
        200,
        {"id": "SCAN1", "status": "DONE", "count": 1, "created": "2026-10-01"},
    ),
    ("POST", "/api/shodan/alert"): (200, ALERT),
    ("POST", "/api/shodan/alert/ALERT1"): (200, ALERT),
    ("GET", "/api/shodan/alert/info"): (200, [ALERT]),
    ("GET", "/api/shodan/alert/ALERT1/info"): (200, ALERT),
    ("DELETE", "/api/shodan/alert/ALERT1"): (200, {"success": True}),
    ("GET", "/api/shodan/alert/triggers"): (
        200,
        [{"name": "new_service", "rule": "*", "description": "New service"}],
    ),
    ("PUT", "/api/shodan/alert/ALERT1/trigger/new_service"): (200, {"success": True}),
    ("PUT", "/api/shodan/alert/ALERT1/trigger/malware"): (200, {"success": True}),
    ("DELETE", "/api/shodan/alert/ALERT1/trigger/new_service"): (200, {"success": True}),
    ("PUT", "/api/shodan/alert/ALERT1/trigger/open_database/ignore/1.2.3.4:9200"): (
        200,
        {"success": True},
    ),
    ("DELETE", "/api/shodan/alert/ALERT1/trigger/open_database/ignore/1.2.3.4:9200"): (
        200,
        {"success": True},
    ),
    ("PUT", "/api/shodan/alert/ALERT1/notifier/default"): (200, {"success": True}),
    ("DELETE", "/api/shodan/alert/ALERT1/notifier/default"): (200, {"success": True}),
    ("GET", "/api/notifier"): (
        200,
        {"total": 1, "matches": [{"id": "default", "provider": "email", "description": None}]},
    ),
    ("GET", "/api/notifier/provider"): (200, {"slack": {"required": ["webhook_url"]}}),
    ("POST", "/api/notifier"): (200, {"success": True, "id": "NOTIF1"}),
    ("GET", "/api/notifier/NOTIF1"): (200, {"id": "NOTIF1", "provider": "slack", "args": {}}),
    ("PUT", "/api/notifier/NOTIF1"): (200, {"success": True, "id": "NOTIF1"}),
    ("DELETE", "/api/notifier/NOTIF1"): (200, {"success": True}),
    ("GET", "/api/shodan/query"): (
        200,
        {"total": 1, "matches": [{"votes": 5, "title": "Webcams", "query": "webcam"}]},
    ),
    ("GET", "/api/shodan/query/search"): (
        200,
        {"total": 1, "matches": [{"votes": 5, "title": "Webcams", "query": "webcam"}]},
    ),
    ("GET", "/api/shodan/query/tags"): (
        200,
        {"total": 1, "matches": [{"value": "webcam", "count": 10}]},
    ),
    ("GET", "/api/shodan/data"): (200, [{"name": "raw-daily", "description": "Daily data"}]),
    ("GET", "/api/shodan/data/raw-daily"): (
        200,
        [{"name": "2026-10-01.json.gz", "size": 1, "timestamp": 1, "url": "https://example.com/f"}],
    ),
    ("GET", "/api/org"): (
        200,
        {
            "id": "ORG1",
            "name": "Vertex",
            "upgrade_type": "corp",
            "domains": ["vertex.link"],
            "admins": [],
            "members": [],
        },
    ),
    ("PUT", "/api/org/member/visi"): (200, {"success": True}),
    ("DELETE", "/api/org/member/visi"): (200, {"success": True}),
    ("GET", "/api/account/profile"): (
        200,
        {"member": True, "credits": 0, "display_name": "visi", "created": "2020-01-01"},
    ),
    ("GET", "/api/api-info"): (200, API_INFO),
    ("GET", "/api/tools/myip"): (200, "5.6.7.8"),
    ("GET", "/api/tools/httpheaders"): (200, {"User-Agent": "test"}),
    ("GET", "/api/dns/domain/vertex.link"): (200, DNS_DOMAIN),
    ("GET", "/api/dns/resolve"): (200, {"vertex.link": "1.2.3.4"}),
    ("GET", "/api/dns/reverse"): (200, {"8.8.8.8": ["dns.google"]}),
    ("GET", "/trends/api/v1/search"): (
        200,
        {
            "total": 10,
            "matches": [{"month": "2026-09", "count": 10}],
            "facets": {"version": [{"key": "2026-09", "values": [{"value": "9.6", "count": 10}]}]},
        },
    ),
    ("GET", "/trends/api/v1/search/facets"): (200, ["version"]),
    ("GET", "/trends/api/v1/search/filters"): (200, ["product"]),
    ("GET", "/internetdb/1.1.1.1"): (200, INTERNETDB_1111),
    ("GET", "/internetdb/10.0.0.1"): (404, {"detail": "No information available"}),
    ("GET", "/cvedb/cve/CVE-2021-44228"): (200, CVE_LOG4SHELL),
    ("GET", "/cvedb/cves"): (200, {"cves": [CVE_LOG4SHELL]}),
    # CVEDB returns shortened CPEs.
    ("GET", "/cvedb/cpes"): (200, {"cpes": ["cpe:2.3:a:f5:nginx:1.25.3"]}),
    ("GET", "/cvedb/ghsa/GHSA-JFH8-C2JP-5V3Q"): (200, GHSA_LOG4SHELL),
    ("GET", "/cvedb/euvd/EUVD-2099-0001"): (200, EUVD_NO_CVE),
}

STREAM_BANNERS = [HOST_8888["data"][0], HOST_8888["data"][1]]


# Endpoints that only read their arguments from a form body, and the argument they require.
FORM_ROUTES = {
    ("POST", "/api/shodan/scan"): "ips",
    ("POST", "/api/shodan/scan/internet"): "protocol",
    ("POST", "/api/notifier"): "provider",
}


class FakeShodan:
    """Run with ``async with FakeShodan() as fake:`` and pass ``fake.urls`` as ``shodan:urls``."""

    def __init__(self):
        self.requests: list[dict] = []
        self.routes = dict(ROUTES)
        self.urls: dict[str, str] = {}

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        body = None
        form = {}
        if request.can_read_body:
            if request.content_type == "application/x-www-form-urlencoded":
                form = dict(await request.post())
            else:
                raw = await request.read()
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = raw.decode()

        self.requests.append(
            {
                "method": request.method,
                "path": request.path,
                "query": dict(request.query),
                "json": body,
                "form": form,
            }
        )

        if request.path.startswith("/stream/"):
            return await self._stream(request)

        if request.query.get("key") == "badkey":
            return web.json_response({"error": "Invalid API key"}, status=401)

        # Like the real API, these endpoints ignore query params and only read a form body.
        required = FORM_ROUTES.get((request.method, request.path))
        if required and required not in form:
            return web.json_response({"error": f"Missing {required} (it must be in the form body)"})

        route = self.routes.get((request.method, request.path))
        if route is None:
            return web.json_response(
                {"error": f"No fake route for {request.method} {request.path}"}, status=404
            )
        if callable(route):
            route = route(request)

        status, data = route
        return web.json_response(data, status=status)

    async def _stream(self, request: web.Request) -> web.StreamResponse:
        resp = web.StreamResponse(status=200)
        await resp.prepare(request)
        for banner in STREAM_BANNERS:
            await resp.write(json.dumps(banner).encode() + b"\n")
            # Heartbeats are blank lines.
            await resp.write(b"\n")
        await resp.write_eof()
        return resp

    async def __aenter__(self):
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", self._handle)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await site.start()
        port = self._runner.addresses[0][1]
        base = f"http://127.0.0.1:{port}"
        self.urls = {
            name: f"{base}/{name}" for name in ("api", "stream", "trends", "internetdb", "cvedb")
        }
        return self

    async def __aexit__(self, *args):
        await self._runner.cleanup()

    def last(self, path: str | None = None, method: str | None = None) -> dict:
        """The most recent request (to ``path``, with ``method``, if given)."""

        for req in reversed(self.requests):
            if (path is None or req["path"] == path) and (
                method is None or req["method"] == method
            ):
                return req
        raise AssertionError(f"No request was made to {path}")


@contextlib.asynccontextmanager
async def shodanSvc(test, apikey: str | None = "testkey"):
    """Yield (core, svc, fake) - a Cortex with slib.shodan added, pointed at a FakeShodan."""

    from shodansvc import ShodanSvc

    async with FakeShodan() as fake:
        conf = {"shodan:urls": fake.urls, "shodan:ratelimit": 0, "shodan:apikey": apikey}
        async with test.getTestCoreProxSvc(ShodanSvc, ssvc_conf=conf) as (core, prox, svc):
            yield core, svc, fake

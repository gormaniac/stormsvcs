"""Skip tests that need an engine (tshark, Suricata, Snort) when it isn't installed.

In the service's test image every engine is installed and ``SLIB_PCAP_REQUIRE=1`` is set, so
nothing skips there: a missing engine fails the tests instead.
"""

import os
import shutil
import unittest

import pytest

BINARIES = {
    "tshark": ("tshark",),
    "suricata": ("suricata",),
    "snort": ("snort", "snort2lua"),
}
"""The binaries each engine needs."""

REQUIRE = os.environ.get("SLIB_PCAP_REQUIRE") == "1"
"""Fail, don't skip, the tests that need a missing engine."""


def missing(*engines: str) -> list[str]:
    """The engines (of ``engines``) that aren't installed."""

    return [e for e in engines if not all(shutil.which(b) for b in BINARIES[e])]


def have(*engines: str) -> bool:
    """True if every engine is installed."""

    return not missing(*engines)


def needs(*engines: str):
    """Skip a test (function, method, or class) without the engines, unless they're required.

    Applies both a pytest mark and a unittest skip, SynTest's async wrappers drop pytest marks
    on methods.
    """

    gone = missing(*engines)
    skip = bool(gone) and not REQUIRE
    reason = f"{', '.join(gone)} isn't installed"

    def wrap(obj):
        return unittest.skipIf(skip, reason)(pytest.mark.skipif(skip, reason=reason)(obj))

    return wrap

# The shared StormLib++ pytest plugin: fails any test that uses a deprecated Synapse API (and
# the run, for deprecations logged outside of a test), and lets the fake abuse.ch server on
# localhost bypass any proxy. See stormlibpp/testing/__init__.py.
pytest_plugins = ["stormlibpp.testing"]

import pytest


@pytest.fixture(autouse=True)
def _collectAllowedDeprecations(request):
    """Collect the deprecations a test marked allow_synapse_deprecations logs.

    stormlibpp 1.1.0 counts them as logged outside of a test, which fails the run. Fixed
    upstream (it then collects them itself, and this does nothing); remove this once
    abusech requires a stormlibpp with the fix.
    """
    import stormlibpp.testing as s_testing

    if not s_testing._allowed(request) or s_testing._SYN_DEPRS.intest is not None:
        yield
        return
    s_testing._SYN_DEPRS.intest = set()
    try:
        yield
    finally:
        s_testing._SYN_DEPRS.intest = None

# The shared StormLib++ pytest plugin: fails any test that uses a deprecated Synapse API (and
# the run, for deprecations logged outside of a test), and lets the fake bgp.he.net server on
# localhost bypass any proxy. See stormlibpp/testing/__init__.py.
pytest_plugins = ["stormlibpp.testing"]

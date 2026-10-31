# The tests that need Snort fail instead of skipping, this image always has it.
export SLIB_SNORT_REQUIRE=1
exec uv run --no-sync --directory /opt/stormsvcs/snort \
    python3 -m pytest /opt/stormsvcs/snort/tests/

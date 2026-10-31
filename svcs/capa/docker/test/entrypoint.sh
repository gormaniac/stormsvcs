# The image's bundled rules (SYN_CAPASVC_CAPA_RULES) also run the tests in test_live.py.
exec uv run --no-sync --directory /opt/stormsvcs/capa \
    python3 -m pytest /opt/stormsvcs/capa/tests/

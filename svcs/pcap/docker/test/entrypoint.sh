# The tests that need an engine (tshark, Suricata, Snort) fail instead of skipping, this image
# always has them.
export SLIB_PCAP_REQUIRE=1
exec uv run --no-sync --directory /opt/stormsvcs/pcap \
    python3 -m pytest /opt/stormsvcs/pcap/tests/

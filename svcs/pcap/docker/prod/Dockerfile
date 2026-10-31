FROM ghcr.io/gormaniac/stormsvcs/base:latest

# Copy all the service files into a build dir.
COPY pyproject.toml /opt/stormsvcs/pcap/pyproject.toml
COPY uv.lock /opt/stormsvcs/pcap/uv.lock
COPY src/pcapsvc /opt/stormsvcs/pcap/src/pcapsvc
COPY README.md /opt/stormsvcs/pcap/README.md

# Use the upstream stormsvcs license since it's a symlink in the repo
RUN cp /opt/stormsvcs/LICENSE /opt/stormsvcs/pcap/LICENSE

# Install deps with uv
RUN uv sync --no-dev --locked --directory /opt/stormsvcs/pcap

# Move the entrypoint script and make it executable.
COPY docker/prod/entrypoint.sh /opt/stormsvcs/pcap/entrypoint.sh
RUN chmod +x /opt/stormsvcs/pcap/entrypoint.sh

# The things that actually run the service
ENTRYPOINT ["tini", "--", "/opt/stormsvcs/pcap/entrypoint.sh"]

HEALTHCHECK --start-period=10s --retries=1 --timeout=10s --interval=30s CMD \
    uv run --no-sync --directory /opt/stormsvcs/pcap \
    python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/

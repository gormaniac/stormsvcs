FROM ghcr.io/gormaniac/stormsvcs/base:latest

# Copy all the service files into a build dir.
COPY pyproject.toml /opt/stormsvcs/bgphe/pyproject.toml
COPY uv.lock /opt/stormsvcs/bgphe/uv.lock
COPY src/bgphesvc /opt/stormsvcs/bgphe/src/bgphesvc
COPY README.md /opt/stormsvcs/bgphe/README.md

# Use the upstream stormsvcs license since it's a symlink in the repo
RUN cp /opt/stormsvcs/LICENSE /opt/stormsvcs/bgphe/LICENSE

# Install deps with uv
RUN uv sync --no-dev --locked --directory /opt/stormsvcs/bgphe

# Move the entrypoint script and make it executable.
COPY docker/prod/entrypoint.sh /opt/stormsvcs/bgphe/entrypoint.sh
RUN chmod +x /opt/stormsvcs/bgphe/entrypoint.sh

# The things that actually run the service
ENTRYPOINT ["tini", "--", "/opt/stormsvcs/bgphe/entrypoint.sh"]

HEALTHCHECK --start-period=10s --retries=1 --timeout=10s --interval=30s CMD \
    uv run --no-sync --directory /opt/stormsvcs/bgphe \
    python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/

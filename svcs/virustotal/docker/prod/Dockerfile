FROM ghcr.io/gormaniac/stormsvcs/base:latest

# Copy all the service files into a build dir.
COPY pyproject.toml /opt/stormsvcs/virustotal/pyproject.toml
COPY uv.lock /opt/stormsvcs/virustotal/uv.lock
COPY src/vtsvc /opt/stormsvcs/virustotal/src/vtsvc
COPY README.md /opt/stormsvcs/virustotal/README.md

# Use the upstream stormsvcs license since it's a symlink in the repo
RUN cp /opt/stormsvcs/LICENSE /opt/stormsvcs/virustotal/LICENSE

# Install deps with uv
RUN uv sync --no-dev --locked --directory /opt/stormsvcs/virustotal

# Move the entrypoint script and make it executable.
COPY docker/prod/entrypoint.sh /opt/stormsvcs/virustotal/entrypoint.sh
RUN chmod +x /opt/stormsvcs/virustotal/entrypoint.sh

# The things that actually run the service
ENTRYPOINT ["tini", "--", "/opt/stormsvcs/virustotal/entrypoint.sh"]

HEALTHCHECK --start-period=10s --retries=1 --timeout=10s --interval=30s CMD \
    uv run --no-sync --directory /opt/stormsvcs/virustotal \
    python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/

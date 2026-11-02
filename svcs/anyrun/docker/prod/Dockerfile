FROM ghcr.io/gormaniac/stormsvcs/base:latest

# Copy all the service files into a build dir.
COPY pyproject.toml /opt/stormsvcs/anyrun/pyproject.toml
COPY uv.lock /opt/stormsvcs/anyrun/uv.lock
COPY src/anyrunsvc /opt/stormsvcs/anyrun/src/anyrunsvc
COPY README.md /opt/stormsvcs/anyrun/README.md

# Use the upstream stormsvcs license since it's a symlink in the repo
RUN cp /opt/stormsvcs/LICENSE /opt/stormsvcs/anyrun/LICENSE

# Install deps with uv
RUN uv sync --no-dev --locked --directory /opt/stormsvcs/anyrun

# Move the entrypoint script and make it executable.
COPY docker/prod/entrypoint.sh /opt/stormsvcs/anyrun/entrypoint.sh
RUN chmod +x /opt/stormsvcs/anyrun/entrypoint.sh

# The things that actually run the service
ENTRYPOINT ["tini", "--", "/opt/stormsvcs/anyrun/entrypoint.sh"]

HEALTHCHECK --start-period=10s --retries=1 --timeout=10s --interval=30s CMD \
    uv run --no-sync --directory /opt/stormsvcs/anyrun \
    python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/

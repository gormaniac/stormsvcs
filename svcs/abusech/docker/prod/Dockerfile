FROM ghcr.io/gormaniac/stormsvcs/base:latest

# Copy all the service files into a build dir.
COPY pyproject.toml /opt/stormsvcs/abusech/pyproject.toml
COPY uv.lock /opt/stormsvcs/abusech/uv.lock
COPY src/abusechsvc /opt/stormsvcs/abusech/src/abusechsvc
COPY README.md /opt/stormsvcs/abusech/README.md

# Use the upstream stormsvcs license since it's a symlink in the repo
RUN cp /opt/stormsvcs/LICENSE /opt/stormsvcs/abusech/LICENSE

# Install deps with uv
RUN uv sync --no-dev --locked --directory /opt/stormsvcs/abusech

# Move the entrypoint script and make it executable.
COPY docker/prod/entrypoint.sh /opt/stormsvcs/abusech/entrypoint.sh
RUN chmod +x /opt/stormsvcs/abusech/entrypoint.sh

# The things that actually run the service
ENTRYPOINT ["tini", "--", "/opt/stormsvcs/abusech/entrypoint.sh"]

HEALTHCHECK --start-period=10s --retries=1 --timeout=10s --interval=30s CMD \
    uv run --no-sync --directory /opt/stormsvcs/abusech \
    python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/

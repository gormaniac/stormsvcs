FROM ghcr.io/gormaniac/stormsvcs/base:latest

# Copy all the service files into a build dir.
COPY pyproject.toml /opt/stormsvcs/crtsh/pyproject.toml
COPY uv.lock /opt/stormsvcs/crtsh/uv.lock
COPY src/crtshsvc /opt/stormsvcs/crtsh/src/crtshsvc
COPY README.md /opt/stormsvcs/crtsh/README.md

# Use the upstream stormsvcs license since it's a symlink in the repo
RUN cp /opt/stormsvcs/LICENSE /opt/stormsvcs/crtsh/LICENSE

# Install deps with uv
RUN uv sync --no-dev --locked --directory /opt/stormsvcs/crtsh

# Move the entrypoint script and make it executable.
COPY docker/prod/entrypoint.sh /opt/stormsvcs/crtsh/entrypoint.sh
RUN chmod +x /opt/stormsvcs/crtsh/entrypoint.sh

# The things that actually run the service
ENTRYPOINT ["tini", "--", "/opt/stormsvcs/crtsh/entrypoint.sh"]

HEALTHCHECK --start-period=10s --retries=1 --timeout=10s --interval=30s CMD \
    uv run --no-sync --directory /opt/stormsvcs/crtsh \
    python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/

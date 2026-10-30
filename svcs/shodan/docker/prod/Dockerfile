FROM ghcr.io/gormaniac/stormsvcs/base:latest

# Copy all the service files into a build dir.
COPY pyproject.toml /opt/stormsvcs/shodan/pyproject.toml
COPY uv.lock /opt/stormsvcs/shodan/uv.lock
COPY src/shodansvc /opt/stormsvcs/shodan/src/shodansvc
COPY README.md /opt/stormsvcs/shodan/README.md

# Use the upstream stormsvcs license since it's a symlink in the repo
RUN cp /opt/stormsvcs/LICENSE /opt/stormsvcs/shodan/LICENSE

# Install deps with uv
RUN uv sync --no-dev --locked --directory /opt/stormsvcs/shodan

# Move the entrypoint script and make it executable.
COPY docker/prod/entrypoint.sh /opt/stormsvcs/shodan/entrypoint.sh
RUN chmod +x /opt/stormsvcs/shodan/entrypoint.sh

# The things that actually run the service
ENTRYPOINT ["tini", "--", "/opt/stormsvcs/shodan/entrypoint.sh"]

HEALTHCHECK --start-period=10s --retries=1 --timeout=10s --interval=30s CMD \
    python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/

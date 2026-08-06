FROM ghcr.io/gormaniac/stormsvcs/base:latest

# Copy all the service files into a build dir.
COPY pyproject.toml /opt/stormsvcs/ip_api/pyproject.toml
COPY uv.lock /opt/stormsvcs/ip_api/uv.lock
COPY src/ipapi /opt/stormsvcs/ip_api/src/ipapi
COPY README.md /opt/stormsvcs/ip_api/README.md

# Use the upstream stormsvcs license since it's a symlink in the repo
RUN cp /opt/stormsvcs/LICENSE /opt/stormsvcs/ip_api/LICENSE

# Install deps with uv
RUN uv sync --no-dev --locked --directory /opt/stormsvcs/ip_api 

# Move the entrypoint script and make it executable. 
COPY docker/prod/entrypoint.sh /opt/stormsvcs/ip_api/entrypoint.sh
RUN chmod +x /opt/stormsvcs/ip_api/entrypoint.sh

# The things that actually run the service
ENTRYPOINT ["tini", "--", "/opt/stormsvcs/ip_api/entrypoint.sh"]

HEALTHCHECK --start-period=10s --retries=1 --timeout=10s --interval=30s CMD \
    python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/

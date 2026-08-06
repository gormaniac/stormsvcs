FROM ghcr.io/gormaniac/stormsvcs/ip_api:latest

# Move tests into the image so they can be run in CI.
COPY tests /opt/stormsvcs/ip_api/tests

# Install any dev dependencies.
# Don't resync the production venv since it already exists in the service's prod image.
RUN uv sync --only-dev --locked --directory /opt/stormsvcs/ip_api

COPY docker/tests/entrypoint.sh /opt/stormsvcs/ip_api/entrypoint.sh
RUN chmod +x /opt/stormsvcs/ip_api/entrypoint.sh

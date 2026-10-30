FROM ghcr.io/gormaniac/stormsvcs/shodan:latest

# Move tests into the image so they can be run in CI.
COPY tests /opt/stormsvcs/shodan/tests

# Install any dev dependencies.
# Don't resync the production venv since it already exists in the service's prod image.
RUN uv sync --only-dev --locked --directory /opt/stormsvcs/shodan

COPY docker/test/entrypoint.sh /opt/stormsvcs/shodan/entrypoint.sh
RUN chmod +x /opt/stormsvcs/shodan/entrypoint.sh

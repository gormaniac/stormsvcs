FROM ghcr.io/gormaniac/stormsvcs/bgphe:latest

# Move tests into the image so they can be run in CI.
COPY tests /opt/stormsvcs/bgphe/tests

# Add the dev dependencies to the production venv at build time, so the test entrypoint
# can run with --no-sync. --only-dev would uninstall the service's own dependencies.
RUN uv sync --locked --directory /opt/stormsvcs/bgphe

COPY docker/test/entrypoint.sh /opt/stormsvcs/bgphe/entrypoint.sh
RUN chmod +x /opt/stormsvcs/bgphe/entrypoint.sh

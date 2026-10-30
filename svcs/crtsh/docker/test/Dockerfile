FROM ghcr.io/gormaniac/stormsvcs/crtsh:latest

# Move tests into the image so they can be run in CI.
COPY tests /opt/stormsvcs/crtsh/tests

# Add the dev dependencies to the production venv at build time, so the test entrypoint
# can run with --no-sync. --only-dev would uninstall the service's own dependencies.
RUN uv sync --locked --directory /opt/stormsvcs/crtsh

COPY docker/test/entrypoint.sh /opt/stormsvcs/crtsh/entrypoint.sh
RUN chmod +x /opt/stormsvcs/crtsh/entrypoint.sh

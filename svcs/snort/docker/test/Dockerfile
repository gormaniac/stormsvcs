# CI builds this on the image it just built (see the docker_tests input of _service.yml).
ARG BASE_IMAGE=ghcr.io/gormaniac/stormsvcs/snort:latest
FROM ${BASE_IMAGE}

# Move tests into the image so they can be run in CI.
COPY tests /opt/stormsvcs/snort/tests

# Add the dev dependencies to the production venv at build time, so the test entrypoint
# can run with --no-sync. --only-dev would uninstall the service's own dependencies.
RUN uv sync --locked --directory /opt/stormsvcs/snort

COPY docker/test/entrypoint.sh /opt/stormsvcs/snort/entrypoint.sh
RUN chmod +x /opt/stormsvcs/snort/entrypoint.sh

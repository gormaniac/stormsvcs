# CI passes the production image it just built (see _service.yml), so the tests run against it.
ARG BASE_IMAGE=ghcr.io/gormaniac/stormsvcs/capa:latest
FROM ${BASE_IMAGE}

# Move tests into the image so they can be run in CI.
COPY tests /opt/stormsvcs/capa/tests
# tests/test_rules.py checks the CAPA_VERSION the prod Dockerfile pins matches capa in uv.lock.
COPY docker/prod/Dockerfile /opt/stormsvcs/capa/docker/prod/Dockerfile

# Add the dev dependencies to the production venv at build time, so the test entrypoint
# can run with --no-sync. --only-dev would uninstall the service's own dependencies.
RUN uv sync --locked --directory /opt/stormsvcs/capa

COPY docker/test/entrypoint.sh /opt/stormsvcs/capa/entrypoint.sh
RUN chmod +x /opt/stormsvcs/capa/entrypoint.sh

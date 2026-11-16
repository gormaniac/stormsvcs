# The base image to build on; the default is the published one. Override it (--build-arg) to
# build against a base image that isn't published yet.
ARG BASE_IMAGE=ghcr.io/gormaniac/stormsvcs/base:latest
FROM ${BASE_IMAGE}

# Copy all the service files into a build dir.
COPY pyproject.toml /opt/stormsvcs/malpedia/pyproject.toml
COPY uv.lock /opt/stormsvcs/malpedia/uv.lock
COPY src/malpediasvc /opt/stormsvcs/malpedia/src/malpediasvc
COPY README.md /opt/stormsvcs/malpedia/README.md

# Use the upstream stormsvcs license since it's a symlink in the repo
RUN cp /opt/stormsvcs/LICENSE /opt/stormsvcs/malpedia/LICENSE

# Install deps with uv
RUN uv sync --no-dev --locked --directory /opt/stormsvcs/malpedia

# Move the entrypoint script and make it executable.
COPY docker/prod/entrypoint.sh /opt/stormsvcs/malpedia/entrypoint.sh
RUN chmod +x /opt/stormsvcs/malpedia/entrypoint.sh

# The things that actually run the service
ENTRYPOINT ["tini", "--", "/opt/stormsvcs/malpedia/entrypoint.sh"]

HEALTHCHECK --start-period=10s --retries=1 --timeout=10s --interval=30s CMD \
    uv run --no-sync --directory /opt/stormsvcs/malpedia \
    python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/

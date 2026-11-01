# Fetch the capa rules and FLIRT signatures that match the version of capa in uv.lock.
# The release tag and commits are pinned, tests/test_rules.py checks CAPA_VERSION matches.
FROM alpine:3.22 AS capa-data

ARG CAPA_VERSION=v10.0.0
ARG CAPA_COMMIT=85813ebc5b99ccdbe43147e46796d0bd6700f30a
ARG CAPA_RULES_COMMIT=805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5

RUN apk add --no-cache git

RUN git clone --quiet --depth 1 --branch "${CAPA_VERSION}" \
        https://github.com/mandiant/capa-rules /capa/rules && \
    test "$(git -C /capa/rules rev-parse HEAD)" = "${CAPA_RULES_COMMIT}" && \
    rm -rf /capa/rules/.git /capa/rules/.github

RUN git clone --quiet --depth 1 --branch "${CAPA_VERSION}" --filter=blob:none --sparse \
        https://github.com/mandiant/capa /tmp/capa && \
    test "$(git -C /tmp/capa rev-parse HEAD)" = "${CAPA_COMMIT}" && \
    git -C /tmp/capa sparse-checkout set sigs && \
    mv /tmp/capa/sigs /capa/sigs && \
    rm -rf /tmp/capa

FROM ghcr.io/gormaniac/stormsvcs/base:latest

# Copy all the service files into a build dir.
COPY pyproject.toml /opt/stormsvcs/capa/pyproject.toml
COPY uv.lock /opt/stormsvcs/capa/uv.lock
COPY src/capasvc /opt/stormsvcs/capa/src/capasvc
COPY README.md /opt/stormsvcs/capa/README.md

# Use the upstream stormsvcs license since it's a symlink in the repo
RUN cp /opt/stormsvcs/LICENSE /opt/stormsvcs/capa/LICENSE

# Install deps with uv
RUN uv sync --no-dev --locked --directory /opt/stormsvcs/capa

# The capa rules (Apache 2.0, see rules/LICENSE.txt) and FLIRT signatures for this capa version.
COPY --from=capa-data /capa/rules /opt/stormsvcs/capa/rules
COPY --from=capa-data /capa/sigs /opt/stormsvcs/capa/sigs
ENV SYN_CAPASVC_CAPA_RULES="/opt/stormsvcs/capa/rules"
ENV SYN_CAPASVC_CAPA_SIGS="/opt/stormsvcs/capa/sigs"

# Move the entrypoint script and make it executable.
COPY docker/prod/entrypoint.sh /opt/stormsvcs/capa/entrypoint.sh
RUN chmod +x /opt/stormsvcs/capa/entrypoint.sh

# The things that actually run the service
ENTRYPOINT ["tini", "--", "/opt/stormsvcs/capa/entrypoint.sh"]

HEALTHCHECK --start-period=10s --retries=1 --timeout=10s --interval=30s CMD \
    uv run --no-sync --directory /opt/stormsvcs/capa \
    python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/

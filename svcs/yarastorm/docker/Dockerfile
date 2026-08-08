FROM ghcr.io/gormaniac/stormsvcs/base:latest

COPY pyproject.toml /opt/stormsvcs/yarastorm/pyproject.toml
COPY uv.lock /opt/stormsvcs/yarastorm/uv.lock
COPY src/yarastorm /opt/stormsvcs/yarastorm/src/yarastorm
COPY README.md /opt/stormsvcs/yarastorm/README.md

RUN cp /opt/stormsvcs/LICENSE /opt/stormsvcs/yarastorm/LICENSE

RUN uv sync --no-dev --locked --directory /opt/stormsvcs/yarastorm

COPY docker/yarastorm/entrypoint.sh /opt/stormsvcs/yarastorm/entrypoint.sh
RUN chmod +x /opt/stormsvcs/yarastorm/entrypoint.sh

EXPOSE 4443
EXPOSE 27492

VOLUME /vertex/storage

ENTRYPOINT ["tini", "--", "/opt/stormsvcs/yarastorm/entrypoint.sh"]

HEALTHCHECK --start-period=10s --retries=1 --timeout=10s --interval=30s CMD \
    uv run --directory /opt/stormsvcs/yarastorm \
    python -m synapse.tools.healthcheck -c cell:///vertex/storage/

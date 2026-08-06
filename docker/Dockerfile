FROM vertexproject/vtx-base-image:py311

# Bring in uv since everything uses it for building and running the services
COPY --from=ghcr.io/astral-sh/uv:0.12.1 /uv /uvx /bin/

# Move LICENSE so every downstream image has it.
COPY README.md /opt/stormsvcs/README.md
COPY LICENSE /opt/stormsvcs/LICENSE

# Make sure all services are logging at the same level. 
ENV SYN_LOG_LEVEL="INFO"

# Every service should expose the default Telepath and HTTPS ports
EXPOSE 4443
EXPOSE 27492

# Update and upgrade the system packages so downstream builds don't have to do it themselves.
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean && \
    apt-get purge -y && \
    rm -rf /var/lib/apt/lists/*

# Make sure the volume persists. The service's data lives here.
# Uses the upstream name for consistency with Synapse.
VOLUME /vertex/storage

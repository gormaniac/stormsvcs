# Snort 3 isn't packaged for Debian, so it's built from source in its own stage and only the
# install (plus its runtime libraries) is copied into the service's image.
FROM ghcr.io/gormaniac/stormsvcs/base:latest AS snort-build

ARG LIBDAQ_VERSION=3.0.28
ARG SNORT_VERSION=3.12.4.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake pkg-config autoconf automake libtool flex libfl-dev bison \
        libdumbnet-dev libhwloc-dev libluajit-5.1-dev libpcap-dev libpcre2-dev libssl-dev \
        zlib1g-dev liblzma-dev libunwind-dev uuid-dev && \
    rm -rf /var/lib/apt/lists/*

ADD https://github.com/snort3/libdaq/archive/refs/tags/v${LIBDAQ_VERSION}.tar.gz /build/libdaq.tar.gz
ADD https://github.com/snort3/snort3/archive/refs/tags/${SNORT_VERSION}.tar.gz /build/snort3.tar.gz

WORKDIR /build
RUN mkdir libdaq && tar -xzf libdaq.tar.gz -C libdaq --strip-components=1 && \
    cd libdaq && ./bootstrap && ./configure --prefix=/opt/snort && \
    make -j"$(nproc)" && make install
RUN mkdir snort3 && tar -xzf snort3.tar.gz -C snort3 --strip-components=1 && \
    cd snort3 && \
    PKG_CONFIG_PATH=/opt/snort/lib/pkgconfig ./configure_cmake.sh --prefix=/opt/snort \
        --with-daq-includes=/opt/snort/include --with-daq-libraries=/opt/snort/lib \
        --disable-docs --disable-gdb && \
    cd build && make -j"$(nproc)" && make install
# Only keep what the service runs: snort, snort2lua, the DAQ modules, and the default configs.
RUN cd /opt/snort && \
    find bin -type f ! -name snort ! -name snort2lua -delete && \
    rm -rf include share lib/*.a lib/*.la lib/pkgconfig && \
    find bin lib -type f \( -name snort -o -name snort2lua -o -name "*.so*" \) -exec strip --strip-unneeded {} + && \
    LD_LIBRARY_PATH=/opt/snort/lib /opt/snort/bin/snort -V


FROM ghcr.io/gormaniac/stormsvcs/base:latest

# Snort's runtime libraries.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libdumbnet1 libhwloc15 libluajit-5.1-2 libnuma1 libpcap0.8 libpcre2-8-0 libssl3 \
        libunwind8 libuuid1 liblzma5 zlib1g && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=snort-build /opt/snort /opt/snort
ENV PATH="/opt/snort/bin:${PATH}"
ENV LD_LIBRARY_PATH="/opt/snort/lib"
RUN snort -V

# Copy all the service files into a build dir.
COPY pyproject.toml /opt/stormsvcs/snort/pyproject.toml
COPY uv.lock /opt/stormsvcs/snort/uv.lock
COPY src/snortsvc /opt/stormsvcs/snort/src/snortsvc
COPY README.md /opt/stormsvcs/snort/README.md

# Use the upstream stormsvcs license since it's a symlink in the repo
RUN cp /opt/stormsvcs/LICENSE /opt/stormsvcs/snort/LICENSE

# Install deps with uv
RUN uv sync --no-dev --locked --directory /opt/stormsvcs/snort

# Move the entrypoint script and make it executable.
COPY docker/prod/entrypoint.sh /opt/stormsvcs/snort/entrypoint.sh
RUN chmod +x /opt/stormsvcs/snort/entrypoint.sh

# The things that actually run the service
ENTRYPOINT ["tini", "--", "/opt/stormsvcs/snort/entrypoint.sh"]

HEALTHCHECK --start-period=10s --retries=1 --timeout=10s --interval=30s CMD \
    uv run --no-sync --directory /opt/stormsvcs/snort \
    python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/

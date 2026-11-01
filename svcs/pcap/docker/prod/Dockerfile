# syntax=docker/dockerfile:1.7
#
# The slib.pcap service image. Every engine is built from source in its own stage (so CI can
# cache each one separately) and only its install is copied into the service's image:
#
#   tshark-build    Wireshark's tshark, without Lua or plugins (TLS key log decryption, gaps).
#   snort-build     Snort 3 and libdaq (Snort rules). Skip it with --build-arg SNORT=no.
#   suricata-build  Suricata 8 (protocol analysis and Suricata rules).
#
# Source tarballs are fetched by BuildKit in the *-src stages. To build offline, or from a
# mirror, override a stage with a local directory holding the same file name, ex.
#   docker buildx build --build-context wireshark-src=./mirror/wireshark ...

ARG BASE_IMAGE=ghcr.io/gormaniac/stormsvcs/base:latest
ARG RUST_IMAGE=rust:1.88-slim-bookworm
ARG SNORT=yes

ARG WIRESHARK_VERSION=4.6.9
ARG WIRESHARK_SHA256=d062d416a1ab3a49975aafe3a671c882dde0562ccd71b078808ceb59d465fc0f
ARG SURICATA_VERSION=8.0.8
ARG SURICATA_SHA256=bb56bbaeb4da81b4c90e61148f93b789ea924412207388bc9cba0a7ac6a24a8f
ARG LIBDAQ_VERSION=3.0.28
ARG LIBDAQ_SHA256=a72bc8882abdcfaf475b18d547b5a08785d574005584ce258e533d247bc62771
ARG SNORT_VERSION=3.12.4.0
ARG SNORT_SHA256=5bab33f703ca09b74bc2de72d16d8be59c67ebb98dbd45e50c30989b5cdd510f


# ---- Sources ----

FROM scratch AS wireshark-src
ARG WIRESHARK_VERSION
ARG WIRESHARK_SHA256
ADD --checksum=sha256:${WIRESHARK_SHA256} \
    https://www.wireshark.org/download/src/all-versions/wireshark-${WIRESHARK_VERSION}.tar.xz \
    /wireshark.tar.xz

FROM scratch AS suricata-src
ARG SURICATA_VERSION
ARG SURICATA_SHA256
ADD --checksum=sha256:${SURICATA_SHA256} \
    https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz \
    /suricata.tar.gz

FROM scratch AS libdaq-src
ARG LIBDAQ_VERSION
ARG LIBDAQ_SHA256
ADD --checksum=sha256:${LIBDAQ_SHA256} \
    https://github.com/snort3/libdaq/archive/refs/tags/v${LIBDAQ_VERSION}.tar.gz /libdaq.tar.gz

FROM scratch AS snort3-src
ARG SNORT_VERSION
ARG SNORT_SHA256
ADD --checksum=sha256:${SNORT_SHA256} \
    https://github.com/snort3/snort3/archive/refs/tags/${SNORT_VERSION}.tar.gz /snort3.tar.gz


# ---- tshark ----

FROM ${BASE_IMAGE} AS tshark-build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build pkg-config flex bison perl python3 xz-utils \
        libglib2.0-dev libgcrypt20-dev libc-ares-dev libpcap-dev libpcre2-dev zlib1g-dev \
        libnghttp2-dev libbrotli-dev libzstd-dev liblz4-dev libsnappy-dev libxml2-dev && \
    rm -rf /var/lib/apt/lists/*

COPY --from=wireshark-src /wireshark.tar.xz /build/wireshark.tar.xz
WORKDIR /build
# Only tshark, and no Lua (no scripts can run in it) or plugins: less code parsing untrusted
# captures. TLS key log decryption only needs libgcrypt.
RUN mkdir wireshark && tar -xJf wireshark.tar.xz -C wireshark --strip-components=1 && \
    cmake -S wireshark -B wireshark/build -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/opt/wireshark -DCMAKE_INSTALL_RPATH=/opt/wireshark/lib \
        -DBUILD_wireshark=OFF -DBUILD_stratoshark=OFF -DBUILD_logray=OFF -DBUILD_tshark=ON \
        -DBUILD_dumpcap=OFF -DBUILD_rawshark=OFF -DBUILD_sharkd=OFF -DBUILD_editcap=OFF \
        -DBUILD_mergecap=OFF -DBUILD_reordercap=OFF -DBUILD_text2pcap=OFF -DBUILD_capinfos=OFF \
        -DBUILD_captype=OFF -DBUILD_randpkt=OFF -DBUILD_dftest=OFF -DBUILD_androiddump=OFF \
        -DBUILD_sshdump=OFF -DBUILD_ciscodump=OFF -DBUILD_dpauxmon=OFF -DBUILD_randpktdump=OFF \
        -DBUILD_wifidump=OFF -DBUILD_udpdump=OFF -DBUILD_sdjournal=OFF -DBUILD_etwdump=OFF \
        -DBUILD_falcodump=OFF -DBUILD_strato=OFF -DBUILD_mmdbresolve=OFF \
        -DENABLE_LUA=OFF -DENABLE_PLUGINS=OFF -DENABLE_SMI=OFF -DENABLE_KERBEROS=OFF \
        -DENABLE_GNUTLS=OFF -DENABLE_MINIZIP=OFF -DENABLE_SBC=OFF -DENABLE_SPANDSP=OFF \
        -DENABLE_BCG729=OFF -DENABLE_AMRNB=OFF -DENABLE_ILBC=OFF -DENABLE_OPUS=OFF \
        -DENABLE_SINSP=OFF -DENABLE_CAP=OFF -DUSE_qt6=OFF && \
    cmake --build wireshark/build -j"$(nproc)" && \
    cmake --install wireshark/build && \
    rm -rf /opt/wireshark/share/man /opt/wireshark/share/doc /opt/wireshark/include && \
    find /opt/wireshark/bin /opt/wireshark/lib -type f \( -name tshark -o -name "*.so*" \) \
        -exec strip --strip-unneeded {} + && \
    /opt/wireshark/bin/tshark --version | head -1


# ---- Snort 3 ----

FROM ${BASE_IMAGE} AS snort-build-yes
ARG LIBDAQ_VERSION
ARG SNORT_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake pkg-config autoconf automake libtool flex libfl-dev bison \
        libdumbnet-dev libhwloc-dev libluajit-5.1-dev libpcap-dev libpcre2-dev libssl-dev \
        zlib1g-dev liblzma-dev libunwind-dev uuid-dev && \
    rm -rf /var/lib/apt/lists/*

COPY --from=libdaq-src /libdaq.tar.gz /build/libdaq.tar.gz
COPY --from=snort3-src /snort3.tar.gz /build/snort3.tar.gz
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
    rm -rf include share/doc lib/*.a lib/*.la lib/pkgconfig && \
    find bin lib -type f \( -name snort -o -name snort2lua -o -name "*.so*" \) -exec strip --strip-unneeded {} + && \
    LD_LIBRARY_PATH=/opt/snort/lib /opt/snort/bin/snort -V

# SNORT=no: an empty /opt/snort, the service then runs without the Snort engine.
FROM ${BASE_IMAGE} AS snort-build-no
RUN mkdir -p /opt/snort

FROM snort-build-${SNORT} AS snort-build


# ---- Suricata 8 ----

FROM ${RUST_IMAGE} AS rust

FROM ${BASE_IMAGE} AS suricata-build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf automake libtool pkg-config python3 \
        libpcap-dev libpcre2-dev libyaml-dev libjansson-dev libcap-ng-dev libmagic-dev \
        liblz4-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

# Suricata 8 needs a newer Rust than Debian 12 ships. Release tarballs vendor every crate, so
# the build needs no network.
COPY --from=rust /usr/local/cargo /usr/local/cargo
COPY --from=rust /usr/local/rustup /usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo RUSTUP_HOME=/usr/local/rustup PATH=/usr/local/cargo/bin:${PATH}

COPY --from=suricata-src /suricata.tar.gz /build/suricata.tar.gz
WORKDIR /build
RUN mkdir suricata && tar -xzf suricata.tar.gz -C suricata --strip-components=1 && \
    cd suricata && \
    ./configure --prefix=/opt/suricata --sysconfdir=/opt/suricata/etc \
        --localstatedir=/var --disable-gccmarch-native --disable-suricata-update \
        --disable-shared && \
    make -j"$(nproc)" && make install && make install-conf && \
    rm -rf /opt/suricata/include /opt/suricata/share/doc /opt/suricata/share/man \
        /opt/suricata/lib/*.a /opt/suricata/lib/*.la /opt/suricata/lib/pkgconfig && \
    strip --strip-unneeded /opt/suricata/bin/suricata && \
    /opt/suricata/bin/suricata --build-info | head -3


# ---- The service ----

FROM ${BASE_IMAGE}

# The engines' runtime libraries.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libglib2.0-0 libgcrypt20 libc-ares2 libpcap0.8 libpcre2-8-0 zlib1g libnghttp2-14 \
        libbrotli1 libzstd1 liblz4-1 libsnappy1v5 libxml2 \
        libdumbnet1 libhwloc15 libluajit-5.1-2 libnuma1 libssl3 libunwind8 libuuid1 liblzma5 \
        libyaml-0-2 libjansson4 libcap-ng0 libmagic1 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=tshark-build /opt/wireshark /opt/wireshark
COPY --from=snort-build /opt/snort /opt/snort
COPY --from=suricata-build /opt/suricata /opt/suricata
ENV PATH="/opt/wireshark/bin:/opt/snort/bin:/opt/suricata/bin:${PATH}" \
    LD_LIBRARY_PATH="/opt/snort/lib"
RUN tshark --version | head -1 && suricata -V && { [ ! -x /opt/snort/bin/snort ] || snort -V; }

# The engines run sandboxed as this unprivileged user (see pcapsvc.sandbox), never as root.
# Suricata installs its config files 0600, the engine's user has to read them.
RUN useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin \
        --uid 2000 slib-pcap-engine && \
    chmod -R a+rX /opt/suricata/etc /opt/snort /opt/wireshark

# Copy all the service files into a build dir.
COPY pyproject.toml /opt/stormsvcs/pcap/pyproject.toml
COPY uv.lock /opt/stormsvcs/pcap/uv.lock
COPY src/pcapsvc /opt/stormsvcs/pcap/src/pcapsvc
COPY README.md /opt/stormsvcs/pcap/README.md

# Use the upstream stormsvcs license since it's a symlink in the repo
RUN cp /opt/stormsvcs/LICENSE /opt/stormsvcs/pcap/LICENSE

# Install deps with uv
RUN uv sync --no-dev --locked --directory /opt/stormsvcs/pcap

# Move the entrypoint script and make it executable.
COPY docker/prod/entrypoint.sh /opt/stormsvcs/pcap/entrypoint.sh
RUN chmod +x /opt/stormsvcs/pcap/entrypoint.sh

# The things that actually run the service
ENTRYPOINT ["tini", "--", "/opt/stormsvcs/pcap/entrypoint.sh"]

HEALTHCHECK --start-period=10s --retries=1 --timeout=10s --interval=30s CMD \
    uv run --no-sync --directory /opt/stormsvcs/pcap \
    python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/

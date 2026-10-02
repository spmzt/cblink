# cblink on FreeBSD: libcblink, its header, cblink-gen, share/cblink and
# the man pages, on the notoolchain base image.
#
#	buildah build -f Containerfile --network=host -t cblink .
#
# The first stage builds the tree, runs the test suite (a failing test
# fails the build; set CBLINK_TESTS=no to skip it) and installs the
# runtime files; the second has only those and libcbor.

FROM ghcr.io/spmzt/freebsd-base:latest AS build
ARG CBLINK_TESTS=yes
RUN pkg install -y FreeBSD-clang FreeBSD-lld FreeBSD-toolchain \
        FreeBSD-clibs-dev FreeBSD-openssl-dev FreeBSD-atf FreeBSD-atf-dev \
        FreeBSD-kyua FreeBSD-libcasper-dev FreeBSD-utilities-dev libcbor && \
    pkg clean -ay
COPY . /usr/src/cblink
WORKDIR /usr/src/cblink
ENV MAKEOBJDIRPREFIX=/usr/obj
RUN if [ "${CBLINK_TESTS}" = yes ]; then \
        make -j "$(sysctl -n hw.ncpu)" && \
        make install DESTDIR=/test && \
        cd /test/usr/local/tests/cblink && \
        env LD_LIBRARY_PATH=/test/usr/local/lib kyua test -k Kyuafile || \
        { kyua report --verbose --results-filter broken,failed; exit 1; }; \
    fi
RUN make -j "$(sysctl -n hw.ncpu)" WITHOUT_TESTS=yes && \
    make install WITHOUT_TESTS=yes DESTDIR=/dist

FROM ghcr.io/spmzt/freebsd-base:latest
LABEL org.opencontainers.image.source="https://github.com/spmzt/cblink" \
    org.opencontainers.image.title="cblink" \
    org.opencontainers.image.description="Netlink-style messaging over CBOR for FreeBSD userland: libcblink and cblink-gen" \
    org.opencontainers.image.licenses="BSD-2-Clause" \
    org.opencontainers.image.authors="spmzt"
RUN pkg install -y libcbor && \
    pkg clean -ay && \
    rm -rf /var/db/pkg/repos/*
COPY --from=build /dist/usr/local/ /usr/local/
RUN ldconfig -m /usr/local/lib && \
    cblink-gen -V

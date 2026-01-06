FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# ---- deps ----
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    libssl-dev \
    autoconf \
    automake \
    libtool \
    pkg-config \
    zlib1g-dev \
    uuid-dev \
    libpam0g-dev \
    git \
    python3 \
    python3-pip \
    unzip \
    && pip3 install matplotlib \
    && rm -rf /var/lib/apt/lists/*

# ---- env ----
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV LIBRARY_PATH=/usr/local/lib
ENV C_INCLUDE_PATH=/usr/local/include

# ---- sources ----
WORKDIR /src
COPY . .

# Make sure no host build artifacts break container builds
RUN find /src -name CMakeCache.txt -delete && \
    find /src -name CMakeFiles -type d -prune -exec rm -rf {} + && \
    find /src -name build -type d -prune -exec rm -rf {} + && \
    find /src -name "*.a" -delete && \
    find /src -name "*.so" -delete && \
    find /src -name "*.so.*" -delete && \
    find /src -name "*.la" -delete || true

# ============================================================
# Build + install CECIES (exports symbols, installs to /usr/local)
# ============================================================
WORKDIR /src/liboqs/lib/cecies
RUN rm -rf build CMakeCache.txt CMakeFiles && \
    mkdir build && cd build && \
    cmake \
      -DBUILD_SHARED_LIBS=ON \
      -Dcecies_BUILD_DLL=ON \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    nm -D /usr/local/lib/libcecies.so | grep cecies_curve25519_encrypt && \
    nm -D /usr/local/lib/libcecies.so | grep cecies_free

# ============================================================
# Build + install liboqs (shared, installs to /usr/local)
# ============================================================
WORKDIR /src/liboqs
RUN rm -rf build CMakeCache.txt CMakeFiles && \
    mkdir build && cd build && \
    cmake -GNinja \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_USE_AVX2_INSTRUCTIONS=OFF \
      -DOQS_ENABLE_TESTS=OFF \
      -DOQS_ENABLE_KAT_TESTS=OFF \
      -DOQS_ENABLE_BENCHMARKS=OFF \
      -DOQS_ENABLE_EXAMPLES=OFF \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      .. && \
    ninja && \
    ninja install && \
    ldconfig && \
    ldconfig && \
    ls -l /usr/local/lib/liboqs.so*

# Fix libcecies.so overwrite by liboqs install
RUN cp /src/liboqs/lib/cecies/build/libcecies.so /usr/local/lib/libcecies.so && ldconfig && nm -D /usr/local/lib/libcecies.so | grep cecies_curve25519_encrypt

# ============================================================
# Build OpenSSH CLIENT (force link with cecies)
# ============================================================
RUN cp -r /src /src-client
WORKDIR /src-client
RUN rm -rf config.h config.log config.status .depend && \
    autoreconf && \
    LDFLAGS="-L/usr/local/lib" LIBS="/usr/local/lib/libcecies.so" \
    ./configure \
      --prefix=/opt/customsshClient \
      --with-ssl-dir=/usr \
      --with-liboqs-dir=/usr/local && \
    make -j$(nproc) V=1 && \
    make install

# ============================================================
# Build OpenSSH SERVER (force link with cecies)
# ============================================================
RUN cp -r /src /src-server
WORKDIR /src-server
RUN rm -rf config.h config.log config.status .depend && \
    autoreconf && \
    LDFLAGS="-L/usr/local/lib" LIBS="/usr/local/lib/libcecies.so" \
    ./configure \
      --with-pam \
      --prefix=/opt/customsshServer \
      --with-ssl-dir=/usr \
      --with-liboqs-dir=/usr/local && \
    make -j$(nproc) V=1 && \
    make install

# ---- users for runtime ----
RUN useradd -m -s /bin/bash dwq && \
    useradd -r -s /usr/sbin/nologin -d /var/empty -c "sshd privilege separation" sshd && \
    mkdir -p /var/empty && chmod 755 /var/empty && chown root:root /var/empty && \
    mkdir -p /home/dwq/.ssh && chown -R dwq:dwq /home/dwq

EXPOSE 2222

WORKDIR /home/dwq

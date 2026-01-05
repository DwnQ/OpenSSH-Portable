FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    gcc \
    ninja-build \
    libssl-dev \
    python3-pytest \
    python3-pytest-xdist \
    unzip \
    xsltproc \
    doxygen \
    graphviz \
    python3-yaml \
    valgrind \
    libpam0g-dev \
    git \
    autoconf \
    automake \
    libtool \
    pkg-config \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /src

# Copy source code
COPY . .

# Build liboqs
WORKDIR /src/liboqs
RUN rm -rf build && mkdir build && cd build && \
    cmake -GNinja \
    -DOQS_BUILD_SHA3=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_USE_AVX2_INSTRUCTIONS=OFF \
    -DOQS_ENABLE_TESTS=OFF \
    -DOQS_ENABLE_KAT_TESTS=OFF \
    -DOQS_ENABLE_BENCHMARKS=OFF \
    -DOQS_ENABLE_EXAMPLES=OFF \
    -DOQS_BUILD_SHAKE=ON \
    .. && \
    ninja && \
    ninja install

# Build OpenSSH Client
WORKDIR /src/build-client
RUN ../configure --prefix=/opt/customsshClient --with-ssl-dir=/usr/local --with-liboqs-dir=/usr/local && \
    make -j$(nproc) && \
    make install

# Build OpenSSH Server
WORKDIR /src/build-server
RUN ../configure --with-pam --prefix=/opt/customsshServer --with-ssl-dir=/usr/local --with-liboqs-dir=/usr/local && \
    make -j$(nproc) && \
    make install

# Setup user for testing
RUN useradd -m -s /bin/bash dwq && \
    mkdir -p /home/dwq/.ssh && \
    chown -R dwq:dwq /home/dwq

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose SSH port
EXPOSE 2222

WORKDIR /home/dwq
ENTRYPOINT ["/entrypoint.sh"]

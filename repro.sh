#!/bin/bash
set -e
cp /src/liboqs/lib/cecies/build/libcecies.so /usr/local/lib/
ldconfig
autoreconf
# Force partial link to test
LDFLAGS="-L/usr/local/lib" LIBS="-lcecies" ./configure --prefix=/opt/customsshClient --with-ssl-dir=/usr --with-liboqs-dir=/usr/local
make sshd

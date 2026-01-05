SCRIPT_DIR=$PWD
MAKEFILE_=${SCRIPT_DIR}/integration_files/Makefile

cd ..
LIBOQS_DIR=$PWD
CECIES_DIR=${LIBOQS_DIR}/lib/cecies

echo -e "Where should I install OQS-OpenSSL (absolute path):\n"
read OPENSSL_DIR

# ---------------------------------- OPENSSL --------------------------------- #

sudo apt install cmake gcc libtool libssl-dev make ninja-build git

git clone --single-branch --branch OQS-OpenSSL_1_1_1-stable-snapshot-2021-03 https://github.com/open-quantum-safe/openssl.git ${OPENSSL_DIR}

cd ${OPENSSL_DIR}
./Configure no-shared linux-x86_64 -lm

# ---------------------------------- LIBOQS ---------------------------------- #

cd ${LIBOQS_DIR}/build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=${OPENSSL_DIR}/oqs ..
ninja
ninja install

# ----------------------- Integrating attacked version ----------------------- #
cd ${SCRIPT_DIR}

# Alterar Makefile
rm ${OPENSSL_DIR}/Makefile
cp ${MAKEFILE_} ${OPENSSL_DIR}

# Importar CECIES
cd ${CECIES_DIR}
bash build.sh
cp ./build/cecies/bin/release/{libcecies.so,libcecies.so.4,libcecies.so.4.0.0} ${OPENSSL_DIR}/oqs/lib

# ----------------------------- Compiling OpenSSL ---------------------------- #

cd ${OPENSSL_DIR}
make
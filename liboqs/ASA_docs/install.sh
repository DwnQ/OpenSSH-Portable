sudo apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz uuid-dev

cd ..
git submodule update --init --recursive
mkdir build
cd build

cmake -GNinja ..
ninja

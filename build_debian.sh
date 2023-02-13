#!/bin/bash
# ------------------------------------------------------------------------------
# requirements
# ------------------------------------------------------------------------------
which cmake g++ make || {
    echo "Failed to find required build packages. Please install with:   sudo apt-get install cmake make g++"
    exit 1
}
# This is necessary in scenarios where the URL of the remote for a given submodule has changed.
git submodule sync || {
    echo "FAILED TO SYNC IS2 LIB"
    exit 1
}
git submodule update -f --init || {
    echo "FAILED TO UPDATE TO LATEST IS2 LIB"
    exit 1
}
# ------------------------------------------------------------------------------
# To build...
# ------------------------------------------------------------------------------
mkdir -p build
pushd build && \
    cmake ../ \
    -DBUILD_SYMBOLS=ON \
    -DBUILD_TCMALLOC=ON \
    -DBUILD_TESTS=ON \
    -DBUILD_APPS=ON \
    -DBUILD_UTILS=ON \
    -DCMAKE_INSTALL_PREFIX=/usr && \
    make -j$(nproc) && \
    umask 0022 && chmod -R a+rX . && \
    make package && \
    make test && \
    popd && \
exit $?


#!/bin/bash

set -xeE

DPCP_DIR=${WORKSPACE}/jenkins/default/_dpcp-last
DPCP_REPO="git@github.com:Mellanox/dpcp.git"
DPCP_BRANCH="master"

mkdir -p "${DPCP_DIR}"
cd "${DPCP_DIR}"

timeout -s SIGKILL 30s git clone -b "${DPCP_BRANCH}" "${DPCP_REPO}" .
DPCP_COMMIT=$(git describe --tags "$(git rev-list --tags --max-count=1)")
if [ -z "$DPCP_COMMIT" ]; then
    DPCP_COMMIT=$(git rev-parse --short HEAD)
fi

git checkout "${DPCP_COMMIT}"

# Apply chaos patches if in chaos mode
if [ "${do_chaos}" == "true" ]; then
    cd "${WORKSPACE}"
    for patch in .ci/chaos/patches/*.diff; do
        [ -f "$patch" ] && git apply "$patch"
    done
    # Commit the patches so tests that check git diff can see the changes
    git add -A
    git -c user.name="Chaos CI" -c user.email="chaos@ci" commit -s -m "Apply chaos patches for chaos testing"
fi

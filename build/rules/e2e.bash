#!/usr/bin/env bash
set -e

BIN=@@BIN@@
TEST_TARGET=@@TEST_TARGET@@
EXTRA_ARGS=@@EXTRA_ARGS@@

PWD=$(pwd)
"$BIN" -e2e.binary "${PWD}/$TEST_TARGET" ${EXTRA_ARGS[@]}
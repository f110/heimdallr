#!/usr/bin/env bash
set -e
if [ "@@DEBUG@@" = "true" ]; then
set -x
fi

BIN=@@BIN@@
GENERATED_DIR=@@GENERATED_DIR@@
OUTPUT_DIR=@@OUTPUT_DIR@@
ARGS=@@ARGS@@

SRC_PACKAGE_NAMES=@@SRC_PACKAGE_NAMES@@
SRC_DIRS=@@SRC_DIRS@@
MODULE=@@MODULE@@

RUNFILE_DIR=$(pwd)
CONTROLLER_GEN="$RUNFILE_DIR/$BIN"

rm -rf src
mkdir -p src

if [ -n "$(ls vendor 2> /dev/null)" ]; then
  for f in vendor/*; do
    ln -sf $RUNFILE_DIR/$f $RUNFILE_DIR/src
  done
fi

mkdir -p src/$MODULE
for i in "${SRC_DIRS[@]}"; do
  ln -sf $RUNFILE_DIR/$i src/$MODULE/$i
done

unset GO111MODULE
export GOPATH=$RUNFILE_DIR
"$CONTROLLER_GEN" "${ARGS[@]}"

cd "$BUILD_WORKSPACE_DIRECTORY"
cp -rT $RUNFILE_DIR/$GENERATED_DIR "$OUTPUT_DIR"
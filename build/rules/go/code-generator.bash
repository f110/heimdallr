#!/usr/bin/env bash
set -e
if [ "@@DEBUG@@" = "true" ]; then
set -x
fi

BIN=@@BIN@@
GAZELLE_PATH=@@GAZELLE@@
ARGS=@@ARGS@@
NO_GAZELLE=@@NO_GAZELLE@@

TARGET_DIRS=@@TARGET_DIRS@@
FILENAME=@@FILENAME@@
GENERATED_DIRS=@@GENERATED_DIRS@@
SRC_PACKAGE_DIRS=@@SRC_PACKAGE_DIRS@@
SRC_DIRS=@@SRC_DIRS@@
GO_ROOT=@@GO_ROOT@@
RUNFILE_DIR=$(pwd)

GEN="$RUNFILE_DIR/$BIN"
GAZELLE="$RUNFILE_DIR/$GAZELLE_PATH"

rm -rf src
mkdir -p src
mkdir -p $RUNFILE_DIR/src/golang.org/x

for f in $GO_ROOT/src/vendor/golang.org/x/*; do
  ln -sf $RUNFILE_DIR/$f $RUNFILE_DIR/src/golang.org/x
done

if [ -n "$(ls vendor 2> /dev/null)" ]; then
  for f in vendor/*; do
    if [ "$f" = "vendor/golang.org" ]; then
      continue
    fi

    ln -sf $RUNFILE_DIR/$f $RUNFILE_DIR/src
  done
fi

for i in "${!SRC_PACKAGE_DIRS[@]}"; do
  mkdir -p src/$(dirname ${SRC_PACKAGE_DIRS[$i]})
  ln -sf $RUNFILE_DIR/${SRC_DIRS[$i]} src/${SRC_PACKAGE_DIRS[$i]}
done

export GOROOT=$RUNFILE_DIR/$GO_ROOT
export GOPATH=$RUNFILE_DIR
unset GO111MODULE
"$GEN" "--output-base=$RUNFILE_DIR" "${ARGS[@]}"

cd "$BUILD_WORKSPACE_DIRECTORY"

if [ -n "$FILENAME" ]; then
  for i in "${!GENERATED_DIRS[@]}"; do
    mkdir -p "${TARGET_DIRS[$i]}"
    cp "$RUNFILE_DIR/${GENERATED_DIRS[$i]}/$FILENAME" "${TARGET_DIRS[$i]}"
  done
else
  mkdir -p $(dirname "${TARGET_DIRS[0]}")
  cp -rT $RUNFILE_DIR/${GENERATED_DIRS[0]} ${TARGET_DIRS[0]}

  if [ "$NO_GAZELLE" = "false" ]; then
    "$GAZELLE" update "${TARGET_DIRS[0]}"
  fi
fi


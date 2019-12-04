#!/usr/bin/env bash

GO=@@GO@@
GAZELLE_PATH=@@GAZELLE@@
DIR=@@DIR@@
ARGS=@@ARGS@@

RUNFILES=$(pwd)
GO_RUNTIME="$RUNFILES"/"$GO"
GAZELLE="$RUNFILES"/"$GAZELLE_PATH"

cd "$BUILD_WORKSPACE_DIRECTORY"/"$DIR"
"$GO_RUNTIME" mod tidy
"$GO_RUNTIME" mod vendor
find vendor -name BUILD.bazel -delete
"$GAZELLE" update "${ARGS[@]}"
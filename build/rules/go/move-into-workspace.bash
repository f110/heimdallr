#!/usr/bin/env bash

FROM=@@FROM@@
TO=@@TO@@

cd "$BUILD_WORKSPACE_DIRECTORY"
cp -f "$FROM" "$TO"
#!/usr/bin/env bash
set -e

BIN=@@BIN@@
VERSION=@@VERSION@@
REPO=@@REPO@@
BRANCH=@@BRANCH@@
ASSETS=@@ASSETS@@

$BIN --version $VERSION --repo $REPO --from $BRANCH "${ASSETS[@]}"
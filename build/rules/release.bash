#!/usr/bin/env bash
set -e

BIN=@@BIN@@
VERSION=@@VERSION@@
REPO=@@REPO@@
BRANCH=@@BRANCH@@
ASSETS=@@ASSETS@@
BODY=@@BODY@@

$BIN github --version $VERSION --repo $REPO --from $BRANCH --body "$BODY" "${ASSETS[@]}"
#!/usr/bin/env bash
set -e

BIN=@@BIN@@
VERSION=@@VERSION@@
REPO=@@REPO@@
BRANCH=@@BRANCH@@
ASSETS=@@ASSETS@@
BODY=@@BODY@@
RC=@@RC@@

$BIN github --version $VERSION --repo $REPO --from $BRANCH $RC --body "$BODY" "${ASSETS[@]}"
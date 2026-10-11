#!/usr/bin/env bash
set -e

BIN=@@BIN@@
VERSION=@@VERSION@@
REPO=@@REPO@@
BRANCH=@@BRANCH@@
ASSETS=@@ASSETS@@
BODY=@@BODY@@

GITHUB_APP_ARG=""
if [ -n "$GITHUB_PRIVATE_KEY" ] && [ -n "$GITHUB_APP_ID" ] && [ -n "$GITHUB_INSTALLATION_ID" ]; then
    GITHUB_APP_ARG="--github-app-id $GITHUB_APP_ID --github-installation-id $GITHUB_INSTALLATION_ID --github-private-key $GITHUB_PRIVATE_KEY"
fi

$BIN github --version $VERSION --repo $REPO --from $BRANCH --body "$BODY" $GITHUB_APP_ARG "${ASSETS[@]}"

#!/usr/bin/env bash
set -e

NAME="code-generator"
VERSION="v0.17.3"

TARGETDIR="$(pwd)/third_party/${NAME}"

if [ -d "${TARGETDIR}" ]; then
  rm -rf "${TARGETDIR}"
fi

TMPDIR=$(mktemp -d)
cd "${TMPDIR}"
git clone --depth 1 "https://github.com/kubernetes/${NAME}.git" -b "$VERSION"
find "${NAME}" -name "*_test.go" -delete
find "${NAME}" -name "testdata" -type d | xargs rm -rf
find "${NAME}" -name "_examples" -type d | xargs rm -rf
cd "${NAME}"

find . -name ".*" -maxdepth 1 | grep -v "^.$" | xargs rm -rf {} +
cat <<EOS > BUILD.bazel
load("//build/rules/go:vendor.bzl", "go_vendor")

# gazelle:prefix k8s.io/${NAME}

go_vendor(name = "vendor")
EOS

mv "${TMPDIR}/${NAME}" "${TARGETDIR}"
bazel run //third_party/${NAME}:vendor
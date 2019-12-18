#!/usr/bin/env bash
set -e

VERSION="v0.2.4"

mkdir -p third_party
cd third_party
if [ -d controller-tools ]; then
  rm -rf controller-tools
fi
git clone --depth 1 https://github.com/kubernetes-sigs/controller-tools.git -b "$VERSION"
find controller-tools -name "*_test.go" -delete
find controller-tools -name "testdata" -type d | xargs rm -rf
cd controller-tools

find . -name ".*" -maxdepth 1 | grep -v "^.$" | xargs rm -rf {} +
cat <<EOS > BUILD.bazel
load("//build/rules/go:vendor.bzl", "go_vendor")

# gazelle:prefix sigs.k8s.io/controller-tools

go_vendor(name = "vendor")
EOS

bazel run //third_party/controller-tools:vendor
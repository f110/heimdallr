#!/usr/bin/env bash
set -e

VERSION="v2.2.0"

mkdir -p third_party
cd third_party
if [ -d kubebuilder ]; then
  rm -rf kubebuilder
fi
git clone --depth 1 https://github.com/kubernetes-sigs/kubebuilder.git -b "$VERSION"
find kubebuilder -name "*_test.go" -delete
find kubebuilder -name "testdata" -type d | xargs rm -rf
cd kubebuilder

find . -name ".*" -maxdepth 1 | grep -v "^.$" | xargs rm -rf {} +
rm -rf WORKSPACE BUILD.bazel test script docs designs build
cat <<EOS > BUILD.bazel
load("//build/rules/go:vendor.bzl", "go_vendor")

# gazelle:prefix sigs.k8s.io/kubebuilder

go_vendor(name = "vendor")

alias(name = "kubebuilder", actual = "//third_party/kubebuilder/cmd:cmd")
EOS

bazel run //third_party/kubebuilder:vendor
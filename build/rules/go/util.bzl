load("@io_bazel_rules_go//go:def.bzl", "go_binary")

def multiplatform_go_binary(name_prefix, **kwargs):
    if not "platforms" in kwargs:
        fail("platforms is mandatory")

    platforms = kwargs.pop("platforms")
    for platform in platforms:
        os, arch = platform.split("_")

        go_binary(
            name = "%s_%s" % (name_prefix, platform),
            goarch = arch,
            goos = os,
            **kwargs
        )

def go_binary_for_container(**kwargs):
    for platform in ["linux_amd64", "linux_arm64"]:
        os, arch = platform.split("_")

        go_binary(
            name = platform,
            goarch = arch,
            goos = os,
            **kwargs
        )

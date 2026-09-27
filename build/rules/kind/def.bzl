load("//build/rules/kind:assets.bzl", "KIND_ASSETS")

BUILD_FILE = """filegroup(name = "file", srcs = [\"{file}\"], visibility = [\"//visibility:public\"])
sh_binary(name = "bin", srcs = [":file"], visibility = ["//visibility:public"])
"""

def _kind_binary_impl(ctx):
    os = ""
    if ctx.os.name == "linux":
        os = "linux"
    elif ctx.os.name == "mac os x":
        os = "darwin"
    else:
        fail("%s is not supported" % ctx.os.name)

    arch = ""
    if ctx.os.arch in ("amd64", "x86_64"):
        arch = "amd64"
    elif ctx.os.arch in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        fail("%s is not supported" % ctx.os.arch)

    if not ctx.attr.version in KIND_ASSETS:
        fail("%s is not supported version" % ctx.attr.version)

    assets = KIND_ASSETS[ctx.attr.version]
    if not os in assets or not arch in assets[os]:
        fail("%s/%s is not supported in %s" % (os, arch, ctx.attr.version))

    download_path = ctx.path("kind")
    url, checksum = assets[os][arch]
    ctx.download(
        url = url,
        output = download_path,
        sha256 = checksum,
        executable = True,
    )

    ctx.file("WORKSPACE", "workspace(name = \"{name}\")".format(name = ctx.name))
    ctx.file("BUILD", BUILD_FILE.format(file = "kind"))

kind_binary = repository_rule(
    implementation = _kind_binary_impl,
    attrs = {
        "version": attr.string(),
    },
)

load("//build/rules/kind:assets.bzl", "KIND_ASSETS")

def _kind_binary_impl(ctx):
    os = ""
    if ctx.os.name == "linux":
        os = "linux"
    elif ctx.os.name == "mac os x":
        os = "darwin"
    else:
        fail("%s is not supported" % ctx.os.name)

    if not ctx.attr.version in KIND_ASSETS:
        fail("%s is not supported version" % ctx.attr.version)

    download_path = ctx.path("kind")
    url, checksum = KIND_ASSETS[ctx.attr.version][os]
    ctx.download(
        url = url,
        output = download_path,
        sha256 = checksum,
        executable = True,
    )

    ctx.file("WORKSPACE", "workspace(name = \"{name}\")".format(name = ctx.name))
    ctx.file("BUILD", "filegroup(name = \"file\", srcs = [\"{file}\"], visibility = [\"//visibility:public\"])".format(file = "kind"))

kind_binary = repository_rule(
    implementation = _kind_binary_impl,
    attrs = {
        "version": attr.string(),
    },
)

load("//build/rules/kustomize:assets.bzl", "KUSTOMIZE_ASSETS")
load("@bazel_skylib//lib:paths.bzl", "paths")

def _kustomize_binary_impl(ctx):
    os = ""
    if ctx.os.name == "linux":
        os = "linux"
    elif ctx.os.name == "mac_os_x":
        os = "darwin"
    else:
        fail("%s is not supported" % ctx.os.name)

    if not ctx.attr.version in KUSTOMIZE_ASSETS:
        fail("%s is not supported version" % ctx.attr.version)

    url, checksum = KUSTOMIZE_ASSETS[ctx.attr.version][os]
    ctx.download_and_extract(
        url = url,
        sha256 = checksum,
        type = "tar.gz",
    )

    ctx.file("BUILD.bazel", "sh_binary(name = \"bin\", srcs = [\"kustomize\"], visibility = [\"//visibility:public\"])")

kustomize_binary = repository_rule(
    implementation = _kustomize_binary_impl,
    attrs = {
        "version": attr.string(),
    },
)

def _kustomization_impl(ctx):
    out = ctx.actions.declare_file("kustomize.%s.yaml" % ctx.label.name)
    args = ctx.actions.args()
    args.add("build")
    args.add(paths.dirname(ctx.file.src.path))
    args.add("--output=%s" % out.path)
    args.add("--load_restrictor=none")

    ctx.actions.run(
        executable = ctx.executable._kustomize,
        inputs = depset(direct = [ctx.file.src], transitive = [depset(ctx.files.resources)]),
        outputs = [out],
        arguments = [args],
    )

    return DefaultInfo(
        files = depset([out]),
    )

kustomization = rule(
    implementation = _kustomization_impl,
    attrs = {
        "src": attr.label(allow_single_file = True),
        "resources": attr.label_list(allow_files = True),
        "_kustomize": attr.label(
            executable = True,
            cfg = "host",
            default = "@kustomize//:bin",
        ),
    }
)
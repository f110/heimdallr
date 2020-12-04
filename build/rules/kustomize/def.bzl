load("//build/rules/kustomize:assets.bzl", "KUSTOMIZE_ASSETS")
load("@bazel_skylib//lib:paths.bzl", "paths")

Kustomization = provider()

def _kustomize_binary_impl(ctx):
    os = ""
    if ctx.os.name == "linux":
        os = "linux"
    elif ctx.os.name == "mac os x":
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

    srcs = []
    for x in ctx.attr.resources:
        if Kustomization in x:
            srcs.extend(x[Kustomization].srcs)
            continue
        srcs.extend(x.files.to_list())

    ctx.actions.run(
        executable = ctx.executable._kustomize,
        inputs = depset(direct = [ctx.file.src], transitive = [depset(srcs)]),
        outputs = [out],
        arguments = [args],
    )

    data_runfiles = ctx.runfiles(files = [out])
    return [
        DefaultInfo(
            files = depset([out]),
            data_runfiles = data_runfiles,
        ),
        Kustomization(
            name = ctx.label.name,
            generated_manifest = out,
            srcs = [ctx.file.src] + depset(ctx.files.resources).to_list(),
        ),
    ]

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
    },
)

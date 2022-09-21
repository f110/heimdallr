load("//build/rules/kustomize:assets.bzl", "KUSTOMIZE_ASSETS")
load("@bazel_skylib//lib:paths.bzl", "paths")
load("//build/rules/private/util:semver.bzl", "semver")

Kustomization = provider()

def _kustomize_binary_impl(ctx):
    os = ""
    if ctx.os.name == "linux":
        os = "linux"
    elif ctx.os.name == "mac os x":
        os = "darwin"
    else:
        fail("%s is not supported" % ctx.os.name)
    arch = ctx.execute(["uname", "-m"]).stdout.strip()

    # On Linux, uname returns x86_64 as CPU architecture.
    if arch == "x86_64":
        arch = "amd64"

    if not ctx.attr.version in KUSTOMIZE_ASSETS:
        fail("%s is not supported version" % ctx.attr.version)

    url, checksum = KUSTOMIZE_ASSETS[ctx.attr.version][os][arch]
    ctx.download_and_extract(
        url = url,
        sha256 = checksum,
        type = "tar.gz",
    )

    ctx.template(
        "BUILD.bazel",
        Label("//build/rules/kustomize:BUILD.kustomize.bazel"),
        executable = False,
        substitutions = {
            "{version}": ctx.attr.version,
        },
    )

kustomize_binary = repository_rule(
    implementation = _kustomize_binary_impl,
    attrs = {
        "version": attr.string(),
    },
)

KustomizeToolchain = provider(
    fields = {
        "version": "The version string of kustomize",
        "bin": "",
    },
)

def _kustomize_toolchain(ctx):
    return [KustomizeToolchain(
        version = ctx.attr.version,
        bin = ctx.executable.bin,
    )]

kustomize_toolchain = rule(
    implementation = _kustomize_toolchain,
    attrs = {
        "version": attr.string(
            mandatory = True,
        ),
        "bin": attr.label(
            executable = True,
            cfg = "host",
        ),
    },
)

def _kustomization_impl(ctx):
    toolchain = ctx.attr._kustomize[KustomizeToolchain]

    out = ctx.actions.declare_file("kustomize.%s.yaml" % ctx.label.name)
    args = ctx.actions.args()
    args.add("build")
    args.add(paths.dirname(ctx.file.src.path))
    args.add("--output=%s" % out.path)
    v = semver.parse(toolchain.version)
    if semver.gte(v, semver.parse("v4.0.1")):
        args.add("--load-restrictor=LoadRestrictionsNone")
    else:
        args.add("--load_restrictor=none")

    srcs = []
    for x in ctx.attr.resources:
        if Kustomization in x:
            srcs.extend(x[Kustomization].srcs)
            continue
        srcs.extend(x.files.to_list())

    ctx.actions.run(
        executable = toolchain.bin,
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
            srcs = [ctx.file.src] + srcs,
        ),
    ]

kustomization = rule(
    implementation = _kustomization_impl,
    attrs = {
        "src": attr.label(allow_single_file = True),
        "resources": attr.label_list(allow_files = True),
        "_kustomize": attr.label(
            default = "@kustomize//:toolchain",
        ),
    },
)

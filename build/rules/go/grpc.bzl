load("@bazel_skylib//lib:shell.bzl", "shell")
load("@io_bazel_rules_go//proto:compiler.bzl", "GoProtoCompiler")
load("@io_bazel_rules_go//proto:def.bzl", "get_imports")
load("@io_bazel_rules_go//go:def.bzl", "go_context")
load("@io_bazel_rules_go//go/private:rules/rule.bzl", "go_rule")
load("@io_bazel_rules_go_compat//:compat.bzl", "get_proto")

def _vendor_grpc_source_impl(ctx):
    generated = ctx.attr.src[OutputGroupInfo].go_generated_srcs.to_list()
    files = [v.path for v in generated]
    substitutions = {
        "@@FROM@@": shell.array_literal(files),
        "@@TO@@": shell.quote(ctx.attr.dir),
    }
    out = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.expand_template(
        template = ctx.file._template,
        output = out,
        substitutions = substitutions,
        is_executable = True,
    )
    runfiles = ctx.runfiles(files = generated)
    return [
        DefaultInfo(
            runfiles = runfiles,
            executable = out,
        ),
    ]

_vendor_grpc_source = rule(
    implementation = _vendor_grpc_source_impl,
    executable = True,
    attrs = {
        "dir": attr.string(),
        "src": attr.label(),
        "_template": attr.label(
            default = "//build/rules/go:move-into-workspace.bash",
            allow_single_file = True,
        ),
    },
)

def vendor_grpc_source(name, **kwargs):
    if not "dir" in kwargs:
        dir = native.package_name()
        kwargs["dir"] = dir

    _vendor_grpc_source(name = name, **kwargs)

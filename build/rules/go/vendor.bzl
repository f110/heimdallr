load("@io_bazel_rules_go//go:def.bzl", "go_context", "go_rule")
load("@bazel_skylib//lib:shell.bzl", "shell")

def _go_vendor(ctx):
    go = go_context(ctx)
    out = ctx.actions.declare_file(ctx.label.name + ".sh")
    substitutions = {
        "@@GO@@": shell.quote(go.go.path),
        "@@GAZELLE@@": shell.quote(ctx.executable._gazelle.short_path),
    }
    ctx.actions.expand_template(
        template = ctx.file._template,
        output = out,
        substitutions = substitutions,
        is_executable = True,
    )
    runfiles = ctx.runfiles(files = [go.go, ctx.executable._gazelle])
    return [
        DefaultInfo(
            runfiles = runfiles,
            executable = out,
        ),
    ]

go_vendor = go_rule(
    implementation = _go_vendor,
    executable = True,
    attrs = {
        "_template": attr.label(
            default = "//build/rules/go:vendor.bash",
            allow_single_file = True,
        ),
        "_gazelle": attr.label(
            default = "@bazel_gazelle//cmd/gazelle",
            executable = True,
            cfg = "host",
        ),
    },
)

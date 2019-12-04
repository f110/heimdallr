load("@bazel_skylib//lib:shell.bzl", "shell")

def _controller_gen_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".sh")
    substitutions = {
        "@@BIN@@": shell.quote(ctx.executable._bin.short_path),
        "@@DIR@@": shell.quote(ctx.attr.dir),
        "@@ARGS@@": shell.array_literal(ctx.attr.extra_args),
    }
    ctx.actions.expand_template(
        template = ctx.file._template,
        output = out,
        substitutions = substitutions,
        is_executable = True,
    )
    runfiles = ctx.runfiles(files = [ctx.executable._bin])
    return [
        DefaultInfo(
            runfiles = runfiles,
            executable = out,
        ),
    ]

_controller_gen = rule(
    implementation = _controller_gen_impl,
    executable = True,
    attrs = {
        "dir": attr.string(),
        "extra_args": attr.string_list(),
        "_template": attr.label(
            default = "//build/rules/go:controller-gen.bash",
            allow_single_file = True,
        ),
        "_bin": attr.label(
            default = "//third_party/controller-tools/cmd/controller-gen",
            executable = True,
            cfg = "host",
        ),
    },
)

def controller_gen(name, **kwargs):
    if not "dir" in kwargs:
        dir = native.package_name()
        kwargs["dir"] = dir

    _controller_gen(name = name, **kwargs)
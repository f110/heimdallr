load("@bazel_skylib//lib:shell.bzl", "shell")

def _vendor_kubeproto_impl(ctx):
    generated = ctx.attr.src[DefaultInfo].files.to_list()
    substitutions = {
        "@@FROM@@": shell.array_literal([v.path for v in generated]),
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

_vendor_kubeproto = rule(
    implementation = _vendor_kubeproto_impl,
    executable = True,
    attrs = {
        "dir": attr.string(),
        "src": attr.label(),
        "_template": attr.label(
            default = "//build/rules:copy.bash",
            allow_single_file = True,
        ),
    },
)

def vendor_kubeproto(name, **kwargs):
    if not "dir" in kwargs:
        dir = native.package_name()
        kwargs["dir"] = dir

    _vendor_kubeproto(name = name, **kwargs)
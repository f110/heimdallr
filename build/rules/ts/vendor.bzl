load("@aspect_rules_js//js:providers.bzl", "JsInfo")
load("@bazel_skylib//lib:shell.bzl", "shell")

def _vendor_ts_impl(ctx):
    info = ctx.attr.src[JsInfo]
    generated = [
        v
        for v in info.transitive_types.to_list() + info.transitive_sources.to_list()
        if v.owner.workspace_name == ""
    ]

    out = ctx.actions.declare_file(ctx.label.name + ".sh")
    substitutions = {
        "@@FROM@@": shell.array_literal([v.path for v in generated]),
        "@@TO@@": shell.quote(ctx.attr.dir),
    }
    ctx.actions.expand_template(
        template = ctx.file._template,
        output = out,
        substitutions = substitutions,
        is_executable = True,
    )
    runfiles = ctx.runfiles(files = generated)
    return [DefaultInfo(runfiles = runfiles, executable = out)]

_vendor_ts = rule(
    implementation = _vendor_ts_impl,
    executable = True,
    attrs = {
        "dir": attr.string(),
        "src": attr.label(providers = [JsInfo]),
        "_template": attr.label(
            default = "//build/rules/ts:move-into-workspace.bash",
            allow_single_file = True,
        ),
    },
)

def vendor_ts(name, **kwargs):
    if not "dir" in kwargs:
        kwargs["dir"] = native.package_name()

    _vendor_ts(name = name, **kwargs)

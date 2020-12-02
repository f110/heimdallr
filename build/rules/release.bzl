load("@bazel_skylib//lib:shell.bzl", "shell")

def _github_release_impl(ctx):
    rc = ""
    if "rc" in ctx.attr.version:
        rc = "--release-candidate"
    files = []
    assets = ["--attach=%s" % x.short_path for x in ctx.files.assets]
    substitutions = {
        "@@BIN@@": shell.quote(ctx.executable._bin.short_path),
        "@@VERSION@@": shell.quote(ctx.attr.version),
        "@@REPO@@": shell.quote(ctx.attr.repository),
        "@@BRANCH@@": shell.quote(ctx.attr.branch),
        "@@ASSETS@@": shell.array_literal(assets),
        "@@RC@@": rc,
    }
    if ctx.attr.body:
        substitutions["@@BODY@@"] = shell.quote(ctx.file.body.short_path)
        files.append(ctx.file.body)

    out = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.expand_template(
        template = ctx.file._template,
        output = out,
        substitutions = substitutions,
        is_executable = True,
    )

    files.append(ctx.executable._bin)
    files.extend(ctx.files.assets)
    runfiles = ctx.runfiles(files = files)
    return [
        DefaultInfo(
            executable = out,
            runfiles = runfiles,
        ),
    ]

github_release = rule(
    implementation = _github_release_impl,
    executable = True,
    attrs = {
        "version": attr.string(),
        "repository": attr.string(),
        "branch": attr.string(),
        "assets": attr.label_list(allow_files = True),
        "body": attr.label(allow_single_file = True),
        "_bin": attr.label(
            executable = True,
            cfg = "host",
            default = "//cmd/release",
        ),
        "_template": attr.label(default = "//build/rules:release.bash", allow_single_file = True),
    },
)

def _template_string_impl(ctx):
    tmpl_file = ctx.actions.declare_file("%s_tmpl" % ctx.label.name)
    ctx.actions.write(tmpl_file, ctx.attr.template)

    data = {}
    for k in ctx.attr.data.keys():
        data["{" + k + "}"] = ctx.attr.data[k]

    out = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.expand_template(
        template = tmpl_file,
        output = out,
        substitutions = data,
        is_executable = False,
    )

    return [DefaultInfo(files = depset([out]))]

template_string = rule(
    implementation = _template_string_impl,
    attrs = {
        "data": attr.string_dict(),
        "template": attr.string(),
    },
)

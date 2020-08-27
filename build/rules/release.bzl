load("@bazel_skylib//lib:shell.bzl", "shell")

def _github_release_impl(ctx):
    assets = ["--attach=%s" % x.short_path for x in ctx.files.assets]
    substitutions = {
        "@@BIN@@": shell.quote(ctx.executable._bin.short_path),
        "@@VERSION@@": shell.quote(ctx.attr.version),
        "@@REPO@@": shell.quote(ctx.attr.repository),
        "@@BRANCH@@": shell.quote(ctx.attr.branch),
        "@@ASSETS@@": shell.array_literal(assets),
    }
    out = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.expand_template(
        template = ctx.file._template,
        output = out,
        substitutions = substitutions,
        is_executable = True,
    )

    runfiles = ctx.runfiles(files = [ctx.executable._bin] + ctx.files.assets)
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
        "_bin": attr.label(
            executable = True,
            cfg = "host",
            default = "//script/github-release",
        ),
        "_template": attr.label(default = "//build/rules:release.bash", allow_single_file = True),
    },
)

load("@bazel_skylib//lib:shell.bzl", "shell")

def _heimdallr_e2e_test_impl(ctx):
    args = []
    if ctx.attr.verbose:
        args.append("-test.v")
        args.append("-e2e.verbose")

    kicker = ctx.actions.declare_file("%s_e2e.sh" % ctx.label.name)
    substitutions = {
        "@@BIN@@": shell.quote(ctx.executable.scenario.short_path),
        "@@TEST_TARGET@@": shell.quote(ctx.executable.proxy.short_path),
        "@@EXTRA_ARGS@@": shell.array_literal(args),
    }
    ctx.actions.expand_template(
        template = ctx.file._template,
        output = kicker,
        substitutions = substitutions,
        is_executable = True,
    )

    runfiles = ctx.runfiles(files = [kicker, ctx.executable.proxy, ctx.executable.scenario])
    return [
        DefaultInfo(
            executable = kicker,
            runfiles = runfiles,
        ),
    ]

heimdallr_e2e_test = rule(
    implementation = _heimdallr_e2e_test_impl,
    test = True,
    attrs = {
        "scenario": attr.label(
            default = Label("//e2e/scenario:scenario_test"),
            executable = True,
            cfg = "target",
        ),
        "proxy": attr.label(
            default = Label("//cmd/heimdallr-proxy"),
            executable = True,
            cfg = "target",
        ),
        "verbose": attr.bool(),
        "_template": attr.label(
            default = "//build/rules:e2e.bash",
            allow_single_file = True,
        ),
    },
)

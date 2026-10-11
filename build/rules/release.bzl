load("@bazel_skylib//lib:shell.bzl", "shell")

ReleaseAssetsInfo = provider(
    doc = "The release assets that are prepared by prepare_release_assets.",
    fields = {
        "files": "list of File: the prepared assets",
    },
)

def _prepare_release_assets_impl(ctx):
    outs = [ctx.actions.declare_file("%s/%s" % (ctx.label.name, x.basename)) for x in ctx.files.srcs]
    inputs = list(ctx.files.srcs)
    args = ctx.actions.args()
    args.add("prepare")
    args.add("--output-dir=%s" % outs[0].dirname)
    args.add_all(ctx.files.srcs, format_each = "--asset=%s")
    if ctx.file.ca_cert and ctx.file.ca_key:
        args.add("--ca-cert=%s" % ctx.file.ca_cert.path)
        args.add("--ca-key=%s" % ctx.file.ca_key.path)
        inputs.extend([ctx.file.ca_cert, ctx.file.ca_key])
    args.add_all(ctx.files.webhook_cert_assets, format_each = "--inject-webhook-cert=%s")
    ctx.actions.run(
        executable = ctx.executable._bin,
        inputs = inputs,
        outputs = outs,
        arguments = [args],
        mnemonic = "PrepareReleaseAssets",
    )

    return [
        DefaultInfo(
            files = depset(outs),
            data_runfiles = ctx.runfiles(files = outs),
        ),
        ReleaseAssetsInfo(files = outs),
    ]

prepare_release_assets = rule(
    implementation = _prepare_release_assets_impl,
    doc = "Prepares the release assets. github_release uploads the outputs, and the e2e test uses them to verify the assets in the same form as the release.",
    attrs = {
        "srcs": attr.label_list(allow_files = True, mandatory = True, allow_empty = False),
        "ca_cert": attr.label(allow_single_file = True),
        "ca_key": attr.label(allow_single_file = True),
        "webhook_cert_assets": attr.label_list(allow_files = True),
        "_bin": attr.label(
            executable = True,
            cfg = "host",
            default = "//cmd/release",
        ),
    },
)

def _github_release_impl(ctx):
    assets = ctx.attr.assets[ReleaseAssetsInfo].files
    files = []
    substitutions = {
        "@@BIN@@": shell.quote(ctx.executable._bin.short_path),
        "@@VERSION@@": shell.quote(ctx.attr.version),
        "@@REPO@@": shell.quote(ctx.attr.repository),
        "@@BRANCH@@": shell.quote(ctx.attr.branch),
        "@@ASSETS@@": shell.array_literal(["--attach=%s" % x.short_path for x in assets]),
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
    files.extend(assets)
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
        "assets": attr.label(providers = [ReleaseAssetsInfo], mandatory = True),
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

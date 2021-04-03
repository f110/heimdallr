def _cleanup_manifest_impl(ctx):
    out = ctx.actions.declare_file("%s.yaml" % ctx.label.name)
    args = ctx.actions.args()
    args.add("manifest-cleaner")
    args.add("--input=%s" % ctx.file.src.path)
    args.add("--output=%s" % out.path)
    args.add("--version=%s" % ctx.attr.version)
    ctx.actions.run(
        executable = ctx.executable._bin,
        inputs = depset(direct = [ctx.file.src]),
        outputs = [out],
        arguments = [args],
    )

    return [
        DefaultInfo(
            files = depset([out]),
            data_runfiles = ctx.runfiles(files = [out]),
        ),
    ]

cleanup_manifest = rule(
    implementation = _cleanup_manifest_impl,
    attrs = {
        "src": attr.label(allow_single_file = True),
        "version": attr.string(),
        "_bin": attr.label(
            executable = True,
            cfg = "host",
            default = "//cmd/release",
        ),
    },
)

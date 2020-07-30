def _finalize_manifest_impl(ctx):
    out = ctx.actions.declare_file("%s.yaml" % ctx.label.name)
    args = ctx.actions.args()
    args.add("--in=%s" % ctx.file.src.path)
    args.add("--out=%s" % out.path)
    ctx.actions.run(
        executable = ctx.executable._bin,
        inputs = depset(direct = [ctx.file.src]),
        outputs = [out],
        arguments = [args],
    )

    return [DefaultInfo(files = depset([out]))]

finalize_manifest = rule(
    implementation = _finalize_manifest_impl,
    attrs = {
        "src": attr.label(allow_single_file = True),
        "_bin": attr.label(
            executable = True,
            cfg = "host",
            default = "//operator/hack/manifest-finalizer:manifest-finalizer",
        ),
    },
)

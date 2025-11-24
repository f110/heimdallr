load("//build/rules/kind:def.bzl", "kind_binary")

def _kind_impl(module_ctx):
    for mod in module_ctx.modules:
        for tools in mod.tags.download:
            if tools.version:
                kind_binary(name = "kind", version = tools.version)

kind_extension = module_extension(
    tag_classes = {
        "download": tag_class(attrs = {
            "version": attr.string(),
        }),
    },
    implementation = _kind_impl,
)

load("//build/rules/kustomize:def.bzl", "kustomize_binary")

def _kustomize_impl(module_ctx):
    for mod in module_ctx.modules:
        for tools in mod.tags.download:
            if tools.version:
                kustomize_binary(name = "kustomize", version = tools.version)

kustomize_extension = module_extension(
    tag_classes = {
        "download": tag_class(attrs = {
            "version": attr.string(),
        }),
    },
    implementation = _kustomize_impl,
)

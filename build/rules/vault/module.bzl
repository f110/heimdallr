load("//build/rules/vault:def.bzl", "vault_binary")

def _vault_impl(module_ctx):
    for mod in module_ctx.modules:
        for tools in mod.tags.download:
            if tools.latest:
                vault_binary(name = "vault_latest", version = tools.latest)
            if tools.oldapi:
                vault_binary(name = "vault_110", version = tools.oldapi)

vault_extension = module_extension(
    tag_classes = {
        "download": tag_class(attrs = {
            "latest": attr.string(),
            "oldapi": attr.string(),
        }),
    },
    implementation = _vault_impl,
)

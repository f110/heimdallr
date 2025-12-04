load("//build/rules/kustomize:assets.bzl", "KUSTOMIZE_ASSETS")
load("//build/rules/assets:assets.bzl", "multi_platform_download_and_extract")

def _kustomize_binary_impl(ctx):
    if not ctx.attr.version in KUSTOMIZE_ASSETS:
        fail("%s is not supported version" % ctx.attr.version)
    multi_platform_download_and_extract(ctx, KUSTOMIZE_ASSETS[ctx.attr.version], Label("//build/rules/kustomize:BUILD.kustomize.bazel"))

kustomize_binary = repository_rule(
    implementation = _kustomize_binary_impl,
    attrs = {
        "version": attr.string(),
    },
)

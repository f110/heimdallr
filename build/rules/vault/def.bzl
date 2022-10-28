VAULT_ASSETS = {
    "1.12.0": {
        "linux": {
            "amd64": (
                "https://releases.hashicorp.com/vault/1.12.0/vault_1.12.0_linux_amd64.zip",
                "56d140b34bec780cd458672e39b3bb0ea9e4b7e4fb9ea7e15de31e1562130d7a",
            ),
            "arm64": (
                "https://releases.hashicorp.com/vault/1.12.0/vault_1.12.0_linux_arm64.zip",
                "8178d5d3354934eb53cceeb212e4ec4bf2a60b2ae48150a7157898288c20519e",
            ),
        },
        "darwin": {
            "amd64": (
                "https://releases.hashicorp.com/vault/1.12.0/vault_1.12.0_darwin_amd64.zip",
                "1042cdf626ed05734332dcbd566548f4622f4320b1c1d7aa8ec89f9fa6d32cc4",
            ),
            "arm64": (
                "https://releases.hashicorp.com/vault/1.12.0/vault_1.12.0_darwin_arm64.zip",
                "efc6506b909c4ccc055302ff1e782b2e214b3bcbb740ce46e8cd78d0046a38f9",
            ),
        },
    },
    "1.6.3": {
        "linux": {
            "amd64": (
                "https://releases.hashicorp.com/vault/1.6.3/vault_1.6.3_linux_amd64.zip",
                "844adaf632391be41f945143de7dccfa9b39c52a72e8e22a5d6bad9c32404c46",
            ),
        },
        "darwin": {
            "amd64": (
                "https://releases.hashicorp.com/vault/1.6.3/vault_1.6.3_darwin_amd64.zip",
                "7250ab8c5e9aa05eb223cfdc3f07a4a437341ee258244062b2d0fddbe391f3d7",
            ),
        },
    },
}

def _vault_binary_impl(ctx):
    os = ""
    if ctx.os.name == "linux":
        os = "linux"
    elif ctx.os.name == "mac os x":
        os = "darwin"
    else:
        fail("%s is not supported" % ctx.os.name)
    arch = ctx.execute(["uname", "-m"]).stdout.strip()

    # On Linux, uname returns x86_64 as CPU architecture.
    if arch == "x86_64":
        arch = "amd64"

    if not ctx.attr.version in VAULT_ASSETS:
        fail("%s is not supported version" % ctx.attr.version)

    url, checksum = VAULT_ASSETS[ctx.attr.version][os][archc]
    ctx.download_and_extract(
        url = url,
        sha256 = checksum,
        type = "zip",
    )

    ctx.file("BUILD.bazel", "sh_binary(name = \"bin\", srcs = [\"vault\"], visibility = [\"//visibility:public\"])")

vault_binary = repository_rule(
    implementation = _vault_binary_impl,
    attrs = {
        "version": attr.string(),
    },
)

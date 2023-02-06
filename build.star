job(
    name = "test_all",
    command = "test",
    all_revision = True,
    github_status = True,
    config_name = "ci",
    targets = [
        "//...",
    ],
    platforms = [
        "@io_bazel_rules_go//go/toolchain:linux_amd64",
    ],
    cpu_limit = "2000m",
    memory_limit = "8096Mi",
    event = ["push"],
)

job(
    name = "release",
    command = "run",
    github_status = True,
    targets = [
        "//:github_release",
    ],
    platforms = [
        "@io_bazel_rules_go//go/toolchain:linux_amd64",
    ],
    event = ["release"],
    secrets = [
        secret(mount_path = "/var/github", vault_mount = "globemaster", vault_path = "github-app/heimdallr-release", vault_key = "privatekey"),
        secret(mount_path = "/var/github", vault_mount = "globemaster", vault_path = "github-app/heimdallr-release", vault_key = "appid"),
        secret(mount_path = "/var/github", vault_mount = "globemaster", vault_path = "github-app/heimdallr-release", vault_key = "installationid"),
    ],
    env = {
        "GITHUB_APP_ID_FILE": "/var/github/appid",
        "GITHUB_INSTALLATION_ID_FILE": "/var/github/installationid",
        "GITHUB_PRIVATE_KEY": "/var/github/privatekey",
    },
    cpu_limit = "2000m",
    memory_limit = "8096Mi",
)

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

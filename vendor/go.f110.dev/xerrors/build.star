job(
    name = "test_all",
    command = "test",
    all_revision = True,
    github_status = True,
    targets = [
        "//...",
    ],
    platforms = [
        "@rules_go//go/toolchain:linux_amd64",
    ],
    cpu_limit = "2000m",
    event = ["push", "pull_request"],
)

jobs: test_all: {
	command: "test"
	targets: ["//..."]
	platforms: ["@rules_go//go/toolchain:linux_amd64"]
	all_revision: true
	github_status: true
	config_name: "ci"
	cpu_limit: "2000m"
	memory_limit: "8096Mi"
	event: ["push", "pull_request"]
}

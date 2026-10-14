jobs: release: {
	command: "run"
	targets: ["//:github_release"]
	platforms: ["@rules_go//go/toolchain:linux_amd64"]
	github_status: true
	event: ["release"]
	secrets: [
		{
			mount_path: "/var/github"
			vault_mount: "globemaster"
			vault_path: "github-app/heimdallr-release"
			vault_key: "privatekey"
		},
		{
			mount_path: "/var/github"
			vault_mount: "globemaster"
			vault_path: "github-app/heimdallr-release"
			vault_key: "appid"
		},
		{
			mount_path: "/var/github"
			vault_mount: "globemaster"
			vault_path: "github-app/heimdallr-release"
			vault_key: "installationid"
		}
	]
	env: {
		GITHUB_APP_ID_FILE: "/var/github/appid",
		GITHUB_INSTALLATION_ID_FILE: "/var/github/installationid",
		GITHUB_PRIVATE_KEY: "/var/github/privatekey",
	}
	cpu_limit: "2000m"
	memory_limit: "8096Mi"
}
jobs: create_release: {
	command: "run"
	targets: ["//cmd/release"]
	args: ["create", "--repo=f110/heimdallr"]
	params: version: {description: "Release version (e.g. v0.18.0-alpha.1)", required: true}
	platforms: ["@rules_go//go/toolchain:linux_amd64"]
	event: ["manual"]
	secrets: [
		{
			mount_path: "/var/github"
			vault_mount: "globemaster"
			vault_path: "github-app/heimdallr-release"
			vault_key: "privatekey"
		},
		{
			mount_path: "/var/github"
			vault_mount: "globemaster"
			vault_path: "github-app/heimdallr-release"
			vault_key: "appid"
		},
		{
			mount_path: "/var/github"
			vault_mount: "globemaster"
			vault_path: "github-app/heimdallr-release"
			vault_key: "installationid"
		}
	]
	env: {
		GITHUB_APP_ID_FILE: "/var/github/appid",
		GITHUB_INSTALLATION_ID_FILE: "/var/github/installationid",
		GITHUB_PRIVATE_KEY: "/var/github/privatekey",
	}
	cpu_limit: "2000m"
	memory_limit: "8096Mi"
}

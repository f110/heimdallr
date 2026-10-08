VERSION = "v0.17.0-rc.2"
RELEASE_BRANCH = "release-v0.17"

PLATFORMS = [
    "linux_amd64",
    "darwin_amd64",
    "darwin_arm64",
    "windows_amd64",
]

RELEASE_MESSAGE = """We have been published container images in ghcr.io.

* proxy: `ghcr.io/{proxy_repository}:{version}`
* rpcserver: `ghcr.io/{rpcserver_repository}:{version}`
* dashboard: `ghcr.io/{dashboard_repository}:{version}`
* CLI: `ghcr.io/{ctl_repository}:{version}`
* operator: `ghcr.io/{operator_repository}:{version}`
"""

ASSET_FILES = [
    "//operator/deploy/prod:all-in-one",
    "//cmd/heim:heim_darwin_amd64",
    "//cmd/heim:heim_darwin_arm64",
    "//cmd/heim:heim_linux_amd64",
    "//cmd/heim:heim_windows_amd64",
    "//cmd/docker-credential-heimdallr:docker-credential-heimdallr_darwin_amd64",
    "//cmd/docker-credential-heimdallr:docker-credential-heimdallr_darwin_arm64",
    "//cmd/docker-credential-heimdallr:docker-credential-heimdallr_linux_amd64",
    "//cmd/docker-credential-heimdallr:docker-credential-heimdallr_windows_amd64",
    "//cmd/heim-connector:heim-connector_darwin_amd64",
    "//cmd/heim-connector:heim-connector_darwin_arm64",
    "//cmd/heim-connector:heim-connector_linux_amd64",
    "//cmd/heim-connector:heim-connector_windows_amd64",
    "//cmd/heim-tunnel:heim-tunnel_darwin_amd64",
    "//cmd/heim-tunnel:heim-tunnel_darwin_arm64",
    "//cmd/heim-tunnel:heim-tunnel_linux_amd64",
    "//cmd/heim-tunnel:heim-tunnel_windows_amd64",
    "//cmd/heimdallrcontroller",
]

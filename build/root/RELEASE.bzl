VERSION = "v0.14.0"
RELEASE_BRANCH = "release-v0.14"

PLATFORMS = [
    "linux_amd64",
    "darwin_amd64",
    "darwin_arm64",
    "windows_amd64",
]

RELEASE_MESSAGE = """We have been published container images in quay.io.

* proxy: `quay.io/{proxy_repository}:{version}`
* rpcserver: `quay.io/{rpcserver_repository}:{version}`
* dashboard: `quay.io/{dashboard_repository}:{version}`
* CLI: `quay.io/{ctl_repository}:{version}`
* operator: `quay.io/{operator_repository}:{version}`
"""

ASSET_FILES = [
    "//operator/deploy/prod:all-in-one",
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

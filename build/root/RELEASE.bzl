VERSION = "v0.11.2"
RELEASE_BRANCH = "release-v0.11"

PLATFORMS = [
    "linux_amd64",
    "darwin_amd64",
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
    "//cmd/heim-connector:heim-connector_linux_amd64",
    "//cmd/heim-connector:heim-connector_windows_amd64",
    "//cmd/heim-proxy:heim-proxy_darwin_amd64",
    "//cmd/heim-proxy:heim-proxy_linux_amd64",
    "//cmd/heim-proxy:heim-proxy_windows_amd64",
    "//operator/cmd/heimdallrcontroller",
]

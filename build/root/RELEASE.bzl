VERSION = "v0.10.1"

PLATFORMS = [
    "linux_amd64",
    "darwin_amd64",
    "windows_amd64",
]

RELEASE_MESSAGE = """We publish container images in quay.io.

proxy: quay.io/{proxy_repository}:{version}
rpcserver: quay.io/{rpcserver_repository}:{version}
dashboard: quay.io/{dashboard_repository}:{version}
CLI: quay.io/{ctl_repository}:{version}
operator: quay.io/{operator_repository}:{version}
"""

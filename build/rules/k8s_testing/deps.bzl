load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

ETCD_URLS = {
    "3.4.3": {
        "linux_amd64": (
            "https://github.com/etcd-io/etcd/releases/download/v3.4.3/etcd-v3.4.3-linux-amd64.tar.gz",
            "6c642b723a86941b99753dff6c00b26d3b033209b15ee33325dc8e7f4cd68f07",
        ),
    },
}

def _etcd_impl(ctx):
    version = ctx.attr.version
    os, arch = _detect_os_and_arch(ctx)

    url, checksum = ETCD_URLS[version][os + "_" + arch]

    ctx.file("WORKSPACE", "workspace(name = \"{name}\")".format(name = ctx.name))
    ctx.file("BUILD", "filegroup(name = \"bin\", srcs = [\"etcd\"], visibility = [\"//visibility:public\"])")
    ctx.download_and_extract(
        url = url,
        sha256 = checksum,
        stripPrefix = "etcd-v" + version + "-" + os + "-" + arch,
    )

etcd = repository_rule(
    implementation = _etcd_impl,
    attrs = {
        "version": attr.string(),
    },
)

KUBE_APISERVER_URLS = {
    "1.16.4": {
        "linux_amd64": (
            "https://dl.k8s.io/v1.16.4/kubernetes-server-linux-amd64.tar.gz",
            "0c5766b2dfc3fed49538dbb539f282fb3f870d70f572907e5e5aac43a48859f3",
        ),
    },
}

def _kube_apiserver_impl(ctx):
    version = ctx.attr.version
    os, arch = _detect_os_and_arch(ctx)

    url, checksum = KUBE_APISERVER_URLS[version][os + "_" + arch]

    ctx.file("WORKSPACE", "workspace(name = \"{name}\")".format(name = ctx.name))
    ctx.file("BUILD", "filegroup(name = \"bin\", srcs = [\"kube-apiserver\"], visibility = [\"//visibility:public\"])")
    ctx.download_and_extract(
        url = url,
        sha256 = checksum,
        stripPrefix = "kubernetes/server/bin",
    )

kube_apiserver = repository_rule(
    implementation = _kube_apiserver_impl,
    attrs = {
        "version": attr.string(),
    },
)

def _detect_os_and_arch(ctx):
    os = "linux"
    if ctx.os.name == "mac os x":
        os = "mac"
    arch = "amd64"
    return os, arch

load("@rules_oci//oci:defs.bzl", "oci_image", "oci_image_index", "oci_push", "oci_tarball")

"""
container_image is a macro function for creating and publishing the container image.
Publishing the image doesn't regard "repotags". So published image doesn't have the tag.
"""

def container_image(name, repotags, amd64_tar, arm64_tar, base = None, entrypoint = [], labels = {}):
    oci_image(
        name = "%s.linux_amd64" % name,
        base = base,
        entrypoint = entrypoint,
        labels = labels,
        architecture = "amd64",
        tars = [amd64_tar],
        visibility = ["//visibility:public"],
    )

    oci_image(
        name = "%s.linux_arm64" % name,
        base = base,
        entrypoint = entrypoint,
        labels = labels,
        architecture = "arm64",
        tars = [arm64_tar],
        visibility = ["//visibility:public"],
    )

    oci_image_index(
        name = name,
        images = [
            "%s.linux_amd64" % name,
            "%s.linux_arm64" % name,
        ],
    )

    native.genrule(
        name = "%s.gen_digest" % name,
        srcs = [":%s" % name],
        outs = ["%s.digest" % name],
        cmd = "$(JQ_BIN) -r '.manifests[0].digest' $(location :%s)/index.json > $@" % name,
        toolchains = ["@jq_toolchains//:resolved_toolchain"],
    )

    oci_tarball(
        name = "%s.amd64_tar" % name,
        image = ":%s.linux_amd64" % name,
        repotags = repotags,
        visibility = ["//visibility:public"],
    )

    oci_tarball(
        name = "%s.arm64_tar" % name,
        image = ":%s.linux_arm64" % name,
        repotags = repotags,
        visibility = ["//visibility:public"],
    )

    oci_push(
        name = "%s.push" % name,
        image = ":%s" % name,
        repotags = repotags,
    )

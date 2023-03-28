load("@rules_oci//oci:defs.bzl", "oci_image", "oci_push", "oci_tarball")

"""
container_image is a macro function for creating and publishing the container image.
Publishing the image doesn't regard "repotags". So published image doesn't have the tag.
"""

def container_image(name, repository, repotags, base = None, entrypoint = [], labels = {}, architecture = "", tars = []):
    oci_image(
        name = name,
        base = base,
        entrypoint = entrypoint,
        labels = labels,
        architecture = architecture,
        tars = tars,
        visibility = ["//visibility:public"],
    )

    native.genrule(
        name = "%s.gen_digest" % name,
        srcs = [":%s" % name],
        outs = ["%s.digest" % name],
        cmd = "$(JQ_BIN) -r '.manifests[0].digest' $(location :%s)/index.json > $@" % name,
        toolchains = ["@jq_toolchains//:resolved_toolchain"],
    )

    oci_tarball(
        name = "%s.tar" % name,
        image = ":%s" % name,
        repotags = repotags,
        visibility = ["//visibility:public"],
    )

    oci_push(
        name = "%s.push" % name,
        image = ":%s" % name,
        repository = repository,
    )

load("@rules_oci//oci:defs.bzl", "oci_image", "oci_image_index", "oci_push", "oci_load")

"""
container_image is a macro function for creating and publishing the container image.
Publishing the image doesn't regard "tags". So published image doesn't have the tag.
"""

def container_image(name, tags, amd64_tar, arm64_tar, base_amd64 = "@com_google_distroless_base_amd64", base_arm64 = "@com_google_distroless_base_arm64", entrypoint = [], labels = {}, repository = None):
    oci_image(
        name = "%s.linux_amd64" % name,
        base = base_amd64,
        entrypoint = entrypoint,
        labels = labels,
        tars = [amd64_tar],
        visibility = ["//visibility:public"],
    )

    oci_image(
        name = "%s.linux_arm64" % name,
        base = base_arm64,
        entrypoint = entrypoint,
        labels = labels,
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

#     native.genrule(
#         name = "%s.gen_digest" % name,
#         srcs = [":%s" % name],
#         outs = ["%s.digest" % name],
#         cmd = "$(JQ_BIN) -r '.manifests[0].digest' $(location :%s)/index.json > $@" % name,
#         toolchains = ["@jq_toolchains//:resolved_toolchain"],
#     )

    oci_load(
        name = "%s.amd64_tar" % name,
        image = ":%s.linux_amd64" % name,
        repo_tags = [repository + ":" + x + "_amd64" for x in tags],
        visibility = ["//visibility:public"],
    )

    oci_load(
        name = "%s.arm64_tar" % name,
        image = ":%s.linux_arm64" % name,
        repo_tags = [repository + ":" + x + "_arm64" for x in tags],
        visibility = ["//visibility:public"],
    )

    oci_push(
        name = "%s.push" % name,
        image = ":%s" % name,
        repository = repository,
        remote_tags = tags,
    )

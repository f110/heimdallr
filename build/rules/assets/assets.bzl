def multi_platform_download_and_extract(ctx, assets, build_file_label):
    url_and_checksum = _get_url_and_checksum(ctx, assets)
    url, checksum = url_and_checksum[0], url_and_checksum[1]
    strip_prefix = ""
    if len(url_and_checksum) == 3:
        strip_prefix = url_and_checksum[2]
    ctx.download_and_extract(
        url = url,
        sha256 = checksum,
        stripPrefix = strip_prefix,
    )

    ctx.template(
        "BUILD.bazel",
        build_file_label,
        executable = False,
        substitutions = {
            "{version}": ctx.attr.version,
        },
    )

def multi_platform_download(ctx, assets, build_file_label):
    download_path = ctx.path(ctx.original_name)
    url, checksum = _get_url_and_checksum(ctx, assets)
    ctx.download(
        url = url,
        output = download_path,
        sha256 = checksum,
        executable = True,
    )

    ctx.template(
        "BUILD.bazel",
        build_file_label,
    )

def _get_url_and_checksum(ctx, assets):
    os = ""
    if ctx.os.name == "linux":
        os = "linux"
    elif ctx.os.name == "mac os x":
        os = "darwin"
    else:
        fail("%s is not supported" % ctx.os.name)
    arch = ctx.execute(["uname", "-m"]).stdout.strip()

    # On Linux, uname returns x86_64 as CPU architecture.
    if arch == "x86_64":
        arch = "amd64"

    if not os in assets:
        fail("%s is not supported platform" % os)
    if not arch in assets[os]:
        fail("%s is not supported architecture" % arch)

    return assets[os][arch]

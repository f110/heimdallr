load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_gazelle//:deps.bzl", "go_repository")

def protobuf_dependencies():
    http_archive(
        name = "com_google_protobuf",
        sha256 = "a295dd3b9551d3e2749a9969583dea110c6cdcc39d02088f7c7bb1100077e081",
        strip_prefix = "protobuf-3.21.1",
        urls = [
            "https://mirror.bazel.build/github.com/protocolbuffers/protobuf/archive/v3.21.1.tar.gz",
            "https://github.com/protocolbuffers/protobuf/archive/refs/tags/v3.21.1.tar.gz",
            "https://mirror.bucket.x.f110.dev/github.com/protocolbuffers/protobuf/archive/refs/tags/v3.21.1.tar.gz",
        ],
    )

def grpc_dependencies():
    go_repository(
        name = "org_golang_google_grpc",
        build_file_proto_mode = "disable",
        importpath = "google.golang.org/grpc",
        sum = "h1:EC2SB8S04d2r73uptxphDSUG+kTKVgjRPF+N3xpxRB4=",
        version = "v1.29.1",
    )

    go_repository(
        name = "org_golang_x_net",
        importpath = "golang.org/x/net",
        sum = "h1:oWX7TPOiFAMXLq8o0ikBYfCJVlRHBcsciT5bXOrH628=",
        version = "v0.0.0-20190311183353-d8887717615a",
    )

    go_repository(
        name = "org_golang_x_text",
        importpath = "golang.org/x/text",
        sum = "h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=",
        version = "v0.3.0",
    )

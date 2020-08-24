protoc-ddl
---

**THIS PROJECT IS WORKING IN PROGRESS**

protoc-ddl is a tool of define and generate the schema for RDB.

# How to use

## Command Line

```
$ go get go.f110.dev/protoc-ddl/cmd/protoc-gen-ddl
```

## With Bazel

`WORKSPACE`

```
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

http_archive(
    name = "io_bazel_rules_go",
    sha256 = "a8d6b1b354d371a646d2f7927319974e0f9e52f73a2452d2b3877118169eb6bb",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.23.3/rules_go-v0.23.3.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.23.3/rules_go-v0.23.3.tar.gz",
    ],
)

git_repository(
    name = "dev_f110_protoc_ddl",
    commit = "61319c2f91243da88d6d88a04d3e5b783b86f510",
    remote = "https://github.com/f110/protoc-ddl",
)

load("@io_bazel_rules_go//go:deps.bzl", "go_rules_dependencies", "go_register_toolchains")

go_rules_dependencies()

go_register_toolchains()

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()
```

`BUILD.bazel`

```
load("@rules_proto//proto:defs.bzl", "proto_library")
load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

proto_library(
    name = "database_proto",
    srcs = ["schema.proto"],
    visibility = ["//visibility:public"],
    deps = [
        "@dev_f110_protoc_ddl//:ddl_proto",
        "@com_google_protobuf//:timestamp_proto",
    ],
)

go_proto_library(
    name = "database_go_proto",
    importpath = "go.f110.dev/mono/tools/build/pkg/database",
    proto = ":database_proto",
    visibility = ["//visibility:public"],
    deps = ["//:go_default_library"],
)

go_library(
    name = "go_default_library",
    embed = [":database_go_proto"],
    importpath = "go.f110.dev/mono/tools/build/pkg/database",
    visibility = ["//visibility:public"],
)

load("@dev_f110_protoc_ddl//rules:def.bzl", "sql_schema", "vendor_sql_schema")

sql_schema(
    name = "schema",
    proto = ":database_proto",
)

vendor_sql_schema(
    name = "vendor_schema",
    src = ":schema",
)
```

You can see the generated schema file by the following command.

```
$ bazel run //:vendor_sql_schema
```

You will see the generated schema file in the same directory at `*.sql`.

# Migration

This tool also supports the migration.

```
$ migrate --schema ./schema.sql --driver mysql --dsn "root@tcp(localhost)/protoc_ddl" --execute
```

Currently, Only mysql is supported.
update-deps:
	go mod tidy
	bazel run //:gazelle -- update
	bazel run //:gazelle -- update-repos -from_file=go.mod -to_macro=build/deps.bzl%project_deps

.PHONY: update-deps
.PHONY: update-deps
update-deps:
	bazel run @rules_go//go mod tidy
	bazel run @rules_go//go mod vendor
	bazel run //:gazelle -- update

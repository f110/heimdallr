update-deps:
	go mod tidy
	bazel run //:gazelle -- update
	bazel run //:gazelle -- update-repos -from_file=go.mod

.PHONY: update-deps
run:
	bazel run //cmd/lagrangian-proxy -- -c $(CURDIR)/config_debug.yaml

update-deps:
	go mod tidy
	go mod vendor
	find vendor -name BUILD.bazel -delete
	bazel run //:gazelle -- update

.PHONY: run update-deps
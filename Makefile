run:
	bazel run //cmd/lagrangian-proxy -- -c $(CURDIR)/config_debug.yaml

update-deps:
	bazel run //:vendor

.PHONY: run update-deps
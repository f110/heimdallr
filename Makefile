run:
	bazel run //cmd/lagrangian-proxy -- -c $(CURDIR)/config_debug.yaml

update-deps:
	bazel run //:vendor

push:
	bazel build --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 //:image.tar
	docker load -i bazel-bin/image.tar
	docker tag bazel:image quay.io/f110/lagrangian-proxy:latest
	docker push quay.io/f110/lagrangian-proxy:latest

.PHONY: run update-deps push
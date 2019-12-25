run:
	bazel run //cmd/lagrangian-proxy -- -c $(CURDIR)/config_debug.yaml

run-operator:
	bazel run //operator:generate
	bazel run //operator:manifests
	bazel run //operator

install-operator:
	bazel run //operator:manifests
	kustomize build operator/config/crd | kubectl apply -f -

update-deps: gen
	@bazel run //:vendor

gen:
	@bazel query 'attr(generator_function, vendor_grpc_source, //...)' | xargs -n1 bazel run

push: push-proxy push-ctl push-rpcserver

push-proxy:
	bazel build --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 //:image.tar
	docker load -i bazel-bin/image.tar
	docker tag bazel:image quay.io/f110/lagrangian-proxy:latest
	docker push quay.io/f110/lagrangian-proxy:latest

push-rpcserver:
	bazel build --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 //:image_rpcserver.tar
	docker load -i bazel-bin/image_rpcserver.tar
	docker tag bazel:image_rpcserver quay.io/f110/lagrangian-proxy-rpcserver:latest
	docker push quay.io/f110/lagrangian-proxy-rpcserver:latest

push-ctl:
	bazel build --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 //:image_ctl.tar
	docker load -i bazel-bin/image_ctl.tar
	docker tag bazel:image_ctl quay.io/f110/lagrangian-proxy-ctl:latest
	docker push quay.io/f110/lagrangian-proxy-ctl:latest

.PHONY: run run-operator install-operator update-deps gen push push-proxy push-rpcserver push-ctl
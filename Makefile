VERSION = v0.3.2

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

generate-deploy-manifests:
	bazel run //operator:manifests
	kubectl kustomize operator/deploy | bazel run //operator/hack/manifest-finalizer > operator/deploy/all-in-one.yaml

push: push-proxy push-ctl push-rpcserver push-operator

push-proxy:
	bazel build --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 //:image.tar
	docker load -i bazel-bin/image.tar
	docker tag bazel:image quay.io/f110/lagrangian-proxy:$(VERSION)
	docker push quay.io/f110/lagrangian-proxy:$(VERSION)
	docker rmi bazel:image

push-rpcserver:
	bazel build --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 //:image_rpcserver.tar
	docker load -i bazel-bin/image_rpcserver.tar
	docker tag bazel:image_rpcserver quay.io/f110/lagrangian-proxy-rpcserver:$(VERSION)
	docker push quay.io/f110/lagrangian-proxy-rpcserver:$(VERSION)
	docker rmi bazel:image_rpcserver

push-ctl:
	bazel build --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 //:image_ctl.tar
	docker load -i bazel-bin/image_ctl.tar
	docker tag bazel:image_ctl quay.io/f110/lagrangian-proxy-ctl:$(VERSION)
	docker push quay.io/f110/lagrangian-proxy-ctl:$(VERSION)
	docker rmi bazel:image_ctl

push-operator:
	bazel build --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 //operator:image.tar
	docker load -i bazel-bin/operator/image.tar
	docker tag bazel/operator:image quay.io/f110/lagrangian-proxy-operator:$(VERSION)
	docker push quay.io/f110/lagrangian-proxy-operator:$(VERSION)
	docker rmi bazel/operator:image

.PHONY: run run-operator install-operator update-deps gen push push-proxy push-rpcserver push-ctl push-operator
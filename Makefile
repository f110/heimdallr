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

push:
	bazel query 'kind(container_push, //...)' | xargs -n1 bazel run

.PHONY: run run-operator install-operator update-deps gen push
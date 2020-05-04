run:
	bazel run //cmd/lagrangian-proxy -- -c $(CURDIR)/config_debug.yaml

run-operator:
	bazel run //operator -- -lease-lock-name operator -lease-lock-namespace default -cluster-domain cluster.local -dev -v 4

install-operator:
	kustomize build operator/config/crd | kubectl apply -f -

update-deps: gen
	@bazel run //:vendor

gen:
	@bazel query 'attr(generator_function, vendor_grpc_source, //...)' | xargs -n1 bazel run

generate-deploy-manifests:
	kustomize build operator/deploy | bazel run //operator/hack/manifest-finalizer > operator/deploy/all-in-one.yaml

gen-operator:
	bazel run //operator/pkg/api:gen.deepcopy
	bazel run //operator/pkg/api:gen.client
	bazel run //operator/pkg/api:gen.lister
	bazel run //operator/pkg/api:gen.informer
	bazel run //operator/pkg/api:gen.crd
	bazel run //operator/pkg/controllers:rbac

push:
	bazel query 'kind(container_push, //...)' | xargs -n1 bazel run

.PHONY: run run-operator install-operator update-deps gen push
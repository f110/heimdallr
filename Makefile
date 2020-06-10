run:
	bazel run //cmd/heimdallr-proxy -- -c $(CURDIR)/config_debug.yaml

run-operator:
	bazel run //operator/cmd/heimdallrcontroller -- -lease-lock-name operator -lease-lock-namespace default -cluster-domain cluster.local -dev -v 4

test:
	bazel test //...

install-operator:
	kustomize build operator/config/crd | kubectl apply -f -

update-deps: gen
	@bazel run //:vendor

gen:
	@bazel query 'attr(generator_function, vendor_grpc_source, //...)' | xargs -n1 bazel run

generate-deploy-manifests:
	bazel run //operator/pkg/controllers:rbac
	kustomize build operator/deploy | bazel run //operator/hack/manifest-finalizer > operator/deploy/all-in-one.yaml

gen-operator:
	bazel query 'attr(generator_function, k8s_code_generator, //...)' | xargs -n1 bazel run
	bazel run //operator/pkg/controllers:rbac

push:
	bazel query 'kind(container_push, //...)' | xargs -n1 bazel run

run-e2e:
	bazel build //operator/e2e/test:go_default_test
	./bazel-bin/operator/e2e/test/go_default_test_/go_default_test -test.v=true -crd $(CURDIR)/operator/config/crd/bases -proxy.version v0.6.3

.PHONY: run run-operator test install-operator update-deps gen push
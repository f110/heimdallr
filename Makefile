API_FILE_DIR   = github.com/f110/lagrangian-proxy/operator/pkg/api/proxy/v1,github.com/f110/lagrangian-proxy/operator/pkg/api/etcd/v1alpha1
GO_HEADER_FILE = ./operator/hack/boilerplate.go.txt

GOHOSTOS = $(shell go env GOHOSTOS)
GOARCH   = $(shell go env GOARCH)
GOROOT   = $(shell go env GOROOT)

CODE_GEN_CMD_DIR = ./bazel-bin/third_party/code-generator/cmd
DEEPCOPY_GEN     = $(CODE_GEN_CMD_DIR)/deepcopy-gen/$(GOHOSTOS)_$(GOARCH)_stripped/deepcopy-gen
CLIENT_GEN       = $(CODE_GEN_CMD_DIR)/client-gen/$(GOHOSTOS)_$(GOARCH)_stripped/client-gen
LISTER_GEN       = $(CODE_GEN_CMD_DIR)/lister-gen/$(GOHOSTOS)_$(GOARCH)_stripped/lister-gen
INFORMER_GEN     = $(CODE_GEN_CMD_DIR)/informer-gen/$(GOHOSTOS)_$(GOARCH)_stripped/informer-gen

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
	bazel run //operator:manifests
	kubectl kustomize operator/deploy | bazel run //operator/hack/manifest-finalizer > operator/deploy/all-in-one.yaml

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
DATABASE_HOST = localhost
DATABASE_USER = heimdallr
DATABASE_NAME = heimdallr

DSN = $(DATABASE_USER)@tcp($(DATABASE_HOST))/$(DATABASE_NAME)
WEBHOOK_CERT = --cert $(CURDIR)/operator/webhook.crt --key $(CURDIR)/operator/webhook.key
OPERATOR_ARG = --lease-lock-name operator --lease-lock-namespace default --cluster-domain cluster.local --dev --log-level=debug --log-encoding=console $(WEBHOOK_CERT)

run:
	bazel run //cmd/heimdallr-proxy -- -c $(CURDIR)/config_debug.yaml

run-dashboard:
	bazel run //cmd/heim-dashboard -- -c $(CURDIR)/dashboard_config_debug.yaml

run-rpcserver:
	bazel run //cmd/heim-rpcserver -- -c $(CURDIR)/rpcserver_config_debug.yaml

run-operator:
	bazel run //cmd/heimdallrcontroller -- $(OPERATOR_ARG)

test:
	bazel test //...

update-deps: gen
	@bazel run //:vendor

gen:
	@bazel query 'attr(generator_function, vendor_grpc_source, //...)' | xargs -n1 bazel run
	bazel run //pkg/database/mysql/entity:vendor_schema
	bazel run //pkg/database/mysql/entity:vendor_entity
	bazel run //pkg/database/mysql/dao:vendor_dao

gen-operator: third_party_protos
	bazel query 'attr(generator_function, k8s_code_generator, //...)' | xargs -n1 bazel run
	bazel query 'kind(vendor_kubeproto, //...)' | xargs -n1 bazel run
	bazel run //pkg/k8s/controllers:rbac

third_party_protos: operator/proto/github.com/jetstack/cert-manager/pkg/apis/certmanagerv1/generated.proto \
	operator/proto/github.com/jetstack/cert-manager/pkg/apis/metav1/generated.proto \
	operator/proto/github.com/jetstack/cert-manager/pkg/apis/acmev1/generated.proto \
	operator/proto/github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoringv1/generated.proto

.PHONY: operator/proto/github.com/jetstack/cert-manager/pkg/apis/certmanagerv1/generated.proto
operator/proto/github.com/jetstack/cert-manager/pkg/apis/certmanagerv1/generated.proto:
	mkdir -p $(@D)
	bazel run @dev_f110_kubeproto//cmd/gen-go-to-protobuf -- --out $(CURDIR)/$@ \
		--proto-package github.com.jetstack.cert_manager.pkg.apis.certmanagerv1 \
		--go-package github.com/jetstack/cert-manager/pkg/apis/certmanager/v1 \
		--api-sub-group cert-manager.io \
		--api-version v1 \
		--imports github.com/jetstack/cert-manager/pkg/apis/meta/v1:github.com.jetstack.cert_manager.pkg.apis.metav1:github.com/jetstack/cert-manager/pkg/apis/metav1 \
		--imports github.com/jetstack/cert-manager/pkg/apis/acme/v1:github.com.jetstack.cert_manager.pkg.apis.acmev1:github.com/jetstack/cert-manager/pkg/apis/acmev1 \
		--import-prefix operator/proto \
		--all \
		$(CURDIR)/vendor/github.com/jetstack/cert-manager/pkg/apis/certmanager/v1

.PHONY: operator/proto/github.com/jetstack/cert-manager/pkg/apis/metav1/generated.proto
operator/proto/github.com/jetstack/cert-manager/pkg/apis/metav1/generated.proto:
	mkdir -p $(@D)
	bazel run @dev_f110_kubeproto//cmd/gen-go-to-protobuf -- --out $(CURDIR)/$@ \
		--proto-package github.com.jetstack.cert_manager.pkg.apis.metav1 \
		--go-package github.com/jetstack/cert-manager/pkg/apis/meta/v1 \
		--api-sub-group cert-manager.io \
		--api-version v1 \
		--all \
		$(CURDIR)/vendor/github.com/jetstack/cert-manager/pkg/apis/meta/v1

.PHONY: operator/proto/github.com/jetstack/cert-manager/pkg/apis/acmev1/generated.proto
operator/proto/github.com/jetstack/cert-manager/pkg/apis/acmev1/generated.proto:
	mkdir -p $(@D)
	bazel run @dev_f110_kubeproto//cmd/gen-go-to-protobuf -- --out $(CURDIR)/$@ \
		--proto-package github.com.jetstack.cert_manager.pkg.apis.acmev1 \
		--go-package github.com/jetstack/cert-manager/pkg/apis/acme/v1 \
		--api-sub-group cert-manager.io \
		--api-version v1 \
		--imports github.com/jetstack/cert-manager/pkg/apis/meta/v1:github.com.jetstack.cert_manager.pkg.apis.metav1:github.com/jetstack/cert-manager/pkg/apis/metav1 \
		--import-prefix operator/proto \
		--all \
		$(CURDIR)/vendor/github.com/jetstack/cert-manager/pkg/apis/acme/v1

.PHONY: operator/proto/github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoringv1/generated.proto
operator/proto/github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoringv1/generated.proto:
	mkdir -p $(@D)
	bazel run @dev_f110_kubeproto//cmd/gen-go-to-protobuf -- --out $(CURDIR)/$@ \
		--proto-package github.com.prometheus_operator.prometheus_operator.pkg.apis.monitoringv1 \
		--go-package github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1 \
		--api-sub-group coreos.com \
		--api-domain monitoring \
		--api-version v1 \
		--all \
		$(CURDIR)/vendor/github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1

create-cluster:
	bazel run //:create_cluster
	bazel run @kind//:bin -- export kubeconfig --name heimdallr

delete-cluster:
	bazel run //:delete_cluster

push:
	bazel query 'kind(container_push, //...)' | xargs -n1 bazel run

run-e2e:
	bazel test --config e2e //operator/e2e/test:test_test

migrate:
	bazel run @dev_f110_protoc_ddl//cmd/migrate -- --schema $(CURDIR)/pkg/database/mysql/entity/schema.sql --driver mysql --dsn "$(DSN)" --execute

.PHONY: run run-dashboard run-operator test update-deps gen generate-deploy-manifests gen-operator push run-e2e migrate

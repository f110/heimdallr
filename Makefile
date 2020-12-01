DATABASE_HOST = localhost
DATABASE_USER = heimdallr
DATABASE_NAME = heimdallr

DSN = $(DATABASE_USER)@tcp($(DATABASE_HOST))/$(DATABASE_NAME)
WEBHOOK_CERT = --cert $(CURDIR)/operator/webhook.crt --key $(CURDIR)/operator/webhook.key
OPERATOR_ARG = --lease-lock-name operator --lease-lock-namespace default --cluster-domain cluster.local --dev --logtostderr=false --log-level=debug $(WEBHOOK_CERT)

run:
	bazel run //cmd/heimdallr-proxy -- -c $(CURDIR)/config_debug.yaml

run-dashboard:
	bazel run //cmd/heim-dashboard -- -c $(CURDIR)/dashboard_config_debug.yaml

run-rpcserver:
	bazel run //cmd/heim-rpcserver -- -c $(CURDIR)/rpcserver_config_debug.yaml

run-operator:
	bazel run //operator/cmd/heimdallrcontroller -- $(OPERATOR_ARG)

test:
	bazel test //...

update-deps: gen
	@bazel run //:vendor

gen:
	@bazel query 'attr(generator_function, vendor_grpc_source, //...)' | xargs -n1 bazel run
	bazel run //pkg/database/mysql/entity:vendor_schema
	bazel run //pkg/database/mysql/entity:vendor_entity
	bazel run //pkg/database/mysql/dao:vendor_dao

gen-operator:
	bazel query 'attr(generator_function, k8s_code_generator, //...)' | xargs -n1 bazel run
	bazel run //operator/pkg/controllers:rbac

create-cluster:
	bazel run //:create_cluster

push:
	bazel query 'kind(container_push, //...)' | xargs -n1 bazel run

run-e2e:
	bazel test --config e2e //operator/e2e/test:test_test

migrate:
	bazel run @dev_f110_protoc_ddl//cmd/migrate -- --schema $(CURDIR)/pkg/database/mysql/entity/schema.sql --driver mysql --dsn "$(DSN)" --execute

.PHONY: run run-dashboard run-operator test update-deps gen generate-deploy-manifests gen-operator push run-e2e migrate

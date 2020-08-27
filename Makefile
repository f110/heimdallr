DATABASE_HOST = localhost
DATABASE_USER = heimdallr
DATABASE_NAME = heimdallr

DSN = $(DATABASE_USER)@tcp($(DATABASE_HOST))/$(DATABASE_NAME)

run:
	bazel run //cmd/heimdallr-proxy -- -c $(CURDIR)/config_debug.yaml

run-operator:
	bazel run //operator/cmd/heimdallrcontroller -- -lease-lock-name operator -lease-lock-namespace default -cluster-domain cluster.local -dev -v 4

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

push:
	bazel query 'kind(container_push, //...)' | xargs -n1 bazel run

run-e2e:
	bazel build //operator/e2e/test:go_default_test
	./bazel-bin/operator/e2e/test/go_default_test_/go_default_test -test.v=true -crd $(CURDIR)/operator/config/crd/bases -proxy.version v0.6.3

migrate:
	bazel run @dev_f110_protoc_ddl//cmd/migrate -- --schema $(CURDIR)/pkg/database/mysql/entity/schema.sql --driver mysql --dsn "$(DSN)" --execute

.PHONY: run run-operator test update-deps gen generate-deploy-manifests gen-operator push run-e2e migrate
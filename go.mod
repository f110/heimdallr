module go.f110.dev/heimdallr

go 1.15

require (
	cloud.google.com/go v0.60.0 // indirect
	cloud.google.com/go/storage v1.10.0
	github.com/Masterminds/semver/v3 v3.1.1
	github.com/bradfitz/gomemcache v0.0.0-20190913173617-a41fca850d0b
	github.com/bradleyfalzon/ghinstallation v1.1.1
	github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/coreos/prometheus-operator v0.36.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/fatih/color v1.10.0
	github.com/fsnotify/fsnotify v1.4.9
	github.com/go-sql-driver/mysql v1.5.0
	github.com/golang/protobuf v1.4.3
	github.com/google/go-cmp v0.5.2
	github.com/google/go-containerregistry v0.1.4
	github.com/google/go-github v17.0.0+incompatible
	github.com/google/go-github/v32 v32.1.0
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.7.3
	github.com/gorilla/securecookie v1.1.1
	github.com/gorilla/websocket v1.4.2
	github.com/grpc-ecosystem/go-grpc-middleware v1.1.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/jarcoal/httpmock v1.0.5
	github.com/jetstack/cert-manager v1.0.1
	github.com/julienschmidt/httprouter v1.3.0
	github.com/miekg/dns v1.1.29
	github.com/minio/minio-go/v6 v6.0.44
	github.com/peterh/liner v1.2.1
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/common v0.10.0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	go.etcd.io/etcd/v3 v3.3.0-rc.0.0.20200518175753-732df43cf85b
	go.f110.dev/protoc-ddl v0.0.0-20201210115038-eee28d3afbdd
	go.opencensus.io v0.22.4 // indirect
	go.uber.org/zap v1.14.1
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
	google.golang.org/api v0.29.0
	google.golang.org/grpc v1.29.1
	google.golang.org/protobuf v1.25.0
	gopkg.in/square/go-jose.v2 v2.3.1
	gopkg.in/yaml.v2 v2.3.0
	k8s.io/api v0.20.4
	k8s.io/apiextensions-apiserver v0.20.4
	k8s.io/apimachinery v0.20.4
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog/v2 v2.4.0
	sigs.k8s.io/kind v0.9.0
	sigs.k8s.io/yaml v1.2.0
	software.sslmate.com/src/go-pkcs12 v0.0.0-20200619203921-c9ed90bd32dc
)

replace k8s.io/client-go => k8s.io/client-go v0.20.4

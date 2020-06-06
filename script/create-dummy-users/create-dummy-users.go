package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
)

func main() {
	host := "local-proxy.f110.dev:4000"
	count := 10
	role := "user"
	userIdFormat := "dummy_%d@exmaple.com"
	ca := ""
	flags := pflag.NewFlagSet("create-dummy-users", pflag.ContinueOnError)
	flags.StringVarP(&host, "host", "h", host, "hostname")
	flags.IntVarP(&count, "count", "c", count, "number of users")
	flags.StringVarP(&role, "role", "r", role, "role name")
	flags.StringVarP(&userIdFormat, "format", "f", userIdFormat, "user id format")
	flags.StringVar(&ca, "ca", ca, "CA Certificate path")
	if err := flags.Parse(os.Args); err != nil {
		panic(err)
	}

	var pool *x509.CertPool
	if ca != "" {
		b, err := ioutil.ReadFile(ca)
		if err != nil {
			panic(err)
		}
		block, _ := pem.Decode(b)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic(err)
		}
		pool = x509.NewCertPool()
		pool.AddCert(cert)
	}

	cred := credentials.NewTLS(&tls.Config{ServerName: host, RootCAs: pool})
	conn, err := grpc.Dial(
		host,
		grpc.WithTransportCredentials(cred),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: time.Second, PermitWithoutStream: true}),
	)
	if err != nil {
		panic(err)
	}

	c, err := rpcclient.NewWithStaticToken(conn)
	if err != nil {
		panic(err)
	}
	defer c.Close()

	for i := 0; i < count; i++ {
		if err := c.AddUser(fmt.Sprintf(userIdFormat, i+1), role); err != nil {
			panic(err)
		}
	}
}

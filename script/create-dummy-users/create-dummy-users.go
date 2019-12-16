package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/f110/lagrangian-proxy/pkg/rpc/rpcclient"
	"github.com/spf13/pflag"
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

	c, err := rpcclient.NewClientWithStaticToken(pool, host)
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

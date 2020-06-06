package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"

	"github.com/spf13/pflag"
)

func findPid() string {
	cmd := exec.Command("ps", "a")
	buf, err := cmd.CombinedOutput()
	if err != nil {
		panic(err)
	}

	line := ""
	lines := strings.Split(string(buf), "\n")
	for _, v := range lines {
		if !strings.Contains(v, "cmd/lagrangian-proxy") {
			continue
		}
		if strings.Contains(v, "grep") {
			continue
		}
		line = v
	}

	if line == "" {
		return ""
	}

	s := strings.Split(line, " ")
	for _, v := range s {
		if len(v) == 0 {
			continue
		}
		return v
	}

	return ""
}

func memoryUsage(pid string) int {
	b, err := ioutil.ReadFile(fmt.Sprintf("/proc/%s/status", pid))
	if err != nil {
		return 0
	}

	rss := 0
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, "Rss") {
			continue
		}

		s := strings.Split(line, " ")
		for _, v := range s[1:] {
			if len(v) > 0 {
				i, err := strconv.Atoi(v)
				if err != nil {
					continue
				}
				rss += i
				break
			}
		}
	}

	return rss
}

func main() {
	host := "local-proxy.f110.dev:4000"
	max := 10
	role := "user"
	userIdFormat := "dummy_%d@exmaple.com"
	ca := ""
	flags := pflag.NewFlagSet("measuring-memory-usage", pflag.ContinueOnError)
	flags.StringVarP(&host, "host", "h", host, "hostname")
	flags.StringVarP(&role, "role", "r", role, "role name")
	flags.StringVarP(&userIdFormat, "format", "f", userIdFormat, "user id format")
	flags.IntVar(&max, "max", max, "maximum number of users")
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

	pid := findPid()
	if pid == "" {
		panic("proxy process not found")
	}
	rss := memoryUsage(pid)
	fmt.Fprintf(os.Stderr, "Found proxy process: %s\n", pid)
	fmt.Fprintf(os.Stderr, "Initial memory usage: %d\n", rss)

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

	users, err := c.ListUser(role)
	if err != nil {
		panic(err)
	}
	if len(users) > 0 {
		fmt.Fprintf(os.Stderr, "Delete existing users (%d)\n", len(users))
		// Remove all existing user
		for _, v := range users {
			if err := c.DeleteUser(v.Id, role); err != nil {
				panic(err)
			}
		}
	}

	rss = memoryUsage(pid)
	fmt.Fprintf(os.Stdout, "0\t%d\n", rss)
	desiredUserCount := 10
	currentUserCount := 0
	for i := 1; i <= 4; i++ {
		fmt.Fprintf(os.Stderr, "Create user to %d\n", desiredUserCount)
		diff := desiredUserCount - currentUserCount
		for k := 0; k < diff; k++ {
			if err := c.AddUser(fmt.Sprintf("mesure_%d@example.com", k+currentUserCount), role); err != nil {
				panic(err)
			}
		}
		currentUserCount += diff
		desiredUserCount = desiredUserCount * 10
		rss = memoryUsage(pid)
		fmt.Fprintf(os.Stdout, "%d\t%d\t%d\n", i, currentUserCount, rss)
	}
}

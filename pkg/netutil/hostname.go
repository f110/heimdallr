package netutil

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/xerrors"
)

const (
	IPAddressEnvKey = "MY_IP_ADDRESS"
	NamespaceEnvKey = "MY_NAMESPACE"
)

var resolvFile = "/etc/resolv.conf"

func GetHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", xerrors.Errorf(": %v", err)
	}

	if os.Getenv("MY_IP_ADDRESS") != "" && os.Getenv("MY_NAMESPACE") != "" {
		// Running on k8s
		b, err := ioutil.ReadFile(resolvFile)
		if err != nil {
			return "", xerrors.Errorf(": %v", err)
		}
		searchDomains := ""
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(line, "search ") {
				continue
			}
			searchDomains = strings.TrimPrefix(line, "search ")
		}
		d := strings.Split(searchDomains, " ")
		clusterDomain := d[len(d)-1]

		h := strings.ReplaceAll(os.Getenv("MY_IP_ADDRESS"), ".", "-")
		hostname = fmt.Sprintf("%s.%s.pod.%s", h, os.Getenv("MY_NAMESPACE"), clusterDomain)
	}

	return hostname, nil
}

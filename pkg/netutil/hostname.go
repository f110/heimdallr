package netutil

import (
	"fmt"
	"os"
	"strings"

	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/k8s"
)

const (
	IPAddressEnvKey = "MY_IP_ADDRESS"
	NamespaceEnvKey = "MY_NAMESPACE"
)

func GetHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", xerrors.WithStack(err)
	}

	if os.Getenv("MY_IP_ADDRESS") != "" && os.Getenv("MY_NAMESPACE") != "" {
		// Running on k8s
		clusterDomain, err := k8s.GetClusterDomain()
		if err != nil {
			return "", err
		}

		h := strings.ReplaceAll(os.Getenv("MY_IP_ADDRESS"), ".", "-")
		hostname = fmt.Sprintf("%s.%s.pod.%s", h, os.Getenv("MY_NAMESPACE"), clusterDomain)
	}

	return hostname, nil
}

package k8s

import (
	"os"
	"strings"

	"go.f110.dev/xerrors"
)

var (
	ResolvFile = "/etc/resolv.conf"
)

func GetClusterDomain() (string, error) {
	// Running on k8s
	b, err := os.ReadFile(ResolvFile)
	if err != nil {
		return "", xerrors.WithStack(err)
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

	return clusterDomain, nil
}

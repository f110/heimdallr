package certmanager

import "embed"

//go:embed cert-manager.yaml cluster-issuer.yaml
var Data embed.FS

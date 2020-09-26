package framework

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/netutil"
)

type providerJson struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSEndpoint          string `json:"jwks_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

type IdentityProvider struct {
	*http.Server
	Issuer string
}

func NewIdentityProvider() (*IdentityProvider, error) {
	port, err := netutil.FindUnusedPort()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, req *http.Request) {
		issuer := fmt.Sprintf("http://127.0.0.1:%d", port)
		p := &providerJson{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/auth",
		}
		if err := json.NewEncoder(w).Encode(p); err != nil {
			return
		}
	})
	s := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	go s.Serve(l)

	return &IdentityProvider{
		Server: s,
		Issuer: fmt.Sprintf("http://127.0.0.1:%d", port),
	}, nil
}

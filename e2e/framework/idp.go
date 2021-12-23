package framework

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/oauth2/jws"
	"golang.org/x/xerrors"
	"gopkg.in/square/go-jose.v2"

	"go.f110.dev/heimdallr/pkg/netutil"
)

type providerJson struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSEndpoint          string `json:"jwks_uri"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

type tokenJson struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	IdToken      string `json:"id_token"`
}

type IdentityProvider struct {
	*http.Server
	Issuer     string
	PrivateKey *rsa.PrivateKey

	codes map[string]struct{}
}

func NewIdentityProvider() (*IdentityProvider, error) {
	port, err := netutil.FindUnusedPort()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	idp := &IdentityProvider{
		Issuer:     fmt.Sprintf("http://127.0.0.1:%d", port),
		PrivateKey: privateKey,
		codes:      make(map[string]struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, req *http.Request) {
		issuer := fmt.Sprintf("http://127.0.0.1:%d", port)
		p := &providerJson{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/custom-idp/auth",
			TokenEndpoint:         issuer + "/api/token",
			JWKSEndpoint:          issuer + "/jwks",
		}
		if err := json.NewEncoder(w).Encode(p); err != nil {
			return
		}
	})
	mux.HandleFunc("/custom-idp/auth", idp.handleAuth)
	mux.HandleFunc("/custom-idp/login", idp.handleLogin)
	mux.HandleFunc("/api/token", idp.handleToken)
	mux.HandleFunc("/jwks", idp.handleJWKS)

	idp.Server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
	l, err := net.Listen("tcp", idp.Server.Addr)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	go idp.Server.Serve(l)

	return idp, nil
}

type AuthResponse struct {
	Query    string
	LoginURL string
}

func (i *IdentityProvider) handleAuth(w http.ResponseWriter, req *http.Request) {
	v := &AuthResponse{
		Query:    req.URL.Query().Encode(),
		LoginURL: i.Issuer + "/custom-idp/login",
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (i *IdentityProvider) handleLogin(w http.ResponseWriter, req *http.Request) {
	authResponse := &AuthResponse{}
	if err := json.NewDecoder(req.Body).Decode(authResponse); err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	q, err := url.ParseQuery(authResponse.Query)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	redirectURL, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	code := make([]byte, 16)
	for i := range code {
		code[i] = letters[mrand.Intn(len(letters))]
	}
	i.codes[string(code)] = struct{}{}
	rq := redirectURL.Query()
	rq.Set("state", q.Get("state"))
	rq.Set("code", string(code))
	redirectURL.RawQuery = rq.Encode()

	http.Redirect(w, req, redirectURL.String(), http.StatusFound)
}

func (i *IdentityProvider) handleToken(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	gotCode := req.FormValue("code")
	if _, ok := i.codes[gotCode]; !ok {
		log.Print("Unknown code")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	cs := &jws.ClaimSet{Iss: i.Issuer, Aud: "identityprovider", Sub: "e2eidentityprovider", PrivateClaims: map[string]interface{}{"email": "test@f110.dev"}}
	idToken, err := jws.Encode(&jws.Header{Algorithm: "RS256", KeyID: "idp"}, cs, i.PrivateKey)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	token := &tokenJson{
		AccessToken:  "accesstoken",
		RefreshToken: "refreshtoken",
		IdToken:      idToken,
	}
	if err := json.NewEncoder(w).Encode(token); err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (i *IdentityProvider) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: i.PrivateKey.Public(), KeyID: "idp", Use: "sig"},
		},
	}
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

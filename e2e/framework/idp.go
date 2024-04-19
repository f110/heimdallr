package framework

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/xerrors"

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

	providerStorage *providerStorage
}

func NewIdentityProvider(redirectURL string) (*IdentityProvider, error) {
	port, err := netutil.FindUnusedPort()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	idp := &IdentityProvider{
		Issuer:     fmt.Sprintf("http://127.0.0.1:%d/", port),
		PrivateKey: privateKey,
	}

	st := newProviderStorage(privateKey)
	st.Clients = []op.Client{
		&client{
			ID:          "e2e",
			RedirectURL: []string{redirectURL},
			Login:       "/login",
		},
	}
	idp.providerStorage = st
	p, err := op.NewProvider(
		&op.Config{CryptoKey: sha256.Sum256([]byte("e2eframework"))},
		st,
		op.StaticIssuer(fmt.Sprintf("http://127.0.0.1:%d/", port)),
		op.WithAllowInsecure(),
	)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	router := p.Handler.(*chi.Mux)
	router.MethodFunc(http.MethodGet, "/login", idp.handleAuth)
	router.MethodFunc(http.MethodPost, "/login", idp.handleLogin)
	router.MethodFunc(http.MethodGet, "/custom-idp/authorized", func(w http.ResponseWriter, req *http.Request) {
		log.Print("OK")
	})
	//router.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, req *http.Request) {
	//	issuer := fmt.Sprintf("http://127.0.0.1:%d", port)
	//	p := &providerJson{
	//		Issuer:                issuer,
	//		AuthorizationEndpoint: issuer + "/custom-idp/auth",
	//		TokenEndpoint:         issuer + "/api/token",
	//		JWKSEndpoint:          issuer + "/jwks",
	//	}
	//	if err := json.NewEncoder(w).Encode(p); err != nil {
	//		return
	//	}
	//})
	//router.HandleFunc("/custom-idp/auth", idp.handleAuth)
	//router.HandleFunc("/custom-idp/login", idp.handleLogin)
	//router.HandleFunc("/api/token", idp.handleToken)
	//router.HandleFunc("/jwks", idp.handleJWKS)

	idp.Server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: router,
	}
	l, err := net.Listen("tcp", idp.Server.Addr)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	go idp.Server.Serve(l)

	return idp, nil
}

type AuthResponse struct {
	Email    string `json:",omitempty"`
	Query    string
	LoginURL string
}

func (i *IdentityProvider) handleAuth(w http.ResponseWriter, req *http.Request) {
	v := &AuthResponse{
		Query:    req.URL.Query().Encode(),
		LoginURL: i.Issuer + "login",
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

	id := q.Get("id")
	if v := i.providerStorage.authRequests[id]; v != nil {
		v.AuthTime = time.Now()
		v.Email = authResponse.Email
	}
	redirectURL, err := url.Parse(fmt.Sprintf("http://%s/authorize/callback", req.Host))
	rq := redirectURL.Query()
	rq.Set("id", id)
	redirectURL.RawQuery = rq.Encode()

	http.Redirect(w, req, redirectURL.String(), http.StatusFound)
}

type providerStorage struct {
	signingKey       crypto.PrivateKey
	signingPublicKey crypto.PublicKey
	Clients          []op.Client

	authRequests map[string]*authRequest
}

var _ op.Storage = (*providerStorage)(nil)

func newProviderStorage(signingKey crypto.PrivateKey) *providerStorage {
	var publicKey crypto.PublicKey
	pubKeyInterface, ok := signingKey.(interface {
		Public() crypto.PublicKey
	})
	if ok {
		publicKey = pubKeyInterface.Public()
	}
	return &providerStorage{
		signingKey:       signingKey,
		signingPublicKey: publicKey,
		authRequests:     make(map[string]*authRequest),
	}
}

func (p *providerStorage) CreateAuthRequest(_ context.Context, req *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	randStr := make([]byte, 16)
	for i := range randStr {
		randStr[i] = letters[mrand.Intn(len(letters))]
	}
	id := string(randStr)
	p.authRequests[id] = &authRequest{
		ID:           id,
		ClientID:     req.ClientID,
		ResponseType: req.ResponseType,
		State:        req.State,
		Nonce:        req.Nonce,
		RedirectURL:  req.RedirectURI,
		Scopes:       req.Scopes,
	}

	return p.authRequests[id], nil
}

func (p *providerStorage) AuthRequestByID(_ context.Context, id string) (op.AuthRequest, error) {
	if v := p.authRequests[id]; v == nil {
		return nil, xerrors.Errorf("not found")
	} else {
		return v, nil
	}
}

func (p *providerStorage) AuthRequestByCode(_ context.Context, code string) (op.AuthRequest, error) {
	for _, v := range p.authRequests {
		if v.Code == code {
			return v, nil
		}
	}

	return nil, xerrors.Errorf("code is not found")
}

func (p *providerStorage) SaveAuthCode(_ context.Context, id string, code string) error {
	if v := p.authRequests[id]; v == nil {
		return xerrors.Errorf("auth request id is not found")
	} else {
		v.Code = code
	}

	return nil
}

func (p *providerStorage) DeleteAuthRequest(_ context.Context, id string) error {
	delete(p.authRequests, id)
	return nil
}

func (p *providerStorage) CreateAccessToken(_ context.Context, _ op.TokenRequest) (string, time.Time, error) {
	return "test-access-token", time.Now().Add(24 * time.Hour), nil
}

func (p *providerStorage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshToken string, expiration time.Time, err error) {
	//TODO implement me
	panic("implement me")
}

func (p *providerStorage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	//TODO implement me
	panic("implement me")
}

func (p *providerStorage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	//TODO implement me
	panic("implement me")
}

func (p *providerStorage) RevokeToken(ctx context.Context, token string, userID string, clientID string) *oidc.Error {
	//TODO implement me
	panic("implement me")
}

func (p *providerStorage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (userID string, tokenID string, err error) {
	//TODO implement me
	panic("implement me")
}

func (p *providerStorage) SigningKey(_ context.Context) (op.SigningKey, error) {
	var algo jose.SignatureAlgorithm
	switch v := p.signingKey.(type) {
	case *ecdsa.PrivateKey:
		switch v.Params().BitSize {
		case 256:
			algo = jose.ES256
		case 384:
			algo = jose.ES384
		case 512:
			algo = jose.ES512
		}
	case *rsa.PrivateKey:
		algo = jose.RS256
	}
	return &signingKey{id: "e2eframework", algo: algo, key: p.signingKey}, nil
}

func (p *providerStorage) SignatureAlgorithms(_ context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

func (p *providerStorage) KeySet(_ context.Context) ([]op.Key, error) {
	return []op.Key{
		&signingPublicKey{
			signingKey: signingKey{
				id:   "e2eframework",
				algo: jose.RS256,
			},
			key: p.signingPublicKey,
		},
	}, nil
}

func (p *providerStorage) GetClientByClientID(_ context.Context, clientID string) (op.Client, error) {
	for _, v := range p.Clients {
		if v.GetID() == clientID {
			return v, nil
		}
	}

	return nil, xerrors.Errorf("client is not found")
}

func (p *providerStorage) AuthorizeClientIDSecret(_ context.Context, clientID, clientSecret string) error {
	for _, v := range p.Clients {
		if v.GetID() == clientID {
			// TODO: Should check the client secret
			return nil
		}
	}

	return xerrors.Errorf("client is not found")
}

func (p *providerStorage) SetUserinfoFromScopes(
	_ context.Context,
	userinfo *oidc.UserInfo,
	userID, clientID string,
	scopes []string,
) error {
	for _, v := range scopes {
		switch v {
		case "email":
			userinfo.Email = userID
			userinfo.Subject = userID
		}
	}
	return nil
}

func (p *providerStorage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	//TODO implement me
	panic("implement me")
}

func (p *providerStorage) SetIntrospectionFromToken(ctx context.Context, userinfo *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	//TODO implement me
	panic("implement me")
}

func (p *providerStorage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]interface{}, error) {
	// TODO:
	return nil, nil
}

func (p *providerStorage) GetKeyByIDAndClientID(ctx context.Context, keyID, userID string) (*jose.JSONWebKey, error) {
	//TODO implement me
	panic("implement me")
}

func (p *providerStorage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	//TODO implement me
	panic("implement me")
}

func (p *providerStorage) Health(ctx context.Context) error {
	//TODO implement me
	panic("implement me")
}

type signingKey struct {
	id   string
	algo jose.SignatureAlgorithm
	key  crypto.PrivateKey
}

var _ op.SigningKey = (*signingKey)(nil)

func (s *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm {
	return s.algo
}

func (s *signingKey) Key() any {
	return s.key
}

func (s *signingKey) ID() string {
	return s.id
}

type signingPublicKey struct {
	signingKey
	key crypto.PublicKey
}

var _ op.Key = (*signingPublicKey)(nil)

func (s *signingPublicKey) Algorithm() jose.SignatureAlgorithm {
	return s.algo
}

func (s *signingPublicKey) Use() string {
	return "sig"
}

func (s *signingPublicKey) Key() any {
	return s.key
}

type authRequest struct {
	ID           string
	Email        string
	Code         string
	ClientID     string
	ResponseType oidc.ResponseType
	State        string
	Nonce        string
	RedirectURL  string
	Scopes       []string
	AuthTime     time.Time
}

func (a *authRequest) GetID() string {
	return a.ID
}

func (a *authRequest) GetACR() string {
	return ""
}

func (a *authRequest) GetAMR() []string {
	return nil
}

func (a *authRequest) GetAudience() []string {
	return []string{}
}

func (a *authRequest) GetAuthTime() time.Time {
	return a.AuthTime
}

func (a *authRequest) GetClientID() string {
	return a.ClientID
}

func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	//TODO implement me
	panic("implement me")
}

func (a *authRequest) GetNonce() string {
	return a.Nonce
}

func (a *authRequest) GetRedirectURI() string {
	return a.RedirectURL
}

func (a *authRequest) GetResponseType() oidc.ResponseType {
	return a.ResponseType
}

func (a *authRequest) GetResponseMode() oidc.ResponseMode {
	return oidc.ResponseModeQuery
}

func (a *authRequest) GetScopes() []string {
	return a.Scopes
}

func (a *authRequest) GetState() string {
	return a.State
}

func (a *authRequest) GetSubject() string {
	return a.Email
}

func (a *authRequest) Done() bool {
	return true
}

type client struct {
	ID          string
	RedirectURL []string
	Login       string
}

var _ op.Client = &client{}

func (c *client) GetID() string {
	return c.ID
}

func (c *client) RedirectURIs() []string {
	return c.RedirectURL
}

func (c *client) PostLogoutRedirectURIs() []string {
	//TODO implement me
	panic("implement me")
}

func (c *client) ApplicationType() op.ApplicationType {
	return op.ApplicationTypeWeb
}

func (c *client) AuthMethod() oidc.AuthMethod {
	return oidc.AuthMethodBasic
}

func (c *client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c *client) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode}
}

func (c *client) LoginURL(s string) string {
	return c.Login + "?id=" + s
}

func (c *client) AccessTokenType() op.AccessTokenType {
	return op.AccessTokenTypeJWT
}

func (c *client) IDTokenLifetime() time.Duration {
	return 24 * time.Hour
}

func (c *client) DevMode() bool {
	return true
}

func (c *client) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	// TODO:
	return func(scopes []string) []string {
		return scopes
	}
}

func (c *client) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	// TODO:
	return func(scopes []string) []string {
		return []string{}
	}
}

func (c *client) IsScopeAllowed(scope string) bool {
	//TODO implement me
	panic("implement me")
}

func (c *client) IDTokenUserinfoClaimsAssertion() bool {
	return true
}

func (c *client) ClockSkew() time.Duration {
	return time.Minute
}

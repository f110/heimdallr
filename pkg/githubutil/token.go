package githubutil

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-github/v32/github"
	"go.f110.dev/xerrors"
)

type TokenProvider struct {
	pat string
	app *App
}

func (p *TokenProvider) Token(ctx context.Context) (string, error) {
	if p.pat != "" {
		return p.pat, nil
	}
	if p.app != nil {
		return p.app.Token(ctx)
	}

	return "", xerrors.New("does not configure with any credential")
}

type App struct {
	appID          int64
	installationID int64
	privateKey     *rsa.PrivateKey

	// client works as GitHub app.
	client       *github.Client
	token        string
	tokenExpires time.Time
}

func NewApp(appId, installationId int64, keyFile string) (*App, error) {
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	a := &App{
		appID:          appId,
		installationID: installationId,
		privateKey:     privateKey,
	}
	a.client = github.NewClient(&http.Client{Transport: newAppTransport(http.DefaultTransport, a)})
	return a, nil
}

func (a *App) Token(ctx context.Context) (string, error) {
	if !a.tokenExpires.IsZero() && time.Now().Before(a.tokenExpires) {
		// the token is valid
		return a.token, nil
	}

	token, _, err := a.client.Apps.CreateInstallationToken(ctx, a.installationID, nil)
	if err != nil {
		return "", xerrors.WithStack(err)
	}
	a.token = token.GetToken()
	a.tokenExpires = token.GetExpiresAt().Add(-1 * time.Minute)
	return a.token, nil
}

func (a *App) JWT() (string, error) {
	claims := &jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		Issuer:    strconv.FormatInt(a.appID, 10),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	sign, err := token.SignedString(a.privateKey)
	if err != nil {
		return "", xerrors.WithStack(err)
	}
	return sign, err
}

type Transport struct {
	http.RoundTripper
	tokenProvider *TokenProvider
}

var _ http.RoundTripper = &Transport{}

func NewTransport(tr http.RoundTripper, tokenProvider *TokenProvider) *Transport {
	return &Transport{RoundTripper: tr, tokenProvider: tokenProvider}
}

func NewTransportWithApp(tr http.RoundTripper, app *App) *Transport {
	return &Transport{RoundTripper: tr, tokenProvider: &TokenProvider{app: app}}
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())

	token, err := t.tokenProvider.Token(req.Context())
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/vnd.github.machine-man-preview+json")
	}
	for _, v := range req.Header["Accept"] {
		if strings.HasSuffix(v, "json") {
			req.Header.Add("Accept", "application/vnd.github.machine-man-preview+json")
			break
		}
	}

	return t.RoundTripper.RoundTrip(req)
}

type appTransport struct {
	http.RoundTripper
	app *App
}

var _ http.RoundTripper = &appTransport{}

func newAppTransport(tr http.RoundTripper, app *App) *appTransport {
	return &appTransport{RoundTripper: tr, app: app}
}

func (t *appTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())

	token, err := t.app.JWT()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	return t.RoundTripper.RoundTrip(req)
}

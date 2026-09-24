package dockercredential

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/auth/token"
	"go.f110.dev/heimdallr/pkg/config/userconfig"
)

// Username is the username returned to docker. heimdallr doesn't verify the username of Basic authorization.
const Username = "heimdallr"

var (
	ErrCredentialsNotFound = xerrors.New("credentials not found in native keychain")
	ErrMissingServerURL    = xerrors.New("no credentials server URL")
)

type Credential struct {
	ServerURL string
	Username  string
	Secret    string
}

// Helper implements the protocol of docker credential helpers.
// Helper returns the token for any server because the helper is expected to be configured by credHelpers of the docker config for specific registries.
type Helper struct {
	userDir      *userconfig.UserDir
	requestToken func(endpoint string) (string, time.Time, error)
}

func New() (*Helper, error) {
	uc, err := userconfig.New()
	if err != nil {
		return nil, err
	}

	return &Helper{
		userDir: uc,
		requestToken: func(endpoint string) (string, time.Time, error) {
			return token.NewClient(net.DefaultResolver).RequestToken(endpoint, "", false)
		},
	}, nil
}

// Run executes the action which is specified by args and returns the exit code.
func (h *Helper) Run(args []string, in io.Reader, out io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(out, "Usage: docker-credential-heimdallr <get|store|erase|list>")
		return 1
	}

	var err error
	switch args[0] {
	case "get":
		err = h.get(in, out)
	case "store", "erase":
		_, err = io.Copy(io.Discard, in)
	case "list":
		err = json.NewEncoder(out).Encode(map[string]string{})
	default:
		err = xerrors.Newf("unknown credential action `%s`", args[0])
	}
	if err != nil {
		fmt.Fprintln(out, err.Error())
		return 1
	}

	return 0
}

func (h *Helper) get(in io.Reader, out io.Writer) error {
	b, err := io.ReadAll(in)
	if err != nil {
		return xerrors.WithStack(err)
	}
	serverURL := strings.TrimSpace(string(b))
	if serverURL == "" {
		return ErrMissingServerURL
	}

	t, err := h.userDir.GetToken()
	if err != nil {
		return err
	}
	if t == nil || t.Endpoint == "" {
		return ErrCredentialsNotFound
	}
	secret := t.Token
	if t.IsExpired() {
		newToken, expiresAt, err := h.requestToken(t.Endpoint)
		if err != nil {
			return err
		}
		if err := h.userDir.SetToken(t.Endpoint, newToken, expiresAt); err != nil {
			return err
		}
		secret = newToken
	}

	return json.NewEncoder(out).Encode(&Credential{ServerURL: serverURL, Username: Username, Secret: secret})
}

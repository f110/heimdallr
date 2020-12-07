package token

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	NewClient("")
}

func TestClient_GetToken(t *testing.T) {
	tmpDir := t.TempDir()

	err := os.Mkdir(filepath.Join(tmpDir, Directory), 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = ioutil.WriteFile(filepath.Join(tmpDir, Directory, "token"), []byte("test-token"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	prevHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer func() {
		os.Setenv("HOME", prevHome)
	}()
	c := NewClient("token")
	gotToken, err := c.GetToken()
	if err != nil {
		t.Fatal(err)
	}
	if gotToken != "test-token" {
		t.Fatalf("got token but not expected value: %s", gotToken)
	}
}

func TestClient_RequestToken(t *testing.T) {
	forTestMock = true
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)

	u, err := url.Parse(ClientRedirectUrl)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf(":%s", u.Port()), 10*time.Millisecond)
			if err != nil {
				continue
			}
			conn.Close()
			break
		}

		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%s?code=%s", u.Port(), "test-code"), nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
	}()

	gotCode := ""
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		v := req.URL.Query()
		gotCode = v.Get("code")

		token := &ExchangeResponse{
			AccessToken: t.Name(),
		}
		if err := json.NewEncoder(w).Encode(token); err != nil {
			t.Fatal(err)
		}
	}))

	c := NewClient("token")
	gotToken, err := c.RequestToken(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if gotToken != t.Name() {
		t.Fatalf("got token but not expected value: %s", gotToken)
	}
	if gotCode != "test-code" {
		t.Errorf("got code is unexpected: %s", gotCode)
	}
}

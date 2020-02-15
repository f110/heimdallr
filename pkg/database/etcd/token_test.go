package etcd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/f110/lagrangian-proxy/pkg/database"
)

func TestNewTemporaryToken(t *testing.T) {
	token := NewTemporaryToken(client)
	if token == nil {
		t.Fatal("NewTemporaryToken should return a value")
	}
}

func TestTemporaryToken_IssueToken(t *testing.T) {
	token := NewTemporaryToken(client)

	code, err := token.NewCode(context.Background(), "test@example.com", "ch", "plain")
	if err != nil {
		t.Fatal(err)
	}
	codes, err := token.AllCodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 1 {
		t.Errorf("Expect got 1 code: %d codes", len(codes))
	}

	t.Run("Failed verify", func(t *testing.T) {
		t.Parallel()

		_, err = token.IssueToken(context.Background(), code.Code, "failure")
		if err == nil {
			t.Error("Expect occurred an error")
		}
	})

	t.Run("Unknown code", func(t *testing.T) {
		t.Parallel()

		_, err = token.IssueToken(context.Background(), "unknown", "ch")
		if err == nil {
			t.Error("Expect occurred an error")
		}
	})

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		tk, err := token.IssueToken(context.Background(), code.Code, "ch")
		if err != nil {
			t.Fatal(err)
		}

		if tk.Token == "" {
			t.Error("Token is an empty string")
		}

		got, err := token.FindToken(context.Background(), tk.Token)
		if err != nil {
			t.Fatal(err)
		}
		if got.UserId != "test@example.com" {
			t.Error("Unexpected UserId")
		}
		_, err = token.FindToken(context.Background(), "unknown")
		if err != database.ErrTokenNotFound {
			t.Error("Expect ErrTokenNotFound")
		}

		tokens, err := token.AllTokens(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(tokens) != 1 {
			t.Errorf("Expect got 1 token: %d tokens", len(tokens))
		}
	})
}

func TestTemporaryToken_DeleteCode(t *testing.T) {
	token := NewTemporaryToken(client)

	code, err := token.NewCode(context.Background(), "test@example.com", "ch", "plain")
	if err != nil {
		t.Fatal(err)
	}
	err = token.DeleteCode(context.Background(), code.Code)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTemporaryToken_DeleteToken(t *testing.T) {
	token := NewTemporaryToken(client)

	s := sha256.New()
	s.Write([]byte("ch"))
	result := s.Sum(nil)
	code, err := token.NewCode(context.Background(), "test@example.com", base64.StdEncoding.EncodeToString(result), "S256")
	if err != nil {
		t.Fatal(err)
	}
	tk, err := token.IssueToken(context.Background(), code.Code, "ch")
	if err != nil {
		t.Fatal(err)
	}

	err = token.DeleteToken(context.Background(), tk.Token)
	if err != nil {
		t.Fatal(err)
	}
}

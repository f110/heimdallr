package auth

import (
	"testing"
)

func TestNewAccessToken(t *testing.T) {
	at, err := NewAccessToken("test-name", "test-userid", "test-issuer")
	if err != nil {
		t.Fatal(err)
	}

	if at.Name != "test-name" {
		t.Errorf("expect Name is test-name: %v", at.Name)
	}
	if at.UserId != "test-userid" {
		t.Errorf("expect UserId is test-userid: %v", at.UserId)
	}
	if at.Issuer != "test-issuer" {
		t.Errorf("expect Issuer is test-issuer: %v", at.Issuer)
	}
	if at.Value == "" {
		t.Error("token is nil")
	}
}

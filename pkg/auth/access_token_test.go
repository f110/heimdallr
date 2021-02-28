package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAccessToken(t *testing.T) {
	at, err := NewAccessToken("test-name", "test-userid", "test-issuer")
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "test-name", at.Name)
	assert.Equal(t, "test-userid", at.UserId)
	assert.Equal(t, "test-issuer", at.Issuer)
	assert.NotEmpty(t, at.Value)
}

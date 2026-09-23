package configv2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAccessProxy_GetTokenExpiration(t *testing.T) {
	assert.Equal(t, 8*time.Hour, (&AccessProxy{}).GetTokenExpiration())
	assert.Equal(t, time.Hour, (&AccessProxy{TokenExpiration: &Duration{Duration: time.Hour}}).GetTokenExpiration())
}

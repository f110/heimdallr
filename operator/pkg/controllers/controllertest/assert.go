package controllertest

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.f110.dev/heimdallr/operator/pkg/controllers/controllerbase"
)

func AssertRetry(t *testing.T, err error) {
	assert.True(t, controllerbase.ShouldRetry(err))
}

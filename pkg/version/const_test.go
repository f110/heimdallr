package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsNewer(t *testing.T) {
	cases := []struct {
		V    string
		Base string
		Want bool
	}{
		{V: "v0.10.0", Base: "v0.9.1", Want: true},
		{V: "v0.9.1", Base: "v0.9.1", Want: false},
		{V: "v0.9.0", Base: "v0.9.1", Want: false},
		{V: "v0.10.0", Base: "latest", Want: false},
		{V: "v0.10.0", Base: "development", Want: false},
		{V: "latest", Base: "v0.9.1", Want: false},
		{V: "", Base: "v0.9.1", Want: false},
	}

	for _, tc := range cases {
		t.Run(tc.V+"_"+tc.Base, func(t *testing.T) {
			assert.Equal(t, tc.Want, IsNewer(tc.V, tc.Base))
		})
	}
}

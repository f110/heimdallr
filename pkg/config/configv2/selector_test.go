package configv2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertUpstream(t *testing.T, sel *HTTPBackendSelector, path, expect string) {
	b := sel.Find(path)
	if expect != "" {
		require.NotNil(t, b, "Path is %s", path)
		assert.Equal(t, expect, b.Upstream, "Path is %s", path)
	} else {
		assert.Nil(t, b)
	}
}

func TestHTTPBackendSelector(t *testing.T) {
	sel := NewHTTPBackendSelector()
	sel.Add(&HTTPBackend{Path: "/api", Upstream: "api"})
	sel.Add(&HTTPBackend{Path: "/web", Upstream: "web", Default: true})
	sel.Add(&HTTPBackend{Path: "/dashboard/ios", Upstream: "ios"})
	sel.Add(&HTTPBackend{Path: "/dashboard/android", Upstream: "android"})

	assertUpstream(t, sel, "/api", "api")
	assertUpstream(t, sel, "/api/new", "api")
	assertUpstream(t, sel, "/web/pc/blog/new", "web")
	assertUpstream(t, sel, "/web", "web")
	assertUpstream(t, sel, "/dashboard/ios", "ios")
	assertUpstream(t, sel, "/dashboard/ios/panic", "ios")
	assertUpstream(t, sel, "/dashboard/android", "android")
	assertUpstream(t, sel, "/", "web")
	assertUpstream(t, sel, "", "web")

	sel = NewHTTPBackendSelector()
	sel.Add(&HTTPBackend{Path: "/", Upstream: "ok"})
	sel.Add(&HTTPBackend{Path: "/second", Upstream: "second"})

	assertUpstream(t, sel, "/api", "ok")
	assertUpstream(t, sel, "", "ok")
	assertUpstream(t, sel, "/second/ok", "second")
}

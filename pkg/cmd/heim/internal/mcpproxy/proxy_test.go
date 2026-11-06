package mcpproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeTokens struct {
	mu      sync.Mutex
	token   string
	renewed []string
	next    string
}

func (f *fakeTokens) Token(_ context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.token, nil
}

func (f *fakeTokens) Renew(_ context.Context, rejected string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renewed = append(f.renewed, rejected)
	f.token = f.next
	return f.token, nil
}

type testProxy struct {
	t      *testing.T
	in     *io.PipeWriter
	out    *bufio.Reader
	cancel context.CancelFunc
	done   chan error
}

func startProxy(t *testing.T, endpoint string, tokens Tokens) *testProxy {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	p := &testProxy{t: t, in: inW, out: bufio.NewReader(outR), cancel: cancel, done: make(chan error, 1)}
	go func() {
		p.done <- New(endpoint, http.DefaultClient, tokens).Run(ctx, inR, outW)
	}()
	t.Cleanup(func() {
		cancel()
		inW.Close()
		outR.Close()
	})
	return p
}

func (p *testProxy) send(msg string) {
	_, err := io.WriteString(p.in, msg+"\n")
	require.NoError(p.t, err)
}

func (p *testProxy) receive() map[string]any {
	line, err := p.out.ReadBytes('\n')
	require.NoError(p.t, err)
	m := map[string]any{}
	require.NoError(p.t, json.Unmarshal(line, &m), string(line))
	return m
}

func (p *testProxy) close() {
	require.NoError(p.t, p.in.Close())
	select {
	case err := <-p.done:
		require.NoError(p.t, err)
	case <-time.After(5 * time.Second):
		p.t.Fatal("the proxy didn't stop")
	}
}

func TestProxy_JSON(t *testing.T) {
	var mu sync.Mutex
	var requests []*http.Request
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		requests = append(requests, req)
		mu.Unlock()

		if req.Method == http.MethodDelete {
			return
		}
		msg := &message{}
		require.NoError(t, json.NewDecoder(req.Body).Decode(msg))
		switch msg.Method {
		case "initialize":
			w.Header().Set(headerSessionID, "session-1")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25"}}`, msg.ID)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			fmt.Fprintf(w, "{\n  \"jsonrpc\": \"2.0\",\n  \"id\": %s,\n  \"result\": {}\n}", msg.ID)
		}
	}))
	defer s.Close()

	p := startProxy(t, s.URL, &fakeTokens{token: "token-1"})
	p.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	assert.Equal(t, map[string]any{"jsonrpc": "2.0", "id": float64(1), "result": map[string]any{"protocolVersion": "2025-11-25"}}, p.receive())
	p.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	p.send(`{"jsonrpc":"2.0","id":"a","method":"tools/list"}`)
	assert.Equal(t, map[string]any{"jsonrpc": "2.0", "id": "a", "result": map[string]any{}}, p.receive())
	p.close()

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, requests, 4)
	for _, req := range requests {
		assert.Equal(t, "Bearer token-1", req.Header.Get("Authorization"))
	}
	assert.Empty(t, requests[0].Header.Get(headerSessionID))
	assert.Empty(t, requests[0].Header.Get(headerProtocolVersion))
	assert.Equal(t, "application/json, text/event-stream", requests[0].Header.Get("Accept"))
	for _, req := range requests[1:] {
		assert.Equal(t, "session-1", req.Header.Get(headerSessionID))
		assert.Equal(t, "2025-11-25", req.Header.Get(headerProtocolVersion))
	}
	assert.Equal(t, http.MethodDelete, requests[3].Method)
}

func TestProxy_SSE(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		msg := &message{}
		require.NoError(t, json.NewDecoder(req.Body).Decode(msg))
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, ": comment\n\n")
		fmt.Fprint(w, "event: message\nid: 1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n")
		fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\r\ndata: \"id\":%s,\"result\":{}}\r\n\r\n", msg.ID)
	}))
	defer s.Close()

	p := startProxy(t, s.URL, &fakeTokens{token: "token-1"})
	p.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`)
	assert.Equal(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/progress"}, p.receive())
	assert.Equal(t, map[string]any{"jsonrpc": "2.0", "id": float64(1), "result": map[string]any{}}, p.receive())
	p.close()
}

func TestProxy_SSEWithoutResponse(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n")
	}))
	defer s.Close()

	p := startProxy(t, s.URL, &fakeTokens{token: "token-1"})
	p.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`)
	assert.Equal(t, "notifications/progress", p.receive()["method"])
	res := p.receive()
	assert.Equal(t, float64(1), res["id"])
	assert.Equal(t, float64(jsonRPCInternalError), res["error"].(map[string]any)["code"])
	p.close()
}

func TestProxy_Unauthorized(t *testing.T) {
	var mu sync.Mutex
	var gotTokens []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		gotTokens = append(gotTokens, req.Header.Get("Authorization"))
		mu.Unlock()
		if req.Header.Get("Authorization") != "Bearer new-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer s.Close()

	tokens := &fakeTokens{token: "old-token", next: "new-token"}
	p := startProxy(t, s.URL, tokens)
	p.send(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	assert.Equal(t, map[string]any{"jsonrpc": "2.0", "id": float64(1), "result": map[string]any{}}, p.receive())
	p.close()

	assert.Equal(t, []string{"Bearer old-token", "Bearer new-token"}, gotTokens)
	assert.Equal(t, []string{"old-token"}, tokens.renewed)
}

func TestProxy_UnauthorizedAfterRenew(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer s.Close()

	tokens := &fakeTokens{token: "old-token", next: "new-token"}
	p := startProxy(t, s.URL, tokens)
	p.send(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	res := p.receive()
	assert.Equal(t, float64(1), res["id"])
	assert.Contains(t, res["error"].(map[string]any)["message"], "401")
	p.close()

	assert.Equal(t, []string{"old-token"}, tokens.renewed)
}

func TestProxy_ProtocolVersionInMeta(t *testing.T) {
	gotVersion := make(chan string, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotVersion <- req.Header.Get(headerProtocolVersion)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
	}))
	defer s.Close()

	p := startProxy(t, s.URL, &fakeTokens{token: "token-1"})
	p.send(`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`)
	assert.Equal(t, float64(-32601), p.receive()["error"].(map[string]any)["code"])
	p.close()

	assert.Equal(t, "2026-07-28", <-gotVersion)
}

func TestProxy_InvalidMessage(t *testing.T) {
	p := startProxy(t, "http://127.0.0.1:1", &fakeTokens{token: "token-1"})
	p.send(`{invalid`)
	res := p.receive()
	assert.Nil(t, res["id"])
	assert.Equal(t, float64(jsonRPCParseError), res["error"].(map[string]any)["code"])
	p.close()
}

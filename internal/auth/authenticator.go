package auth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// Authenticator authenticates against a target and returns an AuthSession.
type Authenticator interface {
	Authenticate(ctx context.Context) (*AuthSession, error)
}

// NewAuthenticator creates the appropriate Authenticator based on the AuthConfig.
// baseURL is the target URL; classified is optional endpoint classification.
func NewAuthenticator(cfg types.AuthConfig, baseURL string, classified *types.ClassifiedEndpoints) Authenticator {
	if cfg.NoAuth {
		return &noopAuth{}
	}

	base := strings.TrimRight(baseURL, "/")
	client := newHTTPClient()

	// Static token / direct header / direct cookie injection
	if cfg.Token != "" || (cfg.Username == "" && cfg.Password == "" && (len(cfg.Headers) > 0 || len(cfg.Cookies) > 0)) {
		return &TokenAuthenticator{cfg: cfg}
	}

	method := strings.ToLower(cfg.Method)
	switch method {
	case "bearer", "cookie", "header":
		return &TokenAuthenticator{cfg: cfg}
	case "form":
		return &FormAuthenticator{cfg: cfg, client: client, baseURL: base, classified: classified}
	case "json":
		return &FormAuthenticator{cfg: cfg, client: client, baseURL: base, classified: classified, forceJSON: true}
	default: // "auto" or unset
		return &AutoLoginAuthenticator{cfg: cfg, client: client, baseURL: base, classified: classified}
	}
}

// noopAuth returns an empty session (no-op).
type noopAuth struct{}

func (n *noopAuth) Authenticate(_ context.Context) (*AuthSession, error) {
	return NewAuthSession(), nil
}

// newHTTPClient creates an HTTP client suitable for auth operations.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		// Follow redirects for form login flows
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}
}

// collectLoginURLs returns a deduplicated list of login endpoints to try.
func collectLoginURLs(baseURL, loginURL string, classified *types.ClassifiedEndpoints) []string {
	seen := make(map[string]bool)
	var urls []string

	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}

	// Explicit login URL has highest priority
	add(loginURL)

	// Classified login endpoints
	if classified != nil {
		for _, ep := range classified.Login {
			add(ep.URL)
		}
	}

	// Common fallbacks
	common := []string{
		"/login", "/api/login", "/auth/login", "/api/auth/login",
		"/rest/user/login", "/signin", "/api/signin",
		"/api/Users/login", "/oauth/token", "/api/authenticate",
		"/api/session", "/api/token",
	}
	for _, p := range common {
		add(baseURL + p)
	}

	return urls
}

// extractAuthToken finds a JWT or auth token in a JSON response body.
// Searches top-level and one level deep.
func extractAuthToken(body string) string {
	fields := []string{
		"token", "access_token", "accessToken", "jwt", "id_token",
		"auth_token", "authToken", "session_token", "sessionToken",
		"idToken", "bearerToken",
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		// Fallback: string scan
		for _, f := range fields {
			pattern := `"` + f + `":"`
			if idx := strings.Index(body, pattern); idx >= 0 {
				start := idx + len(pattern)
				end := strings.Index(body[start:], `"`)
				if end > 10 {
					return body[start : start+end]
				}
			}
		}
		return ""
	}

	// Top-level fields
	for _, f := range fields {
		if val, ok := data[f]; ok {
			if s, ok := val.(string); ok && len(s) > 10 {
				return s
			}
		}
	}

	// One level deep (e.g., {"authentication": {"token": "..."}})
	for _, val := range data {
		if nested, ok := val.(map[string]interface{}); ok {
			for _, f := range fields {
				if v, ok := nested[f]; ok {
					if s, ok := v.(string); ok && len(s) > 10 {
						return s
					}
				}
			}
		}
	}

	return ""
}

// isLoginSuccess heuristically determines if a login response indicates success.
func isLoginSuccess(resp *http.Response, body string) bool {
	lower := strings.ToLower(body)

	switch resp.StatusCode {
	case 200:
		// Token in body is a strong signal
		if extractAuthToken(body) != "" {
			return true
		}
		// Session-like cookie
		for _, c := range resp.Cookies() {
			name := strings.ToLower(c.Name)
			if isSessionCookieName(name) {
				return true
			}
		}
		// Failure indicators
		if strings.Contains(lower, `"error"`) ||
			strings.Contains(lower, "invalid") ||
			strings.Contains(lower, "incorrect") ||
			strings.Contains(lower, "unauthorized") ||
			strings.Contains(lower, "bad credentials") {
			return false
		}
		// Optimistic: 200 with any cookie and no error
		return len(resp.Cookies()) > 0
	case 301, 302, 303:
		// Check redirect location — login failures often redirect back to login page
		loc := strings.ToLower(resp.Header.Get("Location"))
		if strings.Contains(loc, "error") ||
			strings.Contains(loc, "failed") ||
			strings.Contains(loc, "invalid") ||
			strings.Contains(loc, "login?") ||
			strings.Contains(loc, "signin?") {
			return false
		}
		// Redirect with session cookie + non-error location = success
		for _, c := range resp.Cookies() {
			if isSessionCookieName(strings.ToLower(c.Name)) {
				return true
			}
		}
	}
	return false
}

// isSessionCookieName returns true for cookie names commonly used for sessions.
func isSessionCookieName(name string) bool {
	keywords := []string{"session", "token", "auth", "sid", "jwt", "connect.sid", "access"}
	for _, kw := range keywords {
		if strings.Contains(name, kw) {
			return true
		}
	}
	return false
}

// buildSessionFromResponse extracts auth state from a successful login response.
func buildSessionFromResponse(resp *http.Response, body string) *AuthSession {
	sess := NewAuthSession()

	// Extract Bearer token from body
	if tok := extractAuthToken(body); tok != "" {
		sess.SetHeader("Authorization", "Bearer "+tok)
	}

	// Extract all session cookies
	for _, c := range resp.Cookies() {
		sess.SetCookie(c.Name, c.Value)
	}

	return sess
}

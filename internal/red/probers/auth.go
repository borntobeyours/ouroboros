package probers

import (
	"context"
	"fmt"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// AuthProber tests for authentication and access control vulnerabilities.
type AuthProber struct{}

func (p *AuthProber) Name() string { return "auth" }

func (p *AuthProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	if currentClassified != nil {
		cfg.Classified = currentClassified
	}
	var findings []types.Finding

	findings = append(findings, p.testAdminAccessWithoutAuth(cfg)...)
	findings = append(findings, p.testPasswordChangeFlaws(cfg)...)
	findings = append(findings, p.testRegistrationRoleEscalation(cfg)...)
	findings = append(findings, p.testUserEnumeration(cfg)...)
	findings = append(findings, p.testRateLimiting(cfg)...)

	return findings
}

func (p *AuthProber) testAdminAccessWithoutAuth(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil {
		return findings
	}

	for _, ep := range cfg.Classified.Admin {
		path := extractPath(ep.URL)

		// Try without auth
		status, _, respBody, err := cfg.DoRequest("GET", ep.URL, nil, nil)
		if err != nil {
			continue
		}

		// Skip SPA catch-all responses
		if cfg.IsSPAResponse(ep.URL) {
			continue
		}

		if status == 200 && len(respBody) > 50 {
			lowerBody := strings.ToLower(respBody)
			// Must contain actual admin data, not just SPA HTML
			hasAdminContent := !strings.Contains(lowerBody, "<!doctype html>") ||
				strings.Contains(lowerBody, "version") ||
				strings.Contains(lowerBody, "config") ||
				strings.Contains(lowerBody, `"status"`) ||
				strings.Contains(lowerBody, `"data"`)

			if hasAdminContent {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("Missing Authentication - Admin Endpoint (%s)", path),
					"High",
					fmt.Sprintf("The admin endpoint %s is accessible without authentication and returns real admin data.", path),
					path,
					"GET",
					"CWE-306",
					fmt.Sprintf(`curl %s`, ep.URL),
					fmt.Sprintf("HTTP %d - Response: %s", status, truncate(respBody, 200)),
					"auth_bypass",
					0,
				))
			}
		}
	}

	return findings
}

func (p *AuthProber) testPasswordChangeFlaws(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil {
		return findings
	}

	// Look for password change/reset endpoints in discovered user data endpoints
	for _, ep := range cfg.Classified.UserData {
		path := extractPath(ep.URL)
		lowerPath := strings.ToLower(path)

		if !strings.Contains(lowerPath, "password") && !strings.Contains(lowerPath, "change-password") &&
			!strings.Contains(lowerPath, "reset") {
			continue
		}

		// Test password change via GET (should never work)
		getURL := ep.URL
		if strings.Contains(lowerPath, "change-password") || strings.Contains(lowerPath, "reset-password") {
			if !strings.Contains(getURL, "?") {
				getURL += "?new=test123&repeat=test123"
			}
			status, _, respBody, err := cfg.DoRequest("GET", getURL, nil, nil)
			if err == nil && status == 200 {
				findings = append(findings, MakeFinding(
					"Broken Authentication - Password Change via GET Request",
					"High",
					"Password can be changed via GET request, which is logged in browser history, proxy logs, and referrer headers.",
					path,
					"GET",
					"CWE-620",
					fmt.Sprintf(`curl "%s"`, getURL),
					fmt.Sprintf("HTTP %d - Password change accepted via GET: %s", status, truncate(respBody, 200)),
					"auth_bypass",
					0,
				))
			}
		}
	}

	// Test password reset via login endpoints
	for _, ep := range cfg.Classified.Login {
		base := strings.Split(ep.URL, "?")[0]
		baseParts := strings.Split(base, "/")
		if len(baseParts) > 1 {
			baseParts[len(baseParts)-1] = "reset-password"
		}
		resetURL := strings.Join(baseParts, "/")

		body := `{"email":"test@test.com","answer":"anything","new":"hacked123","repeat":"hacked123"}`
		status, _, respBody, err := cfg.DoRequest("POST", resetURL,
			strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
		if err != nil {
			continue
		}

		if status == 200 {
			findings = append(findings, MakeFinding(
				"Password Reset Bypass",
				"Critical",
				"Password reset succeeded with a guessed/incorrect security answer.",
				extractPath(resetURL),
				"POST",
				"CWE-640",
				fmt.Sprintf(`curl -X POST %s -H "Content-Type: application/json" -d '%s'`, resetURL, body),
				fmt.Sprintf("HTTP %d - Password reset successful: %s", status, truncate(respBody, 200)),
				"auth_bypass",
				0,
			))
		} else if strings.Contains(respBody, "Wrong answer") || strings.Contains(respBody, "answer") {
			findings = append(findings, MakeFinding(
				"Weak Password Reset - Security Question Enumeration",
				"Medium",
				"The password reset mechanism confirms whether an email exists and uses guessable security questions.",
				extractPath(resetURL),
				"POST",
				"CWE-640",
				fmt.Sprintf(`curl -X POST %s -H "Content-Type: application/json" -d '%s'`, resetURL, body),
				fmt.Sprintf("HTTP %d - Response confirms account existence: %s", status, truncate(respBody, 200)),
				"auth_bypass",
				0,
			))
		}
		break // Only need to test one
	}

	return findings
}

func (p *AuthProber) testRegistrationRoleEscalation(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil {
		return findings
	}

	// Look for user creation endpoints
	for _, ep := range cfg.Classified.API {
		path := extractPath(ep.URL)
		lowerPath := strings.ToLower(path)

		if !strings.Contains(lowerPath, "user") && !strings.Contains(lowerPath, "register") &&
			!strings.Contains(lowerPath, "signup") {
			continue
		}

		// Don't test endpoints with IDs (they're for specific users)
		segments := strings.Split(path, "/")
		hasID := false
		for _, s := range segments {
			if isNumericStr(s) {
				hasID = true
				break
			}
		}
		if hasID {
			continue
		}

		// Try to register with admin role
		body := `{"email":"test_role@test.com","password":"test12345","passwordRepeat":"test12345","role":"admin"}`
		status, _, respBody, err := cfg.DoRequest("POST", ep.URL,
			strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
		if err != nil {
			continue
		}

		if (status == 200 || status == 201) && (strings.Contains(respBody, "admin") || strings.Contains(respBody, "role")) {
			findings = append(findings, MakeFinding(
				"Privilege Escalation via Registration",
				"Critical",
				"New user registration accepts a 'role' parameter that allows creating admin accounts directly.",
				path,
				"POST",
				"CWE-269",
				fmt.Sprintf(`curl -X POST %s -H "Content-Type: application/json" -d '%s'`, ep.URL, body),
				fmt.Sprintf("HTTP %d - User created with role: %s", status, truncate(respBody, 200)),
				"auth_bypass",
				0,
			))
		}
		break // Only test the first user creation endpoint
	}

	return findings
}

func (p *AuthProber) testUserEnumeration(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil {
		return findings
	}

	// Test user enumeration via login error messages
	for _, ep := range cfg.Classified.Login {
		path := extractPath(ep.URL)

		validEmail := `{"email":"admin@admin.com","password":"wrongpassword"}`
		invalidEmail := `{"email":"nonexistent_user_xyz@test.com","password":"wrongpassword"}`

		s1, _, r1, e1 := cfg.DoRequest("POST", ep.URL,
			strings.NewReader(validEmail), map[string]string{"Content-Type": "application/json"})
		s2, _, r2, e2 := cfg.DoRequest("POST", ep.URL,
			strings.NewReader(invalidEmail), map[string]string{"Content-Type": "application/json"})

		if e1 == nil && e2 == nil && s1 == s2 && r1 != r2 {
			findings = append(findings, MakeFinding(
				"User Enumeration via Login Error Messages",
				"Low",
				"Different error messages for valid vs invalid emails allow attackers to enumerate valid user accounts.",
				path,
				"POST",
				"CWE-204",
				fmt.Sprintf(`curl -X POST %s -H "Content-Type: application/json" -d '%s'`, ep.URL, validEmail),
				fmt.Sprintf("Valid email response: %s | Invalid email response: %s", truncate(r1, 100), truncate(r2, 100)),
				"auth_bypass",
				0,
			))
		}
		break // Only test the first login endpoint
	}

	return findings
}

func (p *AuthProber) testRateLimiting(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil {
		return findings
	}

	// Test rate limiting on login endpoints
	for _, ep := range cfg.Classified.Login {
		path := extractPath(ep.URL)
		payload := `{"email":"test@test.com","password":"wrongpassword"}`
		blocked := false

		for i := 0; i < 10; i++ {
			status, _, _, err := cfg.DoRequest("POST", ep.URL, strings.NewReader(payload),
				map[string]string{"Content-Type": "application/json"})
			if err != nil {
				break
			}
			if status == 429 {
				blocked = true
				break
			}
		}

		if !blocked {
			findings = append(findings, MakeFinding(
				"Missing Rate Limiting on Login Endpoint",
				"Medium",
				"The login endpoint does not implement rate limiting, allowing brute-force password attacks.",
				path,
				"POST",
				"CWE-307",
				fmt.Sprintf(`for i in $(seq 1 10); do curl -s -o /dev/null -w "%%{http_code}" -X POST %s -H "Content-Type: application/json" -d '%s'; done`, ep.URL, payload),
				"10 rapid login attempts accepted without rate limiting (no HTTP 429)",
				"auth_bypass",
				0,
			))
		}
		break // Only test the first login endpoint
	}

	return findings
}

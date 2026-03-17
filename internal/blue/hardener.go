package blue

// SecurityHeaders returns recommended HTTP security headers.
func SecurityHeaders() map[string]string {
	return map[string]string{
		"Content-Security-Policy":   "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
	}
}

// HardeningChecklist returns a general web application hardening checklist.
func HardeningChecklist() []string {
	return []string{
		"Enable HTTPS with TLS 1.2+ and strong cipher suites",
		"Set all security headers (CSP, HSTS, X-Frame-Options, etc.)",
		"Implement rate limiting on all endpoints",
		"Enable CSRF protection on state-changing operations",
		"Use HttpOnly and Secure flags on all cookies",
		"Implement proper CORS configuration",
		"Disable directory listing and verbose error messages",
		"Remove server version headers and debug endpoints",
		"Implement proper session management with timeout",
		"Enable logging and monitoring for security events",
		"Use parameterized queries for all database operations",
		"Validate and sanitize all user input on the server side",
		"Implement proper file upload validation if applicable",
		"Apply principle of least privilege for service accounts",
		"Keep all dependencies up to date and scan for known CVEs",
	}
}

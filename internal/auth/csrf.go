package auth

import (
	"net/http"
	"regexp"
	"strings"
)

var (
	// <meta name="csrf-token" content="...">
	metaCSRFRe = regexp.MustCompile(`(?i)<meta[^>]+name=["'](?:csrf[-_]?token|_token|xsrf[-_]?token)["'][^>]+content=["']([^"']+)["']`)
	// <meta content="..." name="csrf-token">
	metaCSRFRe2 = regexp.MustCompile(`(?i)<meta[^>]+content=["']([^"']+)["'][^>]+name=["'](?:csrf[-_]?token|_token|xsrf[-_]?token)["']`)
	// <input type="hidden" name="_csrf" value="...">
	inputCSRFRe = regexp.MustCompile(`(?i)<input[^>]+type=["']hidden["'][^>]+name=["'](?:_?csrf[-_]?(?:token)?|_token|xsrf[-_]?(?:token)?|authenticity_token)["'][^>]+value=["']([^"']+)["']`)
	// alternate order of attributes
	inputCSRFRe2 = regexp.MustCompile(`(?i)<input[^>]+name=["'](?:_?csrf[-_]?(?:token)?|_token|xsrf[-_]?(?:token)?|authenticity_token)["'][^>]+value=["']([^"']+)["']`)
)

// ExtractCSRFFromHTML extracts a CSRF token from an HTML body.
// Returns empty string if none is found.
func ExtractCSRFFromHTML(html string) string {
	for _, re := range []*regexp.Regexp{metaCSRFRe, metaCSRFRe2, inputCSRFRe, inputCSRFRe2} {
		if m := re.FindStringSubmatch(html); len(m) > 1 {
			if tok := strings.TrimSpace(m[1]); tok != "" {
				return tok
			}
		}
	}
	return ""
}

// ExtractCSRFFromResponse extracts a CSRF token from HTTP response headers,
// cookies, or body. Returns the token value and the field/header name to use
// when submitting the form.
func ExtractCSRFFromResponse(resp *http.Response, body string) (token, fieldName string) {
	// Check response headers
	headerNames := []string{
		"X-CSRF-Token", "X-CSRFToken", "X-Xsrf-Token", "XSRF-TOKEN",
		"csrf-token", "csrfToken", "_csrf",
	}
	for _, h := range headerNames {
		if val := resp.Header.Get(h); val != "" {
			return val, h
		}
	}
	// Check Set-Cookie for XSRF-TOKEN (Angular pattern)
	for _, c := range resp.Cookies() {
		upper := strings.ToUpper(c.Name)
		if upper == "XSRF-TOKEN" || upper == "CSRF-TOKEN" || upper == "_CSRF" {
			return c.Value, c.Name
		}
	}
	// Fall back to HTML parsing
	tok := ExtractCSRFFromHTML(body)
	if tok != "" {
		return tok, "_csrf"
	}
	return "", ""
}

// CommonCSRFFieldNames returns common CSRF form field names.
func CommonCSRFFieldNames() []string {
	return []string{
		"_csrf", "csrf_token", "csrfToken", "_token",
		"authenticity_token", "xsrf_token",
	}
}

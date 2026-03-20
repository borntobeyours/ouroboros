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
	inputCSRFRe = regexp.MustCompile(`(?i)<input[^>]+type=["']hidden["'][^>]+name=["'](?:_?csrf[-_]?(?:token)?|_token|xsrf[-_]?(?:token)?|authenticity_token|user_token|[a-z_]*token[a-z_]*)["'][^>]+value=["']([^"']+)["']`)
	// alternate order of attributes
	inputCSRFRe2 = regexp.MustCompile(`(?i)<input[^>]+name=["'](?:_?csrf[-_]?(?:token)?|_token|xsrf[-_]?(?:token)?|authenticity_token|user_token|[a-z_]*token[a-z_]*)["'][^>]+value=["']([^"']+)["']`)
)

// ExtractCSRFFromHTML extracts a CSRF token from an HTML body.
// Returns empty string if none is found.
func ExtractCSRFFromHTML(html string) string {
	tok, _ := ExtractCSRFFromHTMLWithField(html)
	return tok
}

// inputCSRFFieldRe captures both the field name and value from hidden inputs
// that look like CSRF tokens.
var inputCSRFFieldRe = regexp.MustCompile(`(?i)<input[^>]+type=["']hidden["'][^>]+name=["']([a-z_]*(?:csrf|token|xsrf|authenticity)[a-z_]*)["'][^>]+value=["']([^"']+)["']`)
var inputCSRFFieldRe2 = regexp.MustCompile(`(?i)<input[^>]+name=["']([a-z_]*(?:csrf|token|xsrf|authenticity)[a-z_]*)["'][^>]+type=["']hidden["'][^>]+value=["']([^"']+)["']`)
var inputCSRFFieldRe3 = regexp.MustCompile(`(?i)<input[^>]+name=["']([a-z_]*(?:csrf|token|xsrf|authenticity)[a-z_]*)["'][^>]+value=["']([^"']+)["']`)

// ExtractCSRFFromHTMLWithField extracts a CSRF token AND its field name from HTML.
func ExtractCSRFFromHTMLWithField(html string) (token, fieldName string) {
	// Try meta tags first (no field name)
	for _, re := range []*regexp.Regexp{metaCSRFRe, metaCSRFRe2} {
		if m := re.FindStringSubmatch(html); len(m) > 1 {
			if tok := strings.TrimSpace(m[1]); tok != "" {
				return tok, "_csrf"
			}
		}
	}

	// Try hidden input fields — these capture both name and value
	for _, re := range []*regexp.Regexp{inputCSRFFieldRe, inputCSRFFieldRe2, inputCSRFFieldRe3} {
		if m := re.FindStringSubmatch(html); len(m) > 2 {
			name := strings.TrimSpace(m[1])
			tok := strings.TrimSpace(m[2])
			if tok != "" && name != "" {
				return tok, name
			}
		}
	}

	return "", ""
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
	tok, field := ExtractCSRFFromHTMLWithField(body)
	if tok != "" {
		if field == "" {
			field = "_csrf"
		}
		return tok, field
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

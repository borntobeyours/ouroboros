package target

import (
	"net/url"
	"strings"
)

// Scope manages what's in-scope for scanning.
type Scope struct {
	baseURL    *url.URL
	baseHost   string
	allowedExt []string
	deniedExt  []string
}

// NewScope creates a scope from the target URL.
func NewScope(targetURL string) (*Scope, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	return &Scope{
		baseURL:  u,
		baseHost: u.Host,
		deniedExt: []string{
			".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
			".css", ".woff", ".woff2", ".ttf", ".eot",
			".mp4", ".mp3", ".avi", ".mov",
			".pdf", ".zip", ".tar", ".gz",
		},
	}, nil
}

// InScope checks if a URL is within the scan scope.
func (s *Scope) InScope(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Host != "" && u.Host != s.baseHost {
		return false
	}
	lower := strings.ToLower(u.Path)
	for _, ext := range s.deniedExt {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	return true
}

// BaseURL returns the base URL.
func (s *Scope) BaseURL() string {
	return s.baseURL.String()
}

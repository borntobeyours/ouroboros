package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// AuthSession holds all authentication state for a scan session.
// It is safe for concurrent use.
type AuthSession struct {
	Cookies map[string]string // cookie name → value
	Headers map[string]string // header name → value
	Method  string            // authentication method used (form/json/bearer/cookie/header/auto)
	mu      sync.RWMutex
	refresh func(context.Context) (*AuthSession, error) // optional re-auth function
}

// NewAuthSession creates an empty auth session.
func NewAuthSession() *AuthSession {
	return &AuthSession{
		Cookies: make(map[string]string),
		Headers: make(map[string]string),
	}
}

// IsEmpty returns true if the session has no auth data.
func (s *AuthSession) IsEmpty() bool {
	if s == nil {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.Cookies) == 0 && len(s.Headers) == 0
}

// IsValid returns true if the session contains at least some auth data.
func (s *AuthSession) IsValid() bool {
	return !s.IsEmpty()
}

// SetCookie adds or updates a cookie in the session.
func (s *AuthSession) SetCookie(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Cookies[name] = value
}

// SetHeader adds or updates a header in the session.
func (s *AuthSession) SetHeader(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Headers[name] = value
}

// SetRefresh stores a function used to re-authenticate when the session expires.
func (s *AuthSession) SetRefresh(fn func(context.Context) (*AuthSession, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh = fn
}

// Refresh re-authenticates and updates the session in place.
// Returns an error if no refresh function is configured or re-auth fails.
func (s *AuthSession) Refresh(ctx context.Context) error {
	s.mu.RLock()
	fn := s.refresh
	s.mu.RUnlock()
	if fn == nil {
		return fmt.Errorf("no refresh function configured")
	}
	newSess, err := fn(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Cookies = newSess.Cookies
	s.Headers = newSess.Headers
	return nil
}

// InjectInto adds auth cookies and headers to an HTTP request.
func (s *AuthSession) InjectInto(req *http.Request) {
	if s == nil {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}
	for name, value := range s.Cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
}

// CookieHeader returns a Cookie header value string (name=val; name2=val2).
func (s *AuthSession) CookieHeader() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	parts := make([]string, 0, len(s.Cookies))
	for k, v := range s.Cookies {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, "; ")
}

// Update overwrites this session's state with data from another session.
func (s *AuthSession) Update(other *AuthSession) {
	if other == nil {
		return
	}
	other.mu.RLock()
	newCookies := make(map[string]string, len(other.Cookies))
	newHeaders := make(map[string]string, len(other.Headers))
	for k, v := range other.Cookies {
		newCookies[k] = v
	}
	for k, v := range other.Headers {
		newHeaders[k] = v
	}
	other.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.Cookies = newCookies
	s.Headers = newHeaders
}

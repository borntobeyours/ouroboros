package auth

import (
	"context"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// TokenAuthenticator handles static token / header / cookie injection.
// No actual login request is made — the provided credentials are used directly.
type TokenAuthenticator struct {
	cfg types.AuthConfig
}

// Authenticate builds an AuthSession from the static auth config.
func (t *TokenAuthenticator) Authenticate(_ context.Context) (*AuthSession, error) {
	sess := NewAuthSession()
	sess.Method = "static"

	// Bearer token takes highest priority
	if t.cfg.Token != "" {
		sess.SetHeader("Authorization", "Bearer "+t.cfg.Token)
		sess.Method = "bearer"
	}

	// Custom headers (e.g. "X-API-Key: abc123")
	for k, v := range t.cfg.Headers {
		sess.SetHeader(k, v)
		if sess.Method == "static" {
			sess.Method = "header"
		}
	}

	// Custom cookies
	for k, v := range t.cfg.Cookies {
		sess.SetCookie(k, v)
		if sess.Method == "static" {
			sess.Method = "cookie"
		}
	}

	return sess, nil
}

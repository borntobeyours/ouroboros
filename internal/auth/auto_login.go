package auth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// defaultCredentials are tried when no credentials are explicitly provided.
var defaultCredentials = [][2]string{
	{"admin", "admin"},
	{"admin@admin.com", "admin"},
	{"admin", "password"},
	{"admin@admin.com", "password"},
	{"admin", "admin123"},
	{"test", "test"},
	{"test@test.com", "test"},
	{"user", "user"},
	{"root", "root"},
	{"guest", "guest"},
}

// AutoLoginAuthenticator detects the login type and tries multiple auth strategies.
type AutoLoginAuthenticator struct {
	cfg        types.AuthConfig
	client     *http.Client
	baseURL    string
	classified *types.ClassifiedEndpoints
}

// Authenticate tries all known authentication strategies in order.
func (a *AutoLoginAuthenticator) Authenticate(ctx context.Context) (*AuthSession, error) {
	// Strategy 1: Use explicit credentials with form/JSON login
	if a.cfg.Username != "" && a.cfg.Password != "" {
		form := &FormAuthenticator{
			cfg:        a.cfg,
			client:     a.client,
			baseURL:    a.baseURL,
			classified: a.classified,
		}
		sess, err := form.Authenticate(ctx)
		if err == nil && !sess.IsEmpty() {
			sess.Method = "auto-form"
			// Wire up re-auth
			sess.SetRefresh(func(rCtx context.Context) (*AuthSession, error) {
				return form.Authenticate(rCtx)
			})
			return sess, nil
		}
	}

	// Strategy 2: Try default credentials against discovered login endpoints
	sess, err := a.tryDefaultCredentials(ctx)
	if err == nil && !sess.IsEmpty() {
		sess.Method = "auto-default-creds"
		return sess, nil
	}

	return nil, fmt.Errorf("auto-login failed: no working credentials found")
}

// tryDefaultCredentials tries well-known default credential pairs.
func (a *AutoLoginAuthenticator) tryDefaultCredentials(ctx context.Context) (*AuthSession, error) {
	loginURLs := collectLoginURLs(a.baseURL, a.cfg.LoginURL, a.classified)
	if len(loginURLs) == 0 {
		return nil, fmt.Errorf("no login endpoints discovered")
	}

	// Limit to first 5 login endpoints to avoid being too slow
	if len(loginURLs) > 5 {
		loginURLs = loginURLs[:5]
	}

	for _, loginURL := range loginURLs {
		for _, cred := range defaultCredentials {
			username, password := cred[0], cred[1]

			// Try JSON login first
			form := &FormAuthenticator{
				cfg: types.AuthConfig{
					Username: username,
					Password: password,
					LoginURL: loginURL,
				},
				client:     a.client,
				baseURL:    a.baseURL,
				classified: a.classified,
			}

			sess, err := form.tryJSONLogin(ctx, loginURL, username, password)
			if err == nil && !sess.IsEmpty() {
				return sess, nil
			}

			// Try HTML form login
			sess, err = form.tryFormLogin(ctx, loginURL, username, password)
			if err == nil && !sess.IsEmpty() {
				return sess, nil
			}
		}
	}

	return nil, fmt.Errorf("default credentials failed against %d endpoints", len(loginURLs))
}

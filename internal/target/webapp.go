package target

import "github.com/borntobeyours/ouroboros/pkg/types"

// WebApp represents a web application target with discovered endpoints.
type WebApp struct {
	Target    types.Target
	Scope     *Scope
	Endpoints []types.Endpoint
}

// NewWebApp creates a new WebApp target.
func NewWebApp(t types.Target) (*WebApp, error) {
	scope, err := NewScope(t.URL)
	if err != nil {
		return nil, err
	}
	return &WebApp{
		Target:    t,
		Scope:     scope,
		Endpoints: make([]types.Endpoint, 0),
	}, nil
}

// AddEndpoints adds discovered endpoints to the webapp.
func (w *WebApp) AddEndpoints(eps []types.Endpoint) {
	seen := make(map[string]bool)
	for _, e := range w.Endpoints {
		seen[e.URL+"|"+e.Method] = true
	}
	for _, e := range eps {
		key := e.URL + "|" + e.Method
		if !seen[key] {
			w.Endpoints = append(w.Endpoints, e)
			seen[key] = true
		}
	}
}

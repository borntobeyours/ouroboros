package plugin

import "github.com/ouroboros-security/ouroboros/pkg/types"

// AttackPlugin defines the interface for community attack technique plugins.
type AttackPlugin interface {
	// Name returns the plugin name.
	Name() string
	// Description returns what this plugin tests for.
	Description() string
	// Run executes the attack technique against the given endpoints.
	Run(target types.Target, endpoints []types.Endpoint) ([]types.Finding, error)
}

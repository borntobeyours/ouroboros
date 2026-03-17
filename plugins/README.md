# Ouroboros Plugins

Community-contributed attack technique plugins.

## Creating a Plugin

Implement the `plugin.AttackPlugin` interface from `pkg/plugin/interface.go`:

```go
type AttackPlugin interface {
    Name() string
    Description() string
    Run(target types.Target, endpoints []types.Endpoint) ([]types.Finding, error)
}
```

Place your plugin in this directory and submit a PR.

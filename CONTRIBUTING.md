# Contributing to Ouroboros

Thanks for your interest in contributing to Ouroboros!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<you>/ouroboros.git`
3. Create a branch: `git checkout -b my-feature`
4. Make your changes
5. Run checks: `go vet ./... && go test ./...`
6. Commit and push
7. Open a pull request

## Building

```bash
go build ./cmd/ouroboros/
# or
make build
```

## Project Layout

```
cmd/ouroboros/     CLI entry point
internal/
  ai/              AI provider abstraction (OpenAI, Anthropic, Ollama)
  red/             Red AI agent + probers + exploit techniques
  blue/            Blue AI agent (analysis, patching, hardening)
  boss/            Final Boss validation
  engine/          Loop orchestrator + convergence detection
  memory/          SQLite-backed persistent store
  report/          Markdown/terminal report generation
  target/          Target discovery + scope management
pkg/types/         Shared types (Finding, Severity, Target)
pkg/plugin/        Plugin interface for custom probers
```

## Adding a Prober

Probers live in `internal/red/probers/`. Each prober implements the `Prober` interface:

```go
type Prober interface {
    Name() string
    Probe(ctx context.Context, target *types.Target, endpoints []string) []types.Finding
}
```

1. Create a new file in `internal/red/probers/`
2. Implement the `Prober` interface
3. Register it in `internal/red/agent.go`

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep probers independent — no cross-prober dependencies
- Every finding must include real HTTP evidence

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly via email rather than opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.

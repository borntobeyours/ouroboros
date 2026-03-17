# 🐍 Ouroboros

**Security that attacks itself until nothing can.**

Ouroboros is an AI-powered security scanner that uses adversarial AI loops to find and validate vulnerabilities. A Red AI attacks your application, a Blue AI generates fixes, then the Red AI attacks again — looping until convergence.

Every finding is backed by real HTTP evidence, not theoretical speculation.

## How It Works

```
┌─────────┐     findings      ┌──────────┐
│  Red AI  │ ───────────────► │  Blue AI  │
│ (Attack) │                  │ (Defend)  │
└─────────┘ ◄─────────────── └──────────┘
                patches
        ↻ Loop until convergence
```

1. **Red AI** crawls the target, runs 11 technique-specific probers, and uses AI-guided exploitation
2. **Blue AI** analyzes findings and generates patches/remediations
3. **Loop** — Red AI attacks again, trying to bypass Blue's fixes
4. **Convergence** — when no new vulnerabilities are found, the scan completes

## Features

- **11 Active Probers**: SQLi, XSS, IDOR, auth bypass, info leaks, injection, headers, file upload, SSRF, crypto, and more
- **AI-Guided Exploitation**: Multi-step exploit plans with adaptive retry
- **SPA Detection**: Fingerprints base URL to eliminate false positives from SPA catch-all routes
- **Authenticated Scanning**: Auto SQLi login bypass, then scans with JWT token
- **Self-Learning Memory**: SQLite-backed playbook of successful techniques
- **Real Evidence**: Every finding includes actual HTTP request/response proof

## Quick Start

```bash
# Install
go install github.com/borntobeyours/ouroboros/cmd/ouroboros@latest

# Or build from source
git clone https://github.com/borntobeyours/ouroboros.git
cd ouroboros
go build ./cmd/ouroboros/

# Scan a target (requires OpenAI API key)
export OPENAI_API_KEY=sk-...
./ouroboros scan http://localhost:3000

# With options
./ouroboros scan http://localhost:3000 \
  --max-loops 3 \
  --provider openai \
  --model gpt-4o \
  -o report.md
```

## Scan Results (OWASP Juice Shop)

```
Target:    http://localhost:3000
Duration:  2m33s
Loops:     3
Converged: true

Total Findings: 81
Confirmed:      79/81 (97.5%)

  Critical: 4
  High:     25
  Medium:   30
  Low:      17
  Info:     5
```

### Sample Findings
- **SQLi Login Bypass** — `' OR 1=1--` gets admin JWT token
- **UNION-based SQLi** — dumps entire SQLite schema via product search
- **Stored XSS** — persistent payload in product reviews
- **IDOR** — access any user's basket, profile, payment cards
- **XXE** — XML entity injection in B2B order endpoint
- **JWT Key Exposure** — public key readable, enables token forgery
- **Null Byte Bypass** — download restricted files via `%2500` encoding
- **Privilege Escalation** — register with `role=admin` accepted

## AI Providers

| Provider | Models | Notes |
|----------|--------|-------|
| OpenAI | gpt-4o, gpt-4-turbo | Default, best results |
| Anthropic | claude-sonnet, claude-opus | Opus reserved for Final Boss mode |
| Ollama | Any local model | Free, runs locally |

```bash
# Use different providers
./ouroboros scan http://target --provider anthropic --model claude-sonnet-4-20250514
./ouroboros scan http://target --provider ollama --model llama3
```

## Architecture

```
cmd/ouroboros/          CLI entry point
internal/
  ai/                  AI provider abstraction (OpenAI, Anthropic, Ollama)
  red/                 Red AI agent
    probers/           11 technique-specific active probers
    techniques/        SQLi, XSS, auth bypass implementations
    active_exploit.go  AI-guided multi-step exploitation
    crawler.go         SPA-aware web crawler
  blue/                Blue AI agent (patch generation)
  boss/                Final Boss validation (stub)
  engine/              Ouroboros loop engine + convergence detection
  memory/              SQLite persistent store
  report/              Markdown report generation
pkg/types/             Shared types (Finding, Patch, Target, etc.)
```

## Roadmap

- [ ] Web dashboard (React)
- [ ] Final Boss mode (Opus-level AI validation)
- [ ] CI/CD pipeline integration
- [ ] Compliance report generation (SOC2, ISO27001)
- [ ] Plugin system for custom probers
- [ ] OpenRouter provider support

## License

Apache 2.0 — see [LICENSE](LICENSE)

---

*The serpent that eats its own tail. The more it attacks, the stronger it becomes.*

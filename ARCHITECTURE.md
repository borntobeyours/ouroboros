# Ouroboros Architecture

## Overview

Ouroboros is an AI-powered adversarial security scanner. It uses a Red AI vs Blue AI loop to iteratively discover and validate vulnerabilities in web applications.

## Core Loop

```
Target URL
    │
    ▼
┌──────────┐     ┌──────────┐     ┌──────────┐
│  RED AI   │────▶│ BLUE AI  │────▶│ RE-ATTACK│──┐
│ (Attack)  │     │  (Fix)   │     │(Escalate)│  │
└──────────┘     └──────────┘     └──────────┘  │
                                      │         │
                             no new   │  new    │
                             vulns    │  vulns  │
                               ▼      │         │
                         ┌─────────┐  │         │
                         │CONVERGE │◀─┘         │
                         │  CHECK  │────────────┘
                         └────┬────┘   (loop back)
                              │ converged
                              ▼
                        ┌──────────┐
                        │FINAL BOSS│
                        │(Optional)│
                        └──────────┘
```

1. **Red AI** crawls the target, runs active probers, and uses AI-guided exploitation
2. **Blue AI** analyzes findings and generates patches/remediations
3. **Re-Attack** — Red AI attacks again, trying to bypass Blue's fixes
4. **Convergence** — when no new vulnerabilities are found, the loop stops
5. **Final Boss** (optional) — a more powerful AI model validates all findings

## Project Structure

```
cmd/ouroboros/              CLI entry point (cobra)
internal/
  ai/                       AI provider abstraction
    provider.go               Provider interface
    anthropic.go              Claude API integration
    openai.go                 OpenAI API integration
    ollama.go                 Local model support (Ollama)
  engine/                   Loop orchestrator
    loop.go                   Main attack-fix-reattack loop
    convergence.go            Convergence detection logic
    session.go                Scan session management
  red/                      Red AI (Attacker)
    agent.go                  Red agent — orchestrates probers + AI analysis
    crawler.go                SPA-aware web crawler (colly)
    scanner.go                Vulnerability scanner
    exploiter.go              PoC exploit generator
    active_exploit.go         AI-guided multi-step exploitation
    probers/                  11 technique-specific active probers
      prober.go                 Prober interface
      sqli.go                   SQL injection (error, blind, UNION, time-based)
      xss.go                    Cross-site scripting (reflected, stored, DOM)
      idor.go                   Insecure direct object references
      auth.go                   Auth bypass, JWT manipulation, privilege escalation
      infoleaks.go              Information disclosure, sensitive file exposure
      injection.go              Command, NoSQL, XXE, SSTI injection
      headers.go                Missing security headers, CORS, cookie flags
      fileupload.go             Unrestricted upload, path traversal
      ssrf.go                   Server-side request forgery
      crypto.go                 Weak JWT, session tokens, hashing
      additional.go             Supplementary checks (rate limiting, business logic)
    techniques/               Attack technique implementations
      sqli.go, xss.go, ssrf.go, idor.go, auth_bypass.go, injection.go
  blue/                     Blue AI (Defender)
    agent.go                  Blue agent interface
    analyzer.go               Vulnerability analysis
    patcher.go                Auto-patch generator
    hardener.go               Configuration hardening suggestions
  boss/                     Final Boss (Validator)
    agent.go                  Boss agent interface
    arsenal.go                Advanced attack techniques
  memory/                   Self-learning memory (SQLite)
    store.go                  Finding/pattern storage
    playbook.go               Attack playbook builder
    bypass.go                 Bypass pattern library
  report/                   Report generation
    findings.go               Finding formatter (terminal + Markdown)
    diff.go                   Before/after comparison
    certificate.go            Ouroboros scan certificate
  target/                   Target management
    webapp.go                 Web application target
    discovery.go              Endpoint discovery + SPA detection
    scope.go                  Scope management
pkg/
  types/                    Shared types
    finding.go                Finding struct + helpers
    severity.go               Severity levels
    target.go                 Target struct
  plugin/                   Plugin system
    interface.go              Plugin interface for custom probers
```

## Key Design Decisions

- **SPA Detection**: The crawler fingerprints the target's base URL response. If an unknown path returns the same body (SPA catch-all), it is excluded from findings. This eliminates false positives.
- **Authenticated Scanning**: Red AI attempts SQLi login bypass to obtain a JWT token, then scans both unauthenticated and authenticated surfaces.
- **AI-Guided Exploitation**: After probers run, the AI analyzes ambiguous results and generates multi-step exploit plans with adaptive retry.
- **Provider-Agnostic AI**: All agents use a common `Provider` interface — swap between OpenAI, Anthropic, or Ollama with a CLI flag.
- **Evidence-Based Findings**: Every finding must include actual HTTP request/response proof. No theoretical or speculative findings.

## AI Integration

Each agent (Red, Blue, Boss) uses structured prompts. The AI layer handles:
- Vulnerability analysis and confirmation
- Exploit plan generation
- Patch/remediation generation
- Convergence reasoning

## Memory System

SQLite-backed local storage (`.ouroboros/` directory):
- **Attack Playbook** — successful attack patterns per target type
- **Bypass Library** — cataloged bypasses when Blue AI patches fail
- **Fix Patterns** — common fixes that actually work
- **Target Profiles** — learned framework characteristics

## Tech Stack

- **Language**: Go 1.22+
- **HTTP/Crawling**: net/http + colly
- **Storage**: SQLite (mattn/go-sqlite3)
- **CLI**: cobra
- **Output**: Terminal (fatih/color) + Markdown
- **License**: Apache 2.0

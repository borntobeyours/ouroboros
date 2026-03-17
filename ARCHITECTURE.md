# Ouroboros - AI Security Self-Learning Platform

## Tagline
*"Security that attacks itself until nothing can."*

## Overview
Open-source AI-powered continuous security platform with adversarial self-learning loop.
Red AI attacks → Blue AI fixes → Red AI re-attacks → Loop until convergence → Final Boss validation.

## Target Market
Startups without dedicated security teams. MVP focuses on web application scanning.

## Architecture

### Core Loop Engine
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

### Project Structure
```
ouroboros/
├── cmd/
│   └── ouroboros/          # CLI entry point
│       └── main.go
├── internal/
│   ├── engine/             # Core loop orchestrator
│   │   ├── loop.go         # Main attack-fix-reattack loop
│   │   ├── convergence.go  # Convergence detection logic
│   │   └── session.go      # Scan session management
│   ├── red/                # Red AI (Attacker)
│   │   ├── agent.go        # Red agent interface
│   │   ├── crawler.go      # Web crawler/spider
│   │   ├── scanner.go      # Vulnerability scanner
│   │   ├── exploiter.go    # PoC exploit generator
│   │   └── techniques/     # Attack technique modules
│   │       ├── sqli.go
│   │       ├── xss.go
│   │       ├── ssrf.go
│   │       ├── idor.go
│   │       ├── auth_bypass.go
│   │       └── injection.go
│   ├── blue/               # Blue AI (Defender)
│   │   ├── agent.go        # Blue agent interface
│   │   ├── analyzer.go     # Vulnerability analysis
│   │   ├── patcher.go      # Auto-patch generator
│   │   └── hardener.go     # Config hardening suggestions
│   ├── boss/               # Final Boss (Validator)
│   │   ├── agent.go        # Boss agent interface
│   │   └── arsenal.go      # Advanced attack techniques
│   ├── ai/                 # AI provider abstraction
│   │   ├── provider.go     # Interface for AI backends
│   │   ├── anthropic.go    # Claude API integration
│   │   ├── openai.go       # OpenAI integration
│   │   └── ollama.go       # Local model support
│   ├── memory/             # Self-learning memory
│   │   ├── store.go        # Finding/pattern storage
│   │   ├── playbook.go     # Attack playbook builder
│   │   └── bypass.go       # Bypass pattern library
│   ├── report/             # Report generation
│   │   ├── findings.go     # Finding formatter
│   │   ├── diff.go         # Before/after comparison
│   │   └── certificate.go  # Ouroboros certificate
│   └── target/             # Target management
│       ├── webapp.go       # Web application target
│       ├── discovery.go    # Endpoint discovery
│       └── scope.go        # Scope management
├── api/                    # REST API (for dashboard)
│   ├── server.go
│   ├── handlers/
│   │   ├── scan.go
│   │   ├── findings.go
│   │   └── reports.go
│   └── middleware/
├── web/                    # React dashboard (Phase 2)
│   └── README.md
├── pkg/                    # Public packages
│   ├── types/              # Shared types
│   │   ├── finding.go
│   │   ├── severity.go
│   │   └── target.go
│   └── plugin/             # Plugin system
│       └── interface.go
├── plugins/                # Community plugins (attack techniques)
│   └── README.md
├── testdata/               # Test fixtures
│   └── vulnerable-app/     # Intentionally vulnerable test app
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── LICENSE                 # Apache 2.0
└── README.md
```

### CLI Usage (Target UX)
```bash
# Basic scan with self-learning loop
ouroboros scan https://target.example.com

# Scan with max loop iterations
ouroboros scan https://target.example.com --max-loops 5

# Scan with Final Boss validation
ouroboros scan https://target.example.com --final-boss

# Set AI provider
ouroboros scan https://target.example.com --provider anthropic --model claude-sonnet-4-20250514

# Use local model (Ollama)
ouroboros scan https://target.example.com --provider ollama --model llama3

# View findings
ouroboros report --session <session-id>

# Interactive mode
ouroboros interactive https://target.example.com
```

### AI Integration
The AI layer is provider-agnostic. Each agent (Red, Blue, Boss) uses structured prompts:

**Red AI Prompt Pattern:**
```
You are a penetration tester. Your target is {url}.
Previous findings: {previous_findings}
Patches applied: {patches_from_blue}
Your goal: Find NEW vulnerabilities that weren't found before or that bypass the applied patches.
Focus areas: {owasp_top10_checklist}
Output: JSON array of findings with severity, description, PoC, and affected endpoint.
```

**Blue AI Prompt Pattern:**
```
You are a security engineer. Review these vulnerabilities:
{findings_from_red}
For each finding:
1. Confirm if it's a real vulnerability
2. Generate a specific patch/fix
3. Suggest hardening measures
Output: JSON with patch code, config changes, and hardening recommendations.
```

**Convergence Logic:**
- Track unique vulnerability signatures per loop
- Convergence = 0 new unique findings in a loop
- Min 2 loops required before convergence
- Max loops configurable (default: 10)

### Memory System (Self-Learning)
SQLite-based local storage:
- **Attack Playbook:** Successful attack patterns per target type
- **Bypass Library:** When Blue AI patch fails, catalog the bypass
- **Fix Patterns:** Common fix patterns that actually work
- **Target Profiles:** Learned characteristics of target frameworks

### MVP Scope (Week 1-2)
Focus on getting the core loop working:
1. CLI that accepts a target URL
2. Red AI: HTTP crawling + AI-powered vuln detection (OWASP Top 10)
3. Blue AI: Analyze findings + generate fix suggestions
4. Loop: Re-attack with knowledge of patches
5. Convergence: Stop when no new findings
6. Output: Terminal report with findings, fixes, loop stats

### Tech Decisions
- **Language:** Go 1.22+
- **AI SDK:** Direct HTTP to provider APIs (no heavy SDK deps)
- **HTTP Client:** net/http + colly for crawling
- **Storage:** SQLite (bbolt for embedded)
- **CLI:** cobra
- **Output:** Terminal (color) + JSON + Markdown
- **License:** Apache 2.0

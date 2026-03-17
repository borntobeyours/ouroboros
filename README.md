# Ouroboros

**Security that attacks itself until nothing can.**

Ouroboros is an open-source AI-powered security platform with a self-learning adversarial loop. Red AI attacks your web application, Blue AI generates fixes, then Red AI attacks again — looping until no new vulnerabilities are found.

## How It Works

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

1. **Red AI** crawls your target and uses AI to identify vulnerabilities (OWASP Top 10)
2. **Blue AI** analyzes each finding and generates specific patches and hardening recommendations
3. **Red AI re-attacks** with knowledge of the patches, trying to bypass them
4. **Loop** continues until convergence (0 new findings) or max iterations reached
5. **Final Boss** (optional) performs an elite validation scan with advanced techniques

All findings, patches, and attack patterns are stored in a local SQLite database for self-learning across sessions.

## Installation

### From Source

```bash
go install github.com/ouroboros-security/ouroboros/cmd/ouroboros@latest
```

### Build from Repository

```bash
git clone https://github.com/ouroboros-security/ouroboros.git
cd ouroboros
make build
```

### Docker

```bash
docker build -t ouroboros .
docker run --rm -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY ouroboros scan https://target.example.com
```

## Quick Start

Set your AI provider API key:

```bash
export ANTHROPIC_API_KEY=your-key-here
# or
export OPENAI_API_KEY=your-key-here
```

Run a scan:

```bash
# Basic scan with default settings (Anthropic Claude)
ouroboros scan https://target.example.com

# Limit to 5 loops
ouroboros scan https://target.example.com --max-loops 5

# Enable Final Boss validation
ouroboros scan https://target.example.com --final-boss

# Use OpenAI
ouroboros scan https://target.example.com --provider openai --model gpt-4o

# Use local model via Ollama
ouroboros scan https://target.example.com --provider ollama --model llama3

# Export report
ouroboros scan https://target.example.com -o report.json
ouroboros scan https://target.example.com -o report.md
```

View reports:

```bash
# List recent sessions
ouroboros report

# View a specific session
ouroboros report --session <session-id>
```

## Architecture

```
ouroboros/
├── cmd/ouroboros/          # CLI entry point (cobra)
├── internal/
│   ├── ai/                # AI provider abstraction (Anthropic, OpenAI, Ollama)
│   ├── red/               # Red AI attacker (crawler + AI scanner)
│   │   └── techniques/    # Attack technique payloads
│   ├── blue/              # Blue AI defender (analyzer + patcher)
│   ├── boss/              # Final Boss validator
│   ├── engine/            # Core loop orchestrator + convergence detection
│   ├── memory/            # SQLite self-learning store
│   ├── report/            # Terminal, JSON, and Markdown output
│   └── target/            # Target management and scope
├── pkg/
│   ├── types/             # Shared types (Finding, Severity, Target)
│   └── plugin/            # Plugin interface for community extensions
└── plugins/               # Community attack technique plugins
```

### AI Providers

Ouroboros supports multiple AI backends:

| Provider | Models | API Key Env Var |
|----------|--------|-----------------|
| Anthropic | Claude Sonnet (default), Claude Opus | `ANTHROPIC_API_KEY` |
| OpenAI | GPT-4o, GPT-4, etc. | `OPENAI_API_KEY` |
| Ollama | Any local model (llama3, etc.) | Not required |

### Self-Learning Memory

Ouroboros stores findings and patterns in a local SQLite database (`~/.ouroboros/ouroboros.db`):

- **Attack Playbook**: Successful attack patterns per technique
- **Bypass Library**: When patches fail, the bypass is cataloged
- **Session History**: All scan sessions with full finding history

## Supported Attack Techniques

- SQL Injection (error-based, blind, time-based, UNION)
- Cross-Site Scripting (reflected, stored, DOM-based)
- Server-Side Request Forgery (SSRF)
- Insecure Direct Object References (IDOR)
- Authentication/Authorization Bypass
- Command Injection
- Path Traversal / LFI
- Security Misconfigurations
- Sensitive Data Exposure
- And more via AI-powered analysis

## Important Notes

- Only scan targets you have explicit authorization to test
- The crawler respects `robots.txt` and includes rate limiting
- Findings are AI-generated assessments — always validate manually
- This tool is for authorized security testing and educational purposes only

## Contributing

Contributions are welcome! Areas where help is needed:

- New attack technique plugins
- Additional AI provider integrations
- Dashboard UI (React, Phase 2)
- Test coverage
- Documentation

Please open an issue first to discuss significant changes.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

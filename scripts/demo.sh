#!/usr/bin/env bash
# Demo script for asciinema recording
# Usage: asciinema rec -c "bash scripts/demo.sh" demo.cast
#   Then convert: agg demo.cast demo.gif

set -euo pipefail

DELAY=0.03

type_cmd() {
    local cmd="$1"
    for (( i=0; i<${#cmd}; i++ )); do
        printf '%s' "${cmd:$i:1}"
        sleep $DELAY
    done
    echo
    sleep 0.3
}

clear
sleep 0.5

echo "# 🐍 Ouroboros — AI Security Scanner Demo"
echo "# Target: OWASP Juice Shop (http://localhost:3000)"
echo ""
sleep 1

# Show help
type_cmd "ouroboros scan --help | head -15"
ouroboros scan --help 2>/dev/null | head -15
sleep 2

echo ""
echo "# Quick scan against Juice Shop"
type_cmd "ouroboros scan http://localhost:3000 --profile quick --rate 50"
sleep 0.5

# Run actual scan (quick profile = 1 loop, probers only for demo speed)
cd /Users/harjulianto/Projects/ouroboros
go run ./cmd/ouroboros/main.go scan http://localhost:3000 --max-loops 1 --rate 50 --no-recon 2>/dev/null || true

sleep 2

echo ""
echo "# Export as SARIF for CI/CD integration"
type_cmd "ouroboros report --format json | head -20"
sleep 1

echo ""
echo "# 🐍 Ouroboros — Security that attacks itself until nothing can."
sleep 2

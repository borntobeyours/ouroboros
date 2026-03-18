#!/usr/bin/env bash
# Ouroboros Performance Benchmark
# Tests scan speed against local targets (probers only, no AI)

set -euo pipefail

OUROBOROS="$(cd "$(dirname "$0")/.." && pwd)"
cd "$OUROBOROS"

# Build first
echo "Building ouroboros..."
go build -o /tmp/ouroboros-bench ./cmd/ouroboros/main.go

TARGETS=(
    "http://localhost:3000|OWASP JuiceShop"
    "http://localhost:4280|DVWA"
    "http://localhost:18080|WebGoat"
)

RESULTS_FILE="/tmp/ouroboros-benchmark-$(date +%Y%m%d-%H%M%S).md"

echo "# Ouroboros Performance Benchmark" > "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$RESULTS_FILE"
echo "Host: $(uname -srm)" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
echo "| Target | URLs Found | Findings | Scan Time | Requests | Req/sec |" >> "$RESULTS_FILE"
echo "|--------|-----------|----------|-----------|----------|---------|" >> "$RESULTS_FILE"

for entry in "${TARGETS[@]}"; do
    IFS='|' read -r url name <<< "$entry"
    
    echo ""
    echo "=== Benchmarking: $name ($url) ==="
    
    # Check if target is reachable
    if ! curl -s -o /dev/null --connect-timeout 3 "$url" 2>/dev/null; then
        echo "  SKIP: $name not reachable"
        echo "| $name | - | - | SKIP (unreachable) | - | - |" >> "$RESULTS_FILE"
        continue
    fi
    
    START=$(date +%s%N)
    
    # Run scan with 1 loop, no AI (probers only), capture output
    OUTPUT=$(/tmp/ouroboros-bench scan "$url" --loops 1 --provider none 2>&1 || true)
    
    END=$(date +%s%N)
    ELAPSED_MS=$(( (END - START) / 1000000 ))
    ELAPSED_SEC=$(echo "scale=1; $ELAPSED_MS / 1000" | bc)
    
    # Extract metrics from output
    URLS=$(echo "$OUTPUT" | grep -o 'Discovered [0-9]* URLs' | grep -o '[0-9]*' | head -1 || echo "?")
    FINDINGS=$(echo "$OUTPUT" | grep -o 'Total Findings: [0-9]*' | grep -o '[0-9]*' || echo "?")
    if [ "$FINDINGS" = "?" ]; then
        FINDINGS=$(echo "$OUTPUT" | grep -c '\[Critical\]\|\[High\]\|\[Medium\]\|\[Low\]' || echo "0")
    fi
    
    # Try to extract request count
    REQUESTS=$(echo "$OUTPUT" | grep -o 'requests: [0-9]*' | grep -o '[0-9]*' || echo "?")
    
    if [ "$REQUESTS" != "?" ] && [ "$ELAPSED_SEC" != "0" ] && [ "$ELAPSED_SEC" != "0.0" ]; then
        RPS=$(echo "scale=1; $REQUESTS / $ELAPSED_SEC" | bc)
    else
        RPS="?"
    fi
    
    echo "  Time: ${ELAPSED_SEC}s | URLs: $URLS | Findings: $FINDINGS"
    echo "| $name | $URLS | $FINDINGS | ${ELAPSED_SEC}s | $REQUESTS | $RPS |" >> "$RESULTS_FILE"
done

echo "" >> "$RESULTS_FILE"
echo "## Notes" >> "$RESULTS_FILE"
echo "- Single loop, probers only (no AI provider)" >> "$RESULTS_FILE"
echo "- Default rate limit (10 req/sec)" >> "$RESULTS_FILE"
echo "- All targets running locally via Docker" >> "$RESULTS_FILE"

echo ""
echo "=== Benchmark Complete ==="
echo "Results: $RESULTS_FILE"
cat "$RESULTS_FILE"

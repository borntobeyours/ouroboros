package report

import (
	"fmt"
	"strings"

	"github.com/ouroboros-security/ouroboros/pkg/types"
)

// GenerateLoopDiff creates a before/after comparison between loops.
func GenerateLoopDiff(loops []types.LoopResult) string {
	var sb strings.Builder

	sb.WriteString("Loop-by-Loop Progression:\n")
	sb.WriteString(strings.Repeat("-", 50) + "\n")

	totalFindings := 0
	for _, loop := range loops {
		totalFindings += loop.NewFindings
		sb.WriteString(fmt.Sprintf("Loop %d: +%d new findings (%d total) | %d patches | %s\n",
			loop.Iteration,
			loop.NewFindings,
			totalFindings,
			len(loop.Patches),
			loop.FinishedAt.Sub(loop.StartedAt).Round(1e9),
		))
	}

	return sb.String()
}

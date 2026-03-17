package engine

import "github.com/borntobeyours/ouroboros/pkg/types"

// ConvergenceChecker tracks unique findings and detects convergence.
type ConvergenceChecker struct {
	seenSignatures map[string]bool
	minLoops       int
}

// NewConvergenceChecker creates a new convergence checker.
func NewConvergenceChecker(minLoops int) *ConvergenceChecker {
	if minLoops < 2 {
		minLoops = 2
	}
	return &ConvergenceChecker{
		seenSignatures: make(map[string]bool),
		minLoops:       minLoops,
	}
}

// FilterNew returns only findings with signatures not seen before and marks them as seen.
func (c *ConvergenceChecker) FilterNew(findings []types.Finding) []types.Finding {
	var newFindings []types.Finding
	for _, f := range findings {
		sig := f.Signature()
		if !c.seenSignatures[sig] {
			c.seenSignatures[sig] = true
			newFindings = append(newFindings, f)
		}
	}
	return newFindings
}

// HasConverged returns true if no new findings were found and minimum loops have passed.
func (c *ConvergenceChecker) HasConverged(currentLoop int, newFindingsCount int) bool {
	if currentLoop < c.minLoops {
		return false
	}
	return newFindingsCount == 0
}

// TotalUnique returns the total number of unique findings seen.
func (c *ConvergenceChecker) TotalUnique() int {
	return len(c.seenSignatures)
}

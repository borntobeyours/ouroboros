package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// GenerateCertificate creates an Ouroboros security certificate.
func GenerateCertificate(session *types.ScanSession) string {
	var sb strings.Builder

	sb.WriteString(strings.Repeat("=", 60) + "\n")
	sb.WriteString("          OUROBOROS SECURITY CERTIFICATE\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	sb.WriteString(fmt.Sprintf("  Target:     %s\n", session.Config.Target.URL))
	sb.WriteString(fmt.Sprintf("  Session:    %s\n", session.ID))
	sb.WriteString(fmt.Sprintf("  Date:       %s\n", session.StartedAt.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("  Loops:      %d\n", len(session.Loops)))
	sb.WriteString(fmt.Sprintf("  Converged:  %v\n", session.Converged))
	sb.WriteString(fmt.Sprintf("  Findings:   %d\n", session.TotalFindings))
	sb.WriteString("\n")

	if session.Converged && session.TotalFindings == 0 {
		sb.WriteString("  Status: CLEAN - No vulnerabilities detected\n")
	} else if session.Converged {
		sb.WriteString("  Status: CONVERGED - All detected vulnerabilities documented\n")
	} else {
		sb.WriteString("  Status: INCOMPLETE - Scan did not converge\n")
	}

	sb.WriteString("\n" + strings.Repeat("=", 60) + "\n")

	return sb.String()
}

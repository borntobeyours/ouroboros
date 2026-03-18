package types

// ComplianceFramework identifies a compliance standard.
type ComplianceFramework string

const (
	FrameworkOWASP  ComplianceFramework = "OWASP Top 10 2021"
	FrameworkPCIDSS ComplianceFramework = "PCI DSS v4.0"
	FrameworkCIS    ComplianceFramework = "CIS Controls v8"
	FrameworkNIST   ComplianceFramework = "NIST 800-53"
)

// ComplianceMapping maps a finding to a specific compliance requirement.
type ComplianceMapping struct {
	Framework       ComplianceFramework `json:"framework"`
	RequirementID   string              `json:"requirement_id"`
	RequirementName string              `json:"requirement_name"`
	Description     string              `json:"description"`
}

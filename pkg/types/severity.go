package types

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity represents the severity level of a finding.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityInfo:     "Info",
	SeverityLow:      "Low",
	SeverityMedium:   "Medium",
	SeverityHigh:     "High",
	SeverityCritical: "Critical",
}

var severityFromString = map[string]Severity{
	"info":     SeverityInfo,
	"low":      SeverityLow,
	"medium":   SeverityMedium,
	"high":     SeverityHigh,
	"critical": SeverityCritical,
}

func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return "Unknown"
}

func ParseSeverity(s string) (Severity, error) {
	if sev, ok := severityFromString[strings.ToLower(s)]; ok {
		return sev, nil
	}
	return SeverityInfo, fmt.Errorf("unknown severity: %s", s)
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	parsed, err := ParseSeverity(str)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

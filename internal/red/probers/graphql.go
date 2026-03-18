package probers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// GraphQLProber detects and tests GraphQL endpoints for security vulnerabilities.
type GraphQLProber struct{}

func (p *GraphQLProber) Name() string { return "graphql" }

func (p *GraphQLProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	if currentClassified != nil {
		cfg.Classified = currentClassified
	}
	var findings []types.Finding

	graphqlEPs := p.discoverEndpoints(cfg, endpoints)
	if len(graphqlEPs) == 0 {
		return findings
	}

	for _, ep := range graphqlEPs {
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		findings = append(findings, p.testIntrospection(cfg, ep)...)
		findings = append(findings, p.testBatchAbuse(cfg, ep)...)
		findings = append(findings, p.testSQLiViaArgs(cfg, ep)...)
		findings = append(findings, p.testIDOR(cfg, ep)...)
		findings = append(findings, p.testAuthBypass(cfg, ep)...)
	}

	return findings
}

// discoverEndpoints finds GraphQL endpoints by probing common paths and checking
// classified endpoints.
func (p *GraphQLProber) discoverEndpoints(cfg *ProberConfig, endpoints []types.Endpoint) []string {
	var found []string
	seen := make(map[string]bool)

	// Check classifier-identified GraphQL endpoints first
	if cfg.Classified != nil {
		for _, ep := range cfg.Classified.GraphQL {
			if !seen[ep.URL] {
				found = append(found, ep.URL)
				seen[ep.URL] = true
			}
		}
	}

	commonPaths := []string{
		"/graphql",
		"/graphiql",
		"/api/graphql",
		"/v1/graphql",
		"/v2/graphql",
		"/query",
		"/gql",
		"/api/gql",
		"/graphql/v1",
		"/api/v1/graphql",
		"/api/v2/graphql",
		"/graph",
	}

	for _, path := range commonPaths {
		u := cfg.BaseURL + path
		if seen[u] {
			continue
		}
		if p.isGraphQL(cfg, u) {
			found = append(found, u)
			seen[u] = true
		}
	}

	// Check any discovered API endpoints
	for _, ep := range endpoints {
		if ep.HasCategory(types.CatStatic) {
			continue
		}
		u := strings.Split(ep.URL, "?")[0]
		if seen[u] {
			continue
		}
		if ep.HasCategory(types.CatGraphQL) || strings.Contains(strings.ToLower(u), "graphql") {
			if p.isGraphQL(cfg, u) {
				found = append(found, u)
				seen[u] = true
			}
		}
	}

	return found
}

// isGraphQL sends a minimal introspection query to detect a GraphQL endpoint.
func (p *GraphQLProber) isGraphQL(cfg *ProberConfig, endpoint string) bool {
	payload := `{"query":"{__typename}"}`
	status, _, body, err := cfg.DoRequest("POST", endpoint,
		strings.NewReader(payload),
		map[string]string{"Content-Type": "application/json"})
	if err != nil || status == 404 || status == 405 {
		return false
	}
	lowerBody := strings.ToLower(body)
	return strings.Contains(lowerBody, "__typename") ||
		(strings.Contains(lowerBody, `"data"`) && strings.Contains(lowerBody, `"errors"`)) ||
		strings.Contains(lowerBody, `"data":{`) ||
		strings.Contains(lowerBody, `"errors":[`)
}

// gqlPost sends a GraphQL query and returns status + body.
func (p *GraphQLProber) gqlPost(cfg *ProberConfig, endpoint, query string, variables map[string]interface{}) (int, string, error) {
	reqBody := map[string]interface{}{"query": query}
	if variables != nil {
		reqBody["variables"] = variables
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return 0, "", err
	}
	status, _, body, err := cfg.DoRequest("POST", endpoint,
		strings.NewReader(string(data)),
		map[string]string{"Content-Type": "application/json"})
	return status, body, err
}

// testIntrospection performs full schema introspection and identifies sensitive types/operations.
func (p *GraphQLProber) testIntrospection(cfg *ProberConfig, endpoint string) []types.Finding {
	var findings []types.Finding

	introspectionQuery := `{
		__schema {
			queryType { name }
			mutationType { name }
			subscriptionType { name }
			types {
				name
				kind
				fields {
					name
					args { name type { name kind ofType { name kind } } }
					type { name kind ofType { name kind } }
				}
			}
		}
	}`

	status, body, err := p.gqlPost(cfg, endpoint, introspectionQuery, nil)
	if err != nil || status != 200 {
		return findings
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return findings
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return findings
	}
	schema, ok := data["__schema"].(map[string]interface{})
	if !ok {
		return findings
	}

	sensitiveTypeKWs := []string{"user", "admin", "credential", "auth", "token", "secret", "password", "key", "access", "permission", "role", "session"}
	sensitiveMutationKWs := []string{"createuser", "deleteuser", "updatepassword", "changeemail", "transferfund", "grant", "revoke", "resetpassword", "admin", "promote", "delete"}
	sensitiveQueryKWs := []string{"users", "admin", "credentials", "tokens", "secrets", "userlist", "alluser", "password", "apikey"}

	var sensitiveTypes, sensitiveMutations, sensitiveQueries []string

	if gqlTypes, ok := schema["types"].([]interface{}); ok {
		for _, t := range gqlTypes {
			typObj, ok := t.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := typObj["name"].(string)
			if name == "" || strings.HasPrefix(name, "__") {
				continue
			}
			nameLower := strings.ToLower(name)
			for _, kw := range sensitiveTypeKWs {
				if strings.Contains(nameLower, kw) {
					sensitiveTypes = append(sensitiveTypes, name)
					break
				}
			}
			if fields, ok := typObj["fields"].([]interface{}); ok {
				for _, field := range fields {
					fieldObj, ok := field.(map[string]interface{})
					if !ok {
						continue
					}
					fieldName, _ := fieldObj["name"].(string)
					fieldLower := strings.ToLower(fieldName)
					for _, kw := range sensitiveMutationKWs {
						if strings.Contains(fieldLower, kw) {
							sensitiveMutations = append(sensitiveMutations, name+"."+fieldName)
							break
						}
					}
					for _, kw := range sensitiveQueryKWs {
						if strings.Contains(fieldLower, kw) {
							sensitiveQueries = append(sensitiveQueries, name+"."+fieldName)
							break
						}
					}
				}
			}
		}
	}

	severity := "Medium"
	desc := fmt.Sprintf("GraphQL introspection is enabled at %s. Full schema is exposed to attackers, revealing all types, queries, and mutations.", endpoint)

	if len(sensitiveMutations) > 0 || len(sensitiveQueries) > 0 {
		severity = "High"
		if len(sensitiveMutations) > 0 {
			desc += fmt.Sprintf(" Sensitive mutations found: %s.", strings.Join(sensitiveMutations, ", "))
		}
		if len(sensitiveQueries) > 0 {
			desc += fmt.Sprintf(" Sensitive queries found: %s.", strings.Join(sensitiveQueries, ", "))
		}
	}
	if len(sensitiveTypes) > 0 {
		desc += fmt.Sprintf(" Sensitive types: %s.", strings.Join(sensitiveTypes, ", "))
	}

	poc := fmt.Sprintf("curl -X POST '%s' \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"query\":\"{__schema{types{name fields{name}}}}\"}'\n", endpoint)

	findings = append(findings, MakeFinding(
		"GraphQL Introspection Enabled",
		severity,
		desc,
		extractPath(endpoint),
		"POST",
		"CWE-200",
		poc,
		fmt.Sprintf("HTTP %d - Introspection response:\n%s", status, truncate(body, 600)),
		"graphql",
		0,
	))

	return findings
}

// testBatchAbuse tests whether the endpoint accepts batched query arrays without rate limiting.
func (p *GraphQLProber) testBatchAbuse(cfg *ProberConfig, endpoint string) []types.Finding {
	var findings []types.Finding

	// Send 10 queries in a single batched array
	const batchSize = 10
	batch := make([]map[string]interface{}, batchSize)
	for i := range batch {
		batch[i] = map[string]interface{}{"query": "{__typename}"}
	}

	data, err := json.Marshal(batch)
	if err != nil {
		return findings
	}

	status, _, body, err := cfg.DoRequest("POST", endpoint,
		strings.NewReader(string(data)),
		map[string]string{"Content-Type": "application/json"})
	if err != nil || status != 200 {
		return findings
	}

	// A batch response should be a JSON array
	var batchResp []interface{}
	if err := json.Unmarshal([]byte(body), &batchResp); err != nil {
		return findings
	}
	if len(batchResp) < batchSize {
		return findings
	}

	poc := fmt.Sprintf(`# Send 10 queries in one request to bypass rate limiting:
curl -X POST '%s' \
  -H 'Content-Type: application/json' \
  -d '[%s]'`,
		endpoint,
		strings.Repeat(`{"query":"{__typename}"},`, batchSize-1)+`{"query":"{__typename}"}`)

	findings = append(findings, MakeFinding(
		"GraphQL Batch Query Abuse",
		"Medium",
		fmt.Sprintf("GraphQL endpoint %s accepts batched query arrays. Attackers can send hundreds of queries in a single request to bypass rate limiting (e.g., for brute-force or enumeration).", endpoint),
		extractPath(endpoint),
		"POST",
		"CWE-770",
		poc,
		fmt.Sprintf("HTTP %d - Batch of %d queries accepted, got %d responses", status, batchSize, len(batchResp)),
		"graphql",
		0,
	))

	return findings
}

// testSQLiViaArgs sends SQL injection payloads through GraphQL arguments.
func (p *GraphQLProber) testSQLiViaArgs(cfg *ProberConfig, endpoint string) []types.Finding {
	var findings []types.Finding

	sqliPayloads := []string{
		`' OR '1'='1`,
		`' OR 1=1--`,
		`1' OR '1'='1'--`,
		`" OR "1"="1`,
		`admin'--`,
	}

	// Common query shapes to try
	queryTemplates := []string{
		`{ user(id: "%s") { id } }`,
		`{ users(filter: "%s") { id } }`,
		`{ search(query: "%s") { id } }`,
		`{ item(name: "%s") { id } }`,
	}

	sqliIndicators := []string{
		"sql", "syntax", "mysql", "postgresql", "sqlite", "ora-", "unclosed quotation",
		"you have an error in your sql", "warning: mysql", "invalid query",
		"pg_query()", "unterminated quoted string",
	}

	for _, tmpl := range queryTemplates {
		for _, payload := range sqliPayloads {
			query := fmt.Sprintf(tmpl, payload)
			status, body, err := p.gqlPost(cfg, endpoint, query, nil)
			if err != nil || status == 404 {
				continue
			}

			lowerBody := strings.ToLower(body)
			for _, ind := range sqliIndicators {
				if strings.Contains(lowerBody, ind) {
					poc := fmt.Sprintf("curl -X POST '%s' \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"query\":\"%s\"}'\n",
						endpoint, strings.ReplaceAll(query, `"`, `\"`))
					findings = append(findings, MakeFinding(
						"GraphQL SQL Injection",
						"Critical",
						fmt.Sprintf("SQL injection via GraphQL argument. Payload '%s' triggered a database error, confirming unsanitized input reaches SQL.", payload),
						extractPath(endpoint),
						"POST",
						"CWE-89",
						poc,
						fmt.Sprintf("HTTP %d - DB error indicator '%s' in response:\n%s", status, ind, truncate(body, 400)),
						"graphql",
						0,
					))
					return findings
				}
			}
		}
	}

	return findings
}

// testIDOR tests for Insecure Direct Object References via GraphQL node IDs.
// GraphQL Relay spec uses base64-encoded IDs like base64("TypeName:123").
func (p *GraphQLProber) testIDOR(cfg *ProberConfig, endpoint string) []types.Finding {
	var findings []types.Finding

	// Try to fetch node IDs 1-5 for common type names
	typeNames := []string{"User", "Admin", "Account", "Order", "Post", "Product", "Payment"}

	for _, typeName := range typeNames {
		for id := 1; id <= 3; id++ {
			// Relay-style base64 node ID
			raw := fmt.Sprintf("%s:%d", typeName, id)
			encoded := base64.StdEncoding.EncodeToString([]byte(raw))

			query := fmt.Sprintf(`{ node(id: "%s") { id __typename } }`, encoded)
			status, body, err := p.gqlPost(cfg, endpoint, query, nil)
			if err != nil || status != 200 {
				continue
			}

			lowerBody := strings.ToLower(body)
			// If response contains __typename matching our type, IDOR works
			if strings.Contains(lowerBody, strings.ToLower(typeName)) &&
				strings.Contains(lowerBody, `"id"`) &&
				!strings.Contains(lowerBody, `"errors"`) {

				poc := fmt.Sprintf("# Base64-encoded node IDs expose %s records:\n", typeName)
				poc += fmt.Sprintf("# %s:%d → %s\n", typeName, id, encoded)
				poc += fmt.Sprintf("curl -X POST '%s' \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"query\":\"{ node(id: \\\"%s\\\") { id __typename } }\"}'\n",
					endpoint, encoded)

				findings = append(findings, MakeFinding(
					fmt.Sprintf("GraphQL IDOR — %s Objects Accessible", typeName),
					"High",
					fmt.Sprintf("GraphQL node interface allows direct object access to %s records using base64-encoded Relay IDs. Unauthenticated or cross-user access may be possible by enumerating IDs.", typeName),
					extractPath(endpoint),
					"POST",
					"CWE-639",
					poc,
					fmt.Sprintf("HTTP %d - Node %s:%d accessible:\n%s", status, typeName, id, truncate(body, 300)),
					"graphql",
					0,
				))
				return findings
			}
		}
	}

	return findings
}

// testAuthBypass attempts to query sensitive admin fields without authentication.
func (p *GraphQLProber) testAuthBypass(cfg *ProberConfig, endpoint string) []types.Finding {
	var findings []types.Finding

	// Admin-only query patterns to probe
	adminQueries := []struct {
		query    string
		desc     string
		keywords []string
	}{
		{
			`{ users { id email password role } }`,
			"users listing with credentials",
			[]string{"email", "password", "role"},
		},
		{
			`{ admin { id email token } }`,
			"admin object",
			[]string{"admin", "token", "email"},
		},
		{
			`{ me { id email role isAdmin } }`,
			"current user with admin fields",
			[]string{"isadmin", "role", "email"},
		},
		{
			`{ settings { secretKey apiKey jwtSecret } }`,
			"application settings with secrets",
			[]string{"secretkey", "apikey", "jwtsecret"},
		},
		{
			`{ tokens { accessToken refreshToken } }`,
			"token listing",
			[]string{"accesstoken", "refreshtoken"},
		},
	}

	for _, aq := range adminQueries {
		status, body, err := p.gqlPost(cfg, endpoint, aq.query, nil)
		if err != nil || status != 200 {
			continue
		}

		// Must have data AND no errors to be a real bypass
		lowerBody := strings.ToLower(body)
		if strings.Contains(lowerBody, `"errors"`) {
			continue
		}
		if !strings.Contains(lowerBody, `"data"`) {
			continue
		}

		matched := 0
		for _, kw := range aq.keywords {
			if strings.Contains(lowerBody, kw) {
				matched++
			}
		}
		if matched < 2 {
			continue
		}

		poc := fmt.Sprintf("curl -X POST '%s' \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"query\":\"%s\"}'\n",
			endpoint, strings.ReplaceAll(aq.query, `"`, `\"`))

		findings = append(findings, MakeFinding(
			fmt.Sprintf("GraphQL Authorization Bypass — %s", aq.desc),
			"Critical",
			fmt.Sprintf("GraphQL query for %s returned data without proper authorization. Sensitive fields are accessible without authentication.", aq.desc),
			extractPath(endpoint),
			"POST",
			"CWE-285",
			poc,
			fmt.Sprintf("HTTP %d - Sensitive data returned:\n%s", status, truncate(body, 400)),
			"graphql",
			0,
		))
		return findings
	}

	return findings
}

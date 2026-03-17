package red

import (
	"net/url"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// ClassifyEndpoints categorizes discovered endpoints by their role.
func ClassifyEndpoints(endpoints []types.Endpoint) *types.ClassifiedEndpoints {
	ce := &types.ClassifiedEndpoints{
		All: endpoints,
	}

	for i := range endpoints {
		ep := &endpoints[i]
		ep.Categories = classifyOne(ep)

		for _, cat := range ep.Categories {
			switch cat {
			case types.CatLogin:
				ce.Login = append(ce.Login, *ep)
			case types.CatAPI:
				ce.API = append(ce.API, *ep)
			case types.CatFileUpload:
				ce.FileUpload = append(ce.FileUpload, *ep)
			case types.CatAdmin:
				ce.Admin = append(ce.Admin, *ep)
			case types.CatSearch:
				ce.Search = append(ce.Search, *ep)
			case types.CatUserData:
				ce.UserData = append(ce.UserData, *ep)
			case types.CatRedirect:
				ce.Redirect = append(ce.Redirect, *ep)
			case types.CatGraphQL:
				ce.GraphQL = append(ce.GraphQL, *ep)
			}
		}
	}

	return ce
}

func classifyOne(ep *types.Endpoint) []types.EndpointCategory {
	var cats []types.EndpointCategory
	path := extractURLPath(ep.URL)
	lowerPath := strings.ToLower(path)
	lowerBody := strings.ToLower(ep.Body)
	ct := strings.ToLower(ep.ContentType)

	// Static assets — skip early
	if isStaticAsset(lowerPath, ct) {
		return []types.EndpointCategory{types.CatStatic}
	}

	// Login/auth endpoints
	if isLoginEndpoint(lowerPath, lowerBody) {
		cats = append(cats, types.CatLogin)
	}

	// Search endpoints
	if isSearchEndpoint(lowerPath, ep.Parameters) {
		cats = append(cats, types.CatSearch)
	}

	// Admin endpoints
	if isAdminEndpoint(lowerPath) {
		cats = append(cats, types.CatAdmin)
	}

	// File upload endpoints
	if isFileUploadEndpoint(lowerPath, lowerBody) {
		cats = append(cats, types.CatFileUpload)
	}

	// User data endpoints
	if isUserDataEndpoint(lowerPath) {
		cats = append(cats, types.CatUserData)
	}

	// Redirect endpoints
	if isRedirectEndpoint(lowerPath, ep.Parameters, ep.StatusCode) {
		cats = append(cats, types.CatRedirect)
	}

	// GraphQL
	if isGraphQLEndpoint(lowerPath) {
		cats = append(cats, types.CatGraphQL)
	}

	// API endpoints (broad — JSON responses, /api/ paths, etc.)
	if isAPIEndpoint(lowerPath, ct) {
		cats = append(cats, types.CatAPI)
	}

	if len(cats) == 0 {
		cats = append(cats, types.CatUnknown)
	}
	return cats
}

func isStaticAsset(path, contentType string) bool {
	staticExts := []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
		".ico", ".woff", ".woff2", ".ttf", ".eot", ".map"}
	for _, ext := range staticExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	staticTypes := []string{"image/", "font/", "text/css", "application/javascript"}
	for _, st := range staticTypes {
		if strings.Contains(contentType, st) {
			return true
		}
	}
	return false
}

func isLoginEndpoint(path, body string) bool {
	loginPaths := []string{"/login", "/signin", "/sign-in", "/authenticate",
		"/auth/login", "/auth/signin", "/session", "/oauth/token",
		"/token", "/api/auth", "/api/login"}
	for _, lp := range loginPaths {
		if strings.HasSuffix(path, lp) || strings.Contains(path, lp+"/") || strings.Contains(path, lp+"?") {
			return true
		}
	}
	// Body contains password field (form or JSON)
	if strings.Contains(body, "password") && (strings.Contains(body, "email") ||
		strings.Contains(body, "username") || strings.Contains(body, "user")) {
		return true
	}
	return false
}

func isSearchEndpoint(path string, params []string) bool {
	searchPaths := []string{"/search", "/find", "/query", "/lookup"}
	for _, sp := range searchPaths {
		if strings.Contains(path, sp) {
			return true
		}
	}
	searchParams := []string{"q", "query", "search", "keyword", "term", "s", "filter"}
	for _, p := range params {
		lp := strings.ToLower(p)
		for _, sp := range searchParams {
			if lp == sp {
				return true
			}
		}
	}
	return false
}

func isAdminEndpoint(path string) bool {
	adminPaths := []string{"/admin", "/dashboard", "/management", "/panel",
		"/console", "/backoffice", "/accounting", "/moderate"}
	for _, ap := range adminPaths {
		if strings.Contains(path, ap) {
			return true
		}
	}
	return false
}

func isFileUploadEndpoint(path, body string) bool {
	uploadPaths := []string{"/upload", "/file-upload", "/import", "/attachment"}
	for _, up := range uploadPaths {
		if strings.Contains(path, up) {
			return true
		}
	}
	if strings.Contains(body, `type="file"`) || strings.Contains(body, "multipart") ||
		strings.Contains(body, "enctype") {
		return true
	}
	return false
}

func isUserDataEndpoint(path string) bool {
	userPaths := []string{"/profile", "/account", "/settings", "/user",
		"/me", "/whoami", "/preferences"}
	for _, up := range userPaths {
		if strings.Contains(path, up) {
			return true
		}
	}
	return false
}

func isRedirectEndpoint(path string, params []string, statusCode int) bool {
	if statusCode >= 300 && statusCode < 400 {
		return true
	}
	redirectPaths := []string{"/redirect", "/goto", "/forward", "/out", "/away"}
	for _, rp := range redirectPaths {
		if strings.Contains(path, rp) {
			return true
		}
	}
	redirectParams := []string{"url", "to", "redirect", "target", "next", "return",
		"returnto", "return_to", "redirect_uri", "continue"}
	for _, p := range params {
		lp := strings.ToLower(p)
		for _, rp := range redirectParams {
			if lp == rp {
				return true
			}
		}
	}
	return false
}

func isGraphQLEndpoint(path string) bool {
	return strings.Contains(path, "/graphql") || strings.Contains(path, "/gql")
}

func isAPIEndpoint(path, contentType string) bool {
	if strings.Contains(path, "/api/") || strings.Contains(path, "/rest/") ||
		strings.Contains(path, "/v1/") || strings.Contains(path, "/v2/") ||
		strings.Contains(path, "/v3/") {
		return true
	}
	if strings.Contains(contentType, "json") || strings.Contains(contentType, "xml") {
		return true
	}
	return false
}

func extractURLPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Path
}

// EndpointsWithNumericIDs returns endpoints that have numeric IDs in the path.
// These are prime IDOR candidates (e.g., /api/users/1, /orders/42).
func EndpointsWithNumericIDs(endpoints []types.Endpoint) []types.Endpoint {
	var result []types.Endpoint
	for _, ep := range endpoints {
		path := extractURLPath(ep.URL)
		segments := strings.Split(path, "/")
		for _, seg := range segments {
			if seg != "" && isNumeric(seg) {
				result = append(result, ep)
				break
			}
		}
	}
	return result
}

// EndpointsAcceptingURLParams returns endpoints with parameters that look like URL inputs.
func EndpointsAcceptingURLParams(endpoints []types.Endpoint) []types.Endpoint {
	urlParams := []string{"url", "to", "redirect", "target", "link", "href",
		"src", "imageurl", "image_url", "callback", "next", "return", "uri"}
	var result []types.Endpoint
	for _, ep := range endpoints {
		for _, p := range ep.Parameters {
			lp := strings.ToLower(p)
			for _, up := range urlParams {
				if lp == up {
					result = append(result, ep)
					break
				}
			}
		}
	}
	return result
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

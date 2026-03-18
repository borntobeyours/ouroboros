package red

import (
	"testing"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

func TestClassifyEndpoints_Login(t *testing.T) {
	endpoints := []types.Endpoint{
		{URL: "http://example.com/login", Method: "POST", ContentType: "text/html"},
		{URL: "http://example.com/api/auth/login", Method: "POST", ContentType: "application/json"},
		{URL: "http://example.com/signin", Method: "POST", ContentType: "text/html"},
		{URL: "http://example.com/oauth/token", Method: "POST", ContentType: "application/json"},
	}

	classified := ClassifyEndpoints(endpoints)

	if len(classified.Login) < 4 {
		t.Errorf("expected at least 4 login endpoints, got %d", len(classified.Login))
		for _, ep := range classified.Login {
			t.Logf("  login: %s", ep.URL)
		}
	}
}

func TestClassifyEndpoints_LoginByBody(t *testing.T) {
	endpoints := []types.Endpoint{
		{
			URL:         "http://example.com/custom-form",
			Method:      "POST",
			ContentType: "text/html",
			Body:        `<form><input name="username"><input name="password" type="password"></form>`,
		},
	}

	classified := ClassifyEndpoints(endpoints)

	if len(classified.Login) != 1 {
		t.Errorf("expected 1 login endpoint detected via body, got %d", len(classified.Login))
	}
}

func TestClassifyEndpoints_API(t *testing.T) {
	endpoints := []types.Endpoint{
		{URL: "http://example.com/api/users", Method: "GET", ContentType: "application/json"},
		{URL: "http://example.com/v2/products", Method: "GET", ContentType: "application/json"},
		{URL: "http://example.com/rest/orders/1", Method: "GET", ContentType: "application/json"},
	}

	classified := ClassifyEndpoints(endpoints)

	if len(classified.API) != 3 {
		t.Errorf("expected 3 API endpoints, got %d", len(classified.API))
	}
}

func TestClassifyEndpoints_FileUpload(t *testing.T) {
	endpoints := []types.Endpoint{
		{URL: "http://example.com/upload", Method: "POST", ContentType: "text/html"},
		{URL: "http://example.com/form", Method: "POST", ContentType: "text/html", Body: `<input type="file">`},
	}

	classified := ClassifyEndpoints(endpoints)

	if len(classified.FileUpload) != 2 {
		t.Errorf("expected 2 file upload endpoints, got %d", len(classified.FileUpload))
	}
}

func TestClassifyEndpoints_Admin(t *testing.T) {
	endpoints := []types.Endpoint{
		{URL: "http://example.com/admin/settings", Method: "GET", ContentType: "text/html"},
		{URL: "http://example.com/dashboard", Method: "GET", ContentType: "text/html"},
	}

	classified := ClassifyEndpoints(endpoints)

	if len(classified.Admin) != 2 {
		t.Errorf("expected 2 admin endpoints, got %d", len(classified.Admin))
	}
}

func TestClassifyEndpoints_Search(t *testing.T) {
	endpoints := []types.Endpoint{
		{URL: "http://example.com/search?q=test", Method: "GET", ContentType: "text/html", Parameters: []string{"q"}},
		{URL: "http://example.com/products", Method: "GET", ContentType: "application/json", Parameters: []string{"filter", "page"}},
	}

	classified := ClassifyEndpoints(endpoints)

	if len(classified.Search) != 2 {
		t.Errorf("expected 2 search endpoints, got %d", len(classified.Search))
	}
}

func TestClassifyEndpoints_UserData(t *testing.T) {
	endpoints := []types.Endpoint{
		{URL: "http://example.com/profile", Method: "GET", ContentType: "text/html"},
		{URL: "http://example.com/api/me", Method: "GET", ContentType: "application/json"},
		{URL: "http://example.com/settings", Method: "GET", ContentType: "text/html"},
	}

	classified := ClassifyEndpoints(endpoints)

	if len(classified.UserData) != 3 {
		t.Errorf("expected 3 user data endpoints, got %d", len(classified.UserData))
	}
}

func TestClassifyEndpoints_Redirect(t *testing.T) {
	endpoints := []types.Endpoint{
		{URL: "http://example.com/redirect?url=http://evil.com", Method: "GET", StatusCode: 302, Parameters: []string{"url"}},
		{URL: "http://example.com/goto", Method: "GET", StatusCode: 200, Parameters: []string{"target"}},
	}

	classified := ClassifyEndpoints(endpoints)

	if len(classified.Redirect) != 2 {
		t.Errorf("expected 2 redirect endpoints, got %d", len(classified.Redirect))
	}
}

func TestClassifyEndpoints_GraphQL(t *testing.T) {
	endpoints := []types.Endpoint{
		{URL: "http://example.com/graphql", Method: "POST", ContentType: "application/json"},
		{URL: "http://example.com/api/gql", Method: "POST", ContentType: "application/json"},
	}

	classified := ClassifyEndpoints(endpoints)

	if len(classified.GraphQL) != 2 {
		t.Errorf("expected 2 GraphQL endpoints, got %d", len(classified.GraphQL))
	}
}

func TestClassifyEndpoints_StaticAssets(t *testing.T) {
	endpoints := []types.Endpoint{
		{URL: "http://example.com/style.css", Method: "GET", ContentType: "text/css"},
		{URL: "http://example.com/app.js", Method: "GET", ContentType: "application/javascript"},
		{URL: "http://example.com/logo.png", Method: "GET", ContentType: "image/png"},
	}

	classified := ClassifyEndpoints(endpoints)

	// Static assets should NOT appear in any attack category
	if len(classified.Login) != 0 || len(classified.API) != 0 ||
		len(classified.Search) != 0 || len(classified.Admin) != 0 {
		t.Error("static assets should not be classified as attack targets")
	}
}

func TestClassifyEndpoints_MultipleCategories(t *testing.T) {
	// An endpoint can belong to multiple categories
	endpoints := []types.Endpoint{
		{URL: "http://example.com/api/admin/search", Method: "GET", ContentType: "application/json", Parameters: []string{"q"}},
	}

	classified := ClassifyEndpoints(endpoints)

	if len(classified.API) == 0 {
		t.Error("expected endpoint to be classified as API")
	}
	if len(classified.Admin) == 0 {
		t.Error("expected endpoint to be classified as Admin")
	}
	if len(classified.Search) == 0 {
		t.Error("expected endpoint to be classified as Search")
	}
}

func TestEndpointsWithNumericIDs(t *testing.T) {
	endpoints := []types.Endpoint{
		{URL: "http://example.com/api/users/42"},
		{URL: "http://example.com/api/users"},
		{URL: "http://example.com/orders/123/details"},
	}

	result := EndpointsWithNumericIDs(endpoints)
	if len(result) != 2 {
		t.Errorf("expected 2 endpoints with numeric IDs, got %d", len(result))
	}
}

func TestEndpointsAcceptingURLParams(t *testing.T) {
	endpoints := []types.Endpoint{
		{URL: "http://example.com/redirect", Parameters: []string{"url", "ref"}},
		{URL: "http://example.com/image", Parameters: []string{"src"}},
		{URL: "http://example.com/data", Parameters: []string{"page", "limit"}},
	}

	result := EndpointsAcceptingURLParams(endpoints)
	if len(result) != 2 {
		t.Errorf("expected 2 endpoints with URL params, got %d", len(result))
	}
}

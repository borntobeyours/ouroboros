package target

import (
	"io"
	"net/http"
	"strings"

	"github.com/ouroboros-security/ouroboros/pkg/types"
)

// DiscoverEndpoints probes a list of URLs and returns endpoint metadata.
func DiscoverEndpoints(urls []string, headers map[string]string) []types.Endpoint {
	endpoints := make([]types.Endpoint, 0, len(urls))
	client := &http.Client{
		Timeout: 10 * 1e9, // 10 seconds
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, u := range urls {
		// Skip JS/CSS/image files - not interesting for vuln scanning
		lower := strings.ToLower(u)
		if strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".css") ||
			strings.HasSuffix(lower, ".png") || strings.HasSuffix(lower, ".jpg") ||
			strings.HasSuffix(lower, ".gif") || strings.HasSuffix(lower, ".svg") ||
			strings.HasSuffix(lower, ".ico") || strings.HasSuffix(lower, ".woff") ||
			strings.HasSuffix(lower, ".woff2") || strings.HasSuffix(lower, ".ttf") {
			continue
		}

		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		// Read response body (truncated for AI context)
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		ep := types.Endpoint{
			URL:         u,
			Method:      http.MethodGet,
			StatusCode:  resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
			Body:        string(body),
		}

		// Capture interesting response headers
		secHeaders := []string{
			"Server", "X-Powered-By", "X-Frame-Options",
			"Content-Security-Policy", "Strict-Transport-Security",
			"X-Content-Type-Options", "Access-Control-Allow-Origin",
			"Set-Cookie", "WWW-Authenticate",
		}
		ep.ResponseHeaders = make(map[string]string)
		for _, h := range secHeaders {
			if v := resp.Header.Get(h); v != "" {
				ep.ResponseHeaders[h] = v
			}
		}

		// Extract parameters from URL
		if strings.Contains(u, "?") {
			parts := strings.SplitN(u, "?", 2)
			if len(parts) == 2 {
				for _, p := range strings.Split(parts[1], "&") {
					kv := strings.SplitN(p, "=", 2)
					ep.Parameters = append(ep.Parameters, kv[0])
				}
			}
		}

		endpoints = append(endpoints, ep)
	}

	return endpoints
}

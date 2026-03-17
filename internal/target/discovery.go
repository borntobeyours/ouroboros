package target

import (
	"net/http"
	"strings"

	"github.com/ouroboros-security/ouroboros/pkg/types"
)

// DiscoverEndpoints probes a list of URLs and returns endpoint metadata.
func DiscoverEndpoints(urls []string, headers map[string]string) []types.Endpoint {
	endpoints := make([]types.Endpoint, 0, len(urls))
	client := &http.Client{
		Timeout: 10 * 1e9, // 10 seconds
	}

	for _, u := range urls {
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
		resp.Body.Close()

		ep := types.Endpoint{
			URL:         u,
			Method:      http.MethodGet,
			StatusCode:  resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
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

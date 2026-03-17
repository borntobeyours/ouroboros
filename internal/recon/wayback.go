package recon

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// WaybackMiner queries the Wayback Machine CDX API for historical URLs.
type WaybackMiner struct {
	target  string
	client  *http.Client
	workers int
}

// NewWaybackMiner creates a new Wayback Machine URL miner.
func NewWaybackMiner(target string, workers int) *WaybackMiner {
	if workers <= 0 {
		workers = 10
	}
	return &WaybackMiner{
		target:  target,
		workers: workers,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Mine queries the CDX API and returns interesting historical URLs.
func (wm *WaybackMiner) Mine() []types.WaybackURL {
	parsed, err := url.Parse(wm.target)
	if err != nil {
		return nil
	}
	host := parsed.Hostname()

	// Query Wayback CDX API
	cdxURL := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=timestamp,original,mimetype,statuscode&collapse=urlkey&limit=1000",
		host,
	)

	req, err := http.NewRequest("GET", cdxURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; security-scanner)")

	resp, err := wm.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if resp.StatusCode != 200 {
		return nil
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil
	}

	// First row is header: ["timestamp", "original", "mimetype", "statuscode"]
	if len(rows) < 2 {
		return nil
	}

	// Collect interesting URLs
	seen := make(map[string]bool)
	var candidates []types.WaybackURL
	for _, row := range rows[1:] {
		if len(row) < 4 {
			continue
		}
		timestamp, original, mimetype, status := row[0], row[1], row[2], row[3]

		if seen[original] {
			continue
		}
		seen[original] = true

		if !isInterestingURL(original, mimetype) {
			continue
		}

		candidates = append(candidates, types.WaybackURL{
			URL:       original,
			Timestamp: timestamp,
			MimeType:  mimetype,
			Status:    status,
		})
	}

	// Check which URLs are still alive (concurrent)
	return wm.checkAlive(candidates)
}

// isInterestingURL filters for security-relevant file extensions and paths.
func isInterestingURL(rawURL, mimetype string) bool {
	lower := strings.ToLower(rawURL)

	// Interesting extensions
	interestingExts := []string{
		".php", ".asp", ".aspx", ".jsp", ".jspx", ".do", ".action",
		".json", ".xml", ".yaml", ".yml", ".toml",
		".sql", ".bak", ".old", ".backup", ".log", ".conf", ".config",
		".env", ".ini", ".properties",
		".txt", ".csv",
		".cgi", ".pl", ".py", ".rb",
		".graphql", ".gql",
		".wsdl", ".wadl",
	}
	for _, ext := range interestingExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}

	// Interesting paths
	interestingPaths := []string{
		"/api/", "/v1/", "/v2/", "/v3/",
		"/admin", "/login", "/auth",
		"/graphql", "/swagger", "/openapi",
		"/debug", "/test", "/staging",
		"/upload", "/download", "/export",
		"/webhook", "/callback",
		"/.git", "/.env", "/.htaccess",
		"/wp-admin", "/wp-content",
		"/phpmyadmin", "/adminer",
	}
	for _, p := range interestingPaths {
		if strings.Contains(lower, p) {
			return true
		}
	}

	// Interesting mimetypes
	if strings.Contains(mimetype, "json") || strings.Contains(mimetype, "xml") {
		return true
	}

	// URLs with query params are interesting
	if strings.Contains(rawURL, "?") {
		return true
	}

	return false
}

// checkAlive verifies which URLs are still accessible.
func (wm *WaybackMiner) checkAlive(candidates []types.WaybackURL) []types.WaybackURL {
	var mu sync.Mutex
	var results []types.WaybackURL
	var wg sync.WaitGroup
	sem := make(chan struct{}, wm.workers)

	for _, c := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(wb types.WaybackURL) {
			defer wg.Done()
			defer func() { <-sem }()

			req, err := http.NewRequest("HEAD", wb.URL, nil)
			if err != nil {
				mu.Lock()
				results = append(results, wb)
				mu.Unlock()
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; security-scanner)")

			resp, err := wm.client.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode < 400 {
					wb.Alive = true
				}
			}

			mu.Lock()
			results = append(results, wb)
			mu.Unlock()
		}(c)
	}
	wg.Wait()

	return results
}

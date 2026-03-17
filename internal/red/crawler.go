package red

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
)

// Crawler discovers endpoints on a target using web crawling.
type Crawler struct {
	logger    *log.Logger
	maxDepth  int
	rateLimit time.Duration
	timeout   time.Duration
}

// NewCrawler creates a new web crawler.
func NewCrawler(logger *log.Logger) *Crawler {
	return &Crawler{
		logger:    logger,
		maxDepth:  3,
		rateLimit: 100 * time.Millisecond,
		timeout:   30 * time.Second,
	}
}

// commonAPIPaths contains well-known API paths to brute-force.
var commonAPIPaths = []string{
	// Juice Shop REST endpoints
	"/rest/user/login",
	"/rest/user/whoami",
	"/rest/user/change-password",
	"/rest/user/reset-password",
	"/rest/user/authentication-details",
	"/rest/user/erasure-request",
	"/rest/products/search",
	"/rest/products/1/reviews",
	"/rest/products/2/reviews",
	"/rest/saveLoginIp",
	"/rest/deluxe-membership",
	"/rest/wallet/balance",
	"/rest/order-history",
	"/rest/track-order/1",
	"/rest/basket/1",
	"/rest/basket/2",
	"/rest/basket/3",
	"/rest/admin/application-version",
	"/rest/admin/application-configuration",
	"/rest/repeat-notification",
	"/rest/chatbot/respond",
	"/rest/chatbot/status",
	"/rest/captcha",
	"/rest/image-captcha",
	"/rest/memories",
	"/rest/continue-code",
	"/rest/continue-code-findIt",
	"/rest/country-mapping",
	// Juice Shop API model endpoints
	"/api/Users",
	"/api/Users/1",
	"/api/Users/2",
	"/api/Users/3",
	"/api/Products",
	"/api/Products/1",
	"/api/Products/2",
	"/api/Feedbacks",
	"/api/Feedbacks/1",
	"/api/Challenges",
	"/api/Complaints",
	"/api/Recycles",
	"/api/SecurityQuestions",
	"/api/SecurityAnswers",
	"/api/Cards",
	"/api/Deliverys",
	"/api/Addresss",
	"/api/Quantitys",
	// Juice Shop special endpoints
	"/b2b/v2/orders",
	"/file-upload",
	"/profile",
	"/profile/image/file",
	"/profile/image/url",
	"/redirect",
	"/dataerasure",
	"/accounting",
	"/administration",
	"/privacy-security/last-login-ip",
	// Sensitive files and directories
	"/ftp",
	"/ftp/acquisitions.md",
	"/ftp/package.json.bak",
	"/ftp/suspicious_errors.yml",
	"/ftp/encrypt.pyc",
	"/ftp/incident-support.kdbx",
	"/ftp/coupons_2013.md.bak%2500.md",
	"/ftp/eastere.gg%2500.md",
	"/encryptionkeys",
	"/encryptionkeys/jwt.pub",
	"/support/logs",
	"/metrics",
	"/snippets",
	"/snippets/1",
	"/snippets/2",
	"/snippets/3",
	"/assets/public/images/uploads/",
	"/.well-known/security.txt",
	"/robots.txt",
	"/promotion",
	"/video",
	// API documentation
	"/api-docs",
	"/swagger.json",
	"/api-docs/swagger.json",
	// Common discovery paths
	"/.env",
	"/.git/config",
	"/.git/HEAD",
	"/graphql",
	"/socket.io",
}

// Crawl discovers URLs on the target site.
func (c *Crawler) Crawl(ctx context.Context, targetURL string) ([]string, error) {
	var mu sync.Mutex
	urls := make(map[string]bool)

	// Phase 1: HTML crawling with colly
	c.logger.Printf("[CRAWLER] Phase 1: HTML crawling...")
	c.htmlCrawl(targetURL, &mu, urls)

	// Phase 2: JS file parsing for API routes
	c.logger.Printf("[CRAWLER] Phase 2: Parsing JS files for API routes...")
	c.parseJSFiles(targetURL, &mu, urls)

	// Phase 3: Common API path brute-force
	c.logger.Printf("[CRAWLER] Phase 3: API path discovery...")
	c.bruteforceAPIPaths(targetURL, &mu, urls)

	result := make([]string, 0, len(urls))
	mu.Lock()
	for u := range urls {
		result = append(result, u)
	}
	mu.Unlock()

	return result, nil
}

func (c *Crawler) htmlCrawl(targetURL string, mu *sync.Mutex, urls map[string]bool) {
	collector := colly.NewCollector(
		colly.MaxDepth(c.maxDepth),
		colly.Async(true),
	)

	collector.SetRequestTimeout(c.timeout)

	_ = collector.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: 3,
		Delay:       c.rateLimit,
	})

	collector.IgnoreRobotsTxt = true // Intentional for security scanning

	collector.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Request.AbsoluteURL(e.Attr("href"))
		if link == "" {
			return
		}
		mu.Lock()
		if !urls[link] {
			urls[link] = true
			mu.Unlock()
			_ = e.Request.Visit(link)
		} else {
			mu.Unlock()
		}
	})

	collector.OnHTML("form[action]", func(e *colly.HTMLElement) {
		action := e.Request.AbsoluteURL(e.Attr("action"))
		if action != "" {
			mu.Lock()
			urls[action] = true
			mu.Unlock()
		}
	})

	collector.OnHTML("script[src]", func(e *colly.HTMLElement) {
		src := e.Request.AbsoluteURL(e.Attr("src"))
		if src != "" {
			mu.Lock()
			urls[src] = true
			mu.Unlock()
		}
	})

	// Also capture link tags (CSS, icons, etc.)
	collector.OnHTML("link[href]", func(e *colly.HTMLElement) {
		href := e.Request.AbsoluteURL(e.Attr("href"))
		if href != "" {
			mu.Lock()
			urls[href] = true
			mu.Unlock()
		}
	})

	mu.Lock()
	urls[targetURL] = true
	mu.Unlock()

	_ = collector.Visit(targetURL)
	collector.Wait()
}

// parseJSFiles downloads JS files and extracts API endpoints using regex.
func (c *Crawler) parseJSFiles(targetURL string, mu *sync.Mutex, urls map[string]bool) {
	// Collect JS URLs
	mu.Lock()
	jsURLs := make([]string, 0)
	for u := range urls {
		if strings.HasSuffix(u, ".js") || strings.Contains(u, ".js?") {
			jsURLs = append(jsURLs, u)
		}
	}
	mu.Unlock()

	// Regex patterns for API routes in JS
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`["'](/api/[^"'\s]+)["']`),
		regexp.MustCompile(`["'](/rest/[^"'\s]+)["']`),
		regexp.MustCompile(`["'](/graphql[^"'\s]*)["']`),
		regexp.MustCompile(`["'](https?://[^"'\s]+/api/[^"'\s]+)["']`),
		regexp.MustCompile(`fetch\(["']([^"']+)["']`),
		regexp.MustCompile(`\.(?:get|post|put|delete|patch)\(["']([^"']+)["']`),
		regexp.MustCompile(`url:\s*["']([^"']+)["']`),
		regexp.MustCompile(`endpoint:\s*["']([^"']+)["']`),
	}

	client := &http.Client{Timeout: 15 * time.Second}
	for _, jsURL := range jsURLs {
		resp, err := client.Get(jsURL)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB limit
		resp.Body.Close()
		if err != nil {
			continue
		}

		content := string(body)
		for _, pattern := range patterns {
			matches := pattern.FindAllStringSubmatch(content, -1)
			for _, match := range matches {
				if len(match) > 1 {
					path := match[1]
					var fullURL string
					if strings.HasPrefix(path, "http") {
						fullURL = path
					} else {
						fullURL = strings.TrimRight(targetURL, "/") + path
					}
					mu.Lock()
					urls[fullURL] = true
					mu.Unlock()
				}
			}
		}

		c.logger.Printf("[CRAWLER] Parsed JS: %s", jsURL)
	}
}

// bruteforceAPIPaths tries common API paths against the target.
func (c *Crawler) bruteforceAPIPaths(targetURL string, mu *sync.Mutex, urls map[string]bool) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	base := strings.TrimRight(targetURL, "/")
	found := 0

	for _, path := range commonAPIPaths {
		fullURL := fmt.Sprintf("%s%s", base, path)

		mu.Lock()
		already := urls[fullURL]
		mu.Unlock()
		if already {
			continue
		}

		resp, err := client.Get(fullURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Include anything that's not a 404
		if resp.StatusCode != 404 {
			mu.Lock()
			urls[fullURL] = true
			mu.Unlock()
			found++
		}
	}

	c.logger.Printf("[CRAWLER] API brute-force found %d additional endpoints", found)
}

package red

import (
	"context"
	"log"
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
		rateLimit: 200 * time.Millisecond,
		timeout:   30 * time.Second,
	}
}

// Crawl discovers URLs on the target site.
func (c *Crawler) Crawl(ctx context.Context, targetURL string) ([]string, error) {
	var mu sync.Mutex
	urls := make(map[string]bool)

	collector := colly.NewCollector(
		colly.MaxDepth(c.maxDepth),
		colly.Async(true),
	)

	collector.SetRequestTimeout(c.timeout)

	if err := collector.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: 2,
		Delay:       c.rateLimit,
	}); err != nil {
		return nil, err
	}

	// Respect robots.txt
	collector.IgnoreRobotsTxt = false

	// Collect links from anchor tags
	collector.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Request.AbsoluteURL(e.Attr("href"))
		if link == "" {
			return
		}
		mu.Lock()
		if !urls[link] {
			urls[link] = true
			mu.Unlock()
			if err := e.Request.Visit(link); err != nil {
				// Ignore visit errors (duplicate visits, etc.)
			}
		} else {
			mu.Unlock()
		}
	})

	// Collect form actions
	collector.OnHTML("form[action]", func(e *colly.HTMLElement) {
		action := e.Request.AbsoluteURL(e.Attr("action"))
		if action != "" {
			mu.Lock()
			urls[action] = true
			mu.Unlock()
		}
	})

	// Collect script sources
	collector.OnHTML("script[src]", func(e *colly.HTMLElement) {
		src := e.Request.AbsoluteURL(e.Attr("src"))
		if src != "" {
			mu.Lock()
			urls[src] = true
			mu.Unlock()
		}
	})

	collector.OnError(func(r *colly.Response, err error) {
		c.logger.Printf("[CRAWLER] Error visiting %s: %v", r.Request.URL, err)
	})

	// Always include the target URL itself
	mu.Lock()
	urls[targetURL] = true
	mu.Unlock()

	if err := collector.Visit(targetURL); err != nil {
		c.logger.Printf("[CRAWLER] Error starting crawl: %v", err)
	}
	collector.Wait()

	result := make([]string, 0, len(urls))
	mu.Lock()
	for u := range urls {
		result = append(result, u)
	}
	mu.Unlock()

	return result, nil
}

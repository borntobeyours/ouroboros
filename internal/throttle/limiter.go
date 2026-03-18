// Package throttle provides configurable request rate limiting with stealth profiles.
package throttle

import (
	"math/rand"
	"sync"
	"time"
)

// Profile is a named throttle preset.
type Profile string

const (
	// ProfileAggressive disables all rate limiting (original behaviour).
	ProfileAggressive Profile = "aggressive"
	// ProfileNormal limits to 10 req/s — safe default for most targets.
	ProfileNormal Profile = "normal"
	// ProfileStealth limits to 2 req/s and adds random jitter up to 500 ms.
	ProfileStealth Profile = "stealth"
	// ProfileParanoidStealth limits to 0.5 req/s, adds random jitter up to 2 s,
	// and rotates the User-Agent on every request.
	ProfileParanoidStealth Profile = "paranoid-stealth"
)

// userAgentPool holds realistic browser UA strings used for rotation.
var userAgentPool = []string{
	// Chrome — Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	// Chrome — macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	// Chrome — Linux
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	// Firefox — Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	// Firefox — macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
	// Firefox — Linux
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	// Safari — macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
	// Safari — iPhone
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
	// Edge — Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
	// Edge — macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
}

// Limiter enforces a token-bucket rate limit with optional jitter and UA rotation.
type Limiter struct {
	mu sync.Mutex

	// Token bucket state
	tokens    float64   // current token count
	maxTokens float64   // bucket capacity (= 1 token per request burst window)
	rps       float64   // refill rate (tokens per second); 0 = unlimited
	lastTick  time.Time // last refill timestamp

	// Jitter window added after each Wait() call (0 = no jitter).
	jitterMax time.Duration

	// UA rotation
	rotateUA bool
	uaIndex  int
}

// New creates a Limiter for the named profile.
// Use NewWithRPS for a custom rate.
func New(p Profile) *Limiter {
	switch p {
	case ProfileAggressive:
		return NewWithRPS(0)
	case ProfileStealth:
		l := NewWithRPS(2)
		l.jitterMax = 500 * time.Millisecond
		return l
	case ProfileParanoidStealth:
		l := NewWithRPS(0.5)
		l.jitterMax = 2 * time.Second
		l.rotateUA = true
		return l
	default: // ProfileNormal and anything else
		return NewWithRPS(10)
	}
}

// NewWithRPS creates a Limiter with an explicit requests-per-second cap.
// rps == 0 means unlimited.
func NewWithRPS(rps float64) *Limiter {
	l := &Limiter{
		rps:       rps,
		maxTokens: 1,
		tokens:    1,
		lastTick:  time.Now(),
	}
	if rps > 0 {
		// Allow a small burst of up to 3 tokens.
		l.maxTokens = 3
		l.tokens = 3
	}
	return l
}

// Wait blocks until the next request is allowed, then sleeps any configured jitter.
func (l *Limiter) Wait() {
	l.mu.Lock()

	if l.rps > 0 {
		// Refill tokens based on elapsed time.
		now := time.Now()
		elapsed := now.Sub(l.lastTick).Seconds()
		l.tokens += elapsed * l.rps
		if l.tokens > l.maxTokens {
			l.tokens = l.maxTokens
		}
		l.lastTick = now

		if l.tokens < 1 {
			// Sleep until we have a full token.
			wait := time.Duration((1-l.tokens)/l.rps*1000) * time.Millisecond
			l.mu.Unlock()
			time.Sleep(wait)
			l.mu.Lock()
			l.tokens = 0
			l.lastTick = time.Now()
		} else {
			l.tokens--
		}
	}

	jitter := l.jitterMax
	l.mu.Unlock()

	if jitter > 0 {
		// #nosec G404 — jitter doesn't need crypto-grade randomness
		time.Sleep(time.Duration(rand.Int63n(int64(jitter))))
	}
}

// NextUserAgent returns the next UA string from the rotation pool.
// If UA rotation is disabled it always returns the first entry.
func (l *Limiter) NextUserAgent() string {
	if !l.rotateUA {
		return userAgentPool[0]
	}
	l.mu.Lock()
	ua := userAgentPool[l.uaIndex%len(userAgentPool)]
	l.uaIndex++
	l.mu.Unlock()
	return ua
}

// RotatesUA returns true when this limiter rotates User-Agent strings.
func (l *Limiter) RotatesUA() bool {
	return l.rotateUA
}

// ParseProfile converts a string to a Profile, defaulting to ProfileNormal.
func ParseProfile(s string) Profile {
	switch Profile(s) {
	case ProfileAggressive, ProfileStealth, ProfileParanoidStealth:
		return Profile(s)
	default:
		return ProfileNormal
	}
}

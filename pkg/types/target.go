package types

import (
	"time"

	"github.com/google/uuid"
)

// Target represents a scan target.
type Target struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Cookies map[string]string `json:"cookies,omitempty"`
}

// EndpointCategory classifies the role of a discovered endpoint.
type EndpointCategory string

const (
	CatLogin      EndpointCategory = "login"
	CatAPI        EndpointCategory = "api"
	CatFileUpload EndpointCategory = "file_upload"
	CatAdmin      EndpointCategory = "admin"
	CatSearch     EndpointCategory = "search"
	CatUserData   EndpointCategory = "user_data"
	CatStatic     EndpointCategory = "static"
	CatRedirect   EndpointCategory = "redirect"
	CatGraphQL    EndpointCategory = "graphql"
	CatUnknown    EndpointCategory = "unknown"
)

// Endpoint represents a discovered endpoint on the target.
type Endpoint struct {
	URL             string             `json:"url"`
	Method          string             `json:"method"`
	StatusCode      int                `json:"status_code,omitempty"`
	ContentType     string             `json:"content_type,omitempty"`
	Parameters      []string           `json:"parameters,omitempty"`
	Headers         map[string]string  `json:"headers,omitempty"`
	ResponseHeaders map[string]string  `json:"response_headers,omitempty"`
	Body            string             `json:"body,omitempty"`
	Categories      []EndpointCategory `json:"categories,omitempty"`
}

// HasCategory returns true if the endpoint has the given category.
func (e Endpoint) HasCategory(cat EndpointCategory) bool {
	for _, c := range e.Categories {
		if c == cat {
			return true
		}
	}
	return false
}

// ClassifiedEndpoints provides categorized views of discovered endpoints.
type ClassifiedEndpoints struct {
	All        []Endpoint
	Login      []Endpoint
	API        []Endpoint
	FileUpload []Endpoint
	Admin      []Endpoint
	Search     []Endpoint
	UserData   []Endpoint
	Redirect   []Endpoint
	GraphQL    []Endpoint
}

// AuthConfig holds authentication configuration for a scan session.
type AuthConfig struct {
	Method   string            `json:"method,omitempty"`   // form, json, bearer, cookie, header, auto
	LoginURL string            `json:"login_url,omitempty"`
	Username string            `json:"username,omitempty"`
	Password string            `json:"password,omitempty"`
	Token    string            `json:"token,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Cookies  map[string]string `json:"cookies,omitempty"`
	NoAuth   bool              `json:"no_auth,omitempty"`
}

// ScanConfig holds configuration for a scan session.
type ScanConfig struct {
	Target      Target      `json:"target"`
	MaxLoops    int         `json:"max_loops"`
	FinalBoss   bool        `json:"final_boss"`
	SkipBlue    bool        `json:"skip_blue"`
	Verbose     bool        `json:"verbose,omitempty"`
	Provider    string      `json:"provider"`
	Model       string      `json:"model"`
	ReconConfig ReconConfig `json:"recon_config,omitempty"`
	AuthConfig  AuthConfig  `json:"auth_config,omitempty"`
}

// ScanSession represents an entire scan lifecycle.
type ScanSession struct {
	ID          string       `json:"id"`
	Config      ScanConfig   `json:"config"`
	Loops       []LoopResult `json:"loops"`
	Converged   bool         `json:"converged"`
	StartedAt   time.Time    `json:"started_at"`
	FinishedAt  time.Time    `json:"finished_at,omitempty"`
	TotalFindings int        `json:"total_findings"`
}

// NewScanSession creates a new scan session with defaults.
func NewScanSession(cfg ScanConfig) *ScanSession {
	return &ScanSession{
		ID:        uuid.New().String(),
		Config:    cfg,
		Loops:     make([]LoopResult, 0),
		StartedAt: time.Now(),
	}
}

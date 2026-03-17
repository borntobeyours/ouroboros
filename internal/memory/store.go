package memory

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// Store provides persistent storage for findings, patterns, and playbooks.
type Store struct {
	db *sql.DB
}

// NewStore creates or opens the SQLite database.
func NewStore(dbPath string) (*Store, error) {
	if dbPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dir := filepath.Join(home, ".ouroboros")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		dbPath = filepath.Join(dir, "ouroboros.db")
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}

	return store, nil
}

func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		config TEXT NOT NULL,
		started_at DATETIME NOT NULL,
		finished_at DATETIME,
		converged BOOLEAN DEFAULT FALSE,
		total_findings INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS findings (
		id TEXT NOT NULL,
		session_id TEXT NOT NULL,
		loop INTEGER NOT NULL,
		title TEXT NOT NULL,
		severity TEXT NOT NULL,
		description TEXT,
		endpoint TEXT,
		method TEXT,
		cwe TEXT,
		poc TEXT,
		evidence TEXT,
		technique TEXT,
		confirmed BOOLEAN DEFAULT FALSE,
		confidence INTEGER DEFAULT 0,
		cvss_score REAL DEFAULT 0,
		cvss_vector TEXT,
		adjusted_severity TEXT,
		exploit_evidence TEXT,
		exfiltrated_data TEXT,
		remediation TEXT,
		found_at DATETIME NOT NULL,
		FOREIGN KEY (session_id) REFERENCES sessions(id)
	);

	CREATE TABLE IF NOT EXISTS patches (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL,
		finding_id TEXT NOT NULL,
		description TEXT,
		code TEXT,
		config_change TEXT,
		hardening TEXT,
		confidence TEXT,
		FOREIGN KEY (session_id) REFERENCES sessions(id)
	);

	CREATE TABLE IF NOT EXISTS playbooks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		technique TEXT NOT NULL,
		target_type TEXT,
		payload TEXT NOT NULL,
		success_rate REAL DEFAULT 0,
		last_used DATETIME,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS bypasses (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		original_finding_id TEXT NOT NULL,
		patch_description TEXT,
		bypass_technique TEXT NOT NULL,
		bypass_payload TEXT,
		created_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
	CREATE INDEX IF NOT EXISTS idx_findings_technique ON findings(technique);
	CREATE INDEX IF NOT EXISTS idx_playbooks_technique ON playbooks(technique);
	`
	_, err := s.db.Exec(schema)
	return err
}

// SaveSession stores a scan session.
func (s *Store) SaveSession(session *types.ScanSession) error {
	configJSON, err := json.Marshal(session.Config)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO sessions (id, config, started_at, finished_at, converged, total_findings) VALUES (?, ?, ?, ?, ?, ?)`,
		session.ID, string(configJSON), session.StartedAt, session.FinishedAt, session.Converged, session.TotalFindings,
	)
	return err
}

// SaveFinding stores a finding.
func (s *Store) SaveFinding(sessionID string, f types.Finding) error {
	_, err := s.db.Exec(
		`INSERT INTO findings (id, session_id, loop, title, severity, description, endpoint, method, cwe, poc, evidence, technique, confirmed, confidence, cvss_score, cvss_vector, adjusted_severity, exploit_evidence, exfiltrated_data, remediation, found_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, sessionID, f.Loop, f.Title, f.Severity.String(), f.Description, f.Endpoint, f.Method, f.CWE, f.PoC, f.Evidence, f.Technique, f.Confirmed, int(f.Confidence), f.CVSS.Score, f.CVSS.Vector, f.AdjustedSeverity.String(), f.ExploitEvidence, f.ExfiltratedData, f.Remediation, f.FoundAt,
	)
	return err
}

// SavePatch stores a patch.
func (s *Store) SavePatch(sessionID string, p types.Patch) error {
	_, err := s.db.Exec(
		`INSERT INTO patches (session_id, finding_id, description, code, config_change, hardening, confidence)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sessionID, p.FindingID, p.Description, p.Code, p.ConfigChange, p.Hardening, p.Confidence,
	)
	return err
}

// GetSessionFindings retrieves all findings for a session.
func (s *Store) GetSessionFindings(sessionID string) ([]types.Finding, error) {
	rows, err := s.db.Query(
		`SELECT id, loop, title, severity, description, endpoint, method, cwe, poc, evidence, technique, confirmed, confidence, cvss_score, cvss_vector, adjusted_severity, exploit_evidence, exfiltrated_data, remediation, found_at
		 FROM findings WHERE session_id = ? ORDER BY found_at`,
		sessionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []types.Finding
	for rows.Next() {
		var f types.Finding
		var sevStr string
		var adjSevStr sql.NullString
		var confidence int
		var cvssScore float64
		var cvssVector sql.NullString
		var exploitEvidence, exfilData, remediation sql.NullString
		if err := rows.Scan(&f.ID, &f.Loop, &f.Title, &sevStr, &f.Description, &f.Endpoint, &f.Method, &f.CWE, &f.PoC, &f.Evidence, &f.Technique, &f.Confirmed, &confidence, &cvssScore, &cvssVector, &adjSevStr, &exploitEvidence, &exfilData, &remediation, &f.FoundAt); err != nil {
			return nil, err
		}
		f.Severity, _ = types.ParseSeverity(sevStr)
		f.Confidence = types.Confidence(confidence)
		f.CVSS.Score = cvssScore
		if cvssVector.Valid {
			f.CVSS.Vector = cvssVector.String
		}
		if adjSevStr.Valid {
			f.AdjustedSeverity, _ = types.ParseSeverity(adjSevStr.String)
		}
		if exploitEvidence.Valid {
			f.ExploitEvidence = exploitEvidence.String
		}
		if exfilData.Valid {
			f.ExfiltratedData = exfilData.String
		}
		if remediation.Valid {
			f.Remediation = remediation.String
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// GetSession retrieves a session by ID.
func (s *Store) GetSession(sessionID string) (*types.ScanSession, error) {
	row := s.db.QueryRow(
		`SELECT id, config, started_at, finished_at, converged, total_findings FROM sessions WHERE id = ?`,
		sessionID,
	)

	var session types.ScanSession
	var configJSON string
	var finishedAt sql.NullTime
	if err := row.Scan(&session.ID, &configJSON, &session.StartedAt, &finishedAt, &session.Converged, &session.TotalFindings); err != nil {
		return nil, err
	}
	if finishedAt.Valid {
		session.FinishedAt = finishedAt.Time
	}
	if err := json.Unmarshal([]byte(configJSON), &session.Config); err != nil {
		return nil, err
	}
	return &session, nil
}

// ListSessions returns recent sessions.
func (s *Store) ListSessions(limit int) ([]types.ScanSession, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(
		`SELECT id, config, started_at, finished_at, converged, total_findings FROM sessions ORDER BY started_at DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []types.ScanSession
	for rows.Next() {
		var session types.ScanSession
		var configJSON string
		var finishedAt sql.NullTime
		if err := rows.Scan(&session.ID, &configJSON, &session.StartedAt, &finishedAt, &session.Converged, &session.TotalFindings); err != nil {
			return nil, err
		}
		if finishedAt.Valid {
			session.FinishedAt = finishedAt.Time
		}
		if err := json.Unmarshal([]byte(configJSON), &session.Config); err != nil {
			continue
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// RecordPlaybookEntry records a successful attack pattern.
func (s *Store) RecordPlaybookEntry(technique, targetType, payload string) error {
	_, err := s.db.Exec(
		`INSERT INTO playbooks (technique, target_type, payload, success_rate, last_used, created_at)
		 VALUES (?, ?, ?, 1.0, ?, ?)`,
		technique, targetType, payload, time.Now(), time.Now(),
	)
	return err
}

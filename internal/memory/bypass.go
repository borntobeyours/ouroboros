package memory

import "time"

// BypassEntry records when a patch was successfully bypassed.
type BypassEntry struct {
	ID               int
	OriginalFindingID string
	PatchDescription string
	BypassTechnique  string
	BypassPayload    string
	CreatedAt        time.Time
}

// RecordBypass stores a successful bypass of a patch.
func (s *Store) RecordBypass(originalFindingID, patchDescription, bypassTechnique, bypassPayload string) error {
	_, err := s.db.Exec(
		`INSERT INTO bypasses (original_finding_id, patch_description, bypass_technique, bypass_payload, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		originalFindingID, patchDescription, bypassTechnique, bypassPayload, time.Now(),
	)
	return err
}

// GetBypasses retrieves all bypasses for a finding.
func (s *Store) GetBypasses(findingID string) ([]BypassEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, original_finding_id, patch_description, bypass_technique, bypass_payload, created_at
		 FROM bypasses WHERE original_finding_id = ?`,
		findingID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []BypassEntry
	for rows.Next() {
		var e BypassEntry
		if err := rows.Scan(&e.ID, &e.OriginalFindingID, &e.PatchDescription, &e.BypassTechnique, &e.BypassPayload, &e.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

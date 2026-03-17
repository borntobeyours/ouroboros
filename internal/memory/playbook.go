package memory

import "time"

// PlaybookEntry represents a successful attack pattern.
type PlaybookEntry struct {
	ID          int
	Technique   string
	TargetType  string
	Payload     string
	SuccessRate float64
	LastUsed    time.Time
	CreatedAt   time.Time
}

// GetPlaybook retrieves attack playbook entries for a technique.
func (s *Store) GetPlaybook(technique string) ([]PlaybookEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, technique, target_type, payload, success_rate, last_used, created_at
		 FROM playbooks WHERE technique = ? ORDER BY success_rate DESC`,
		technique,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []PlaybookEntry
	for rows.Next() {
		var e PlaybookEntry
		if err := rows.Scan(&e.ID, &e.Technique, &e.TargetType, &e.Payload, &e.SuccessRate, &e.LastUsed, &e.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// UpdatePlaybookSuccess updates the success rate of a playbook entry.
func (s *Store) UpdatePlaybookSuccess(id int, success bool) error {
	var adjust string
	if success {
		adjust = "MIN(success_rate + 0.1, 1.0)"
	} else {
		adjust = "MAX(success_rate - 0.1, 0.0)"
	}
	_, err := s.db.Exec(
		`UPDATE playbooks SET success_rate = `+adjust+`, last_used = ? WHERE id = ?`,
		time.Now(), id,
	)
	return err
}

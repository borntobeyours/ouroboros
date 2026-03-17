package engine

import (
	"github.com/borntobeyours/ouroboros/internal/memory"
	"github.com/borntobeyours/ouroboros/pkg/types"
)

// SessionManager handles scan session persistence.
type SessionManager struct {
	store *memory.Store
}

// NewSessionManager creates a new session manager.
func NewSessionManager(store *memory.Store) *SessionManager {
	return &SessionManager{store: store}
}

// Save persists the session and all its findings/patches.
func (sm *SessionManager) Save(session *types.ScanSession) error {
	if err := sm.store.SaveSession(session); err != nil {
		return err
	}

	for _, loop := range session.Loops {
		for _, f := range loop.Findings {
			if err := sm.store.SaveFinding(session.ID, f); err != nil {
				return err
			}
		}
		for _, p := range loop.Patches {
			if err := sm.store.SavePatch(session.ID, p); err != nil {
				return err
			}
		}
	}

	return nil
}

// Load retrieves a session and its findings.
func (sm *SessionManager) Load(sessionID string) (*types.ScanSession, []types.Finding, error) {
	session, err := sm.store.GetSession(sessionID)
	if err != nil {
		return nil, nil, err
	}

	findings, err := sm.store.GetSessionFindings(sessionID)
	if err != nil {
		return nil, nil, err
	}

	return session, findings, nil
}

// ListRecent returns recent sessions.
func (sm *SessionManager) ListRecent(limit int) ([]types.ScanSession, error) {
	return sm.store.ListSessions(limit)
}

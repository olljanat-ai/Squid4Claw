// Package approval implements the default-deny host approval system.
package approval
 
import (
	"sync"
	"time"
)
 
// Status represents the approval state of a host.
type Status string
 
const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
)
 
// HostApproval tracks the approval state for a specific host+skill combination.
type HostApproval struct {
	Host      string    `json:"host"`
	SkillID   string    `json:"skill_id"`
	Status    Status    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Note      string    `json:"note"`
}
 
// key returns the unique key for a host+skill.
func key(host, skillID string) string {
	return skillID + "|" + host
}
 
// Manager manages host approval decisions.
type Manager struct {
	mu        sync.RWMutex
	approvals map[string]*HostApproval
	waiters   map[string][]chan Status // channels waiting for approval decision
}
 
// NewManager creates a new approval manager.
func NewManager() *Manager {
	return &Manager{
		approvals: make(map[string]*HostApproval),
		waiters:   make(map[string][]chan Status),
	}
}
 
// CheckExisting returns the current status for a host+skill without creating
// a pending entry. Returns the status and whether an entry exists.
func (m *Manager) CheckExisting(host, skillID string) (Status, bool) {
	k := key(host, skillID)
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.approvals[k]
	if !ok {
		return "", false
	}
	return a.Status, true
}

// Check returns the current status for a host+skill, or StatusPending if unknown.
// If the host is new, it registers it as pending.
func (m *Manager) Check(host, skillID string) Status {
	k := key(host, skillID)
	m.mu.RLock()
	a, ok := m.approvals[k]
	m.mu.RUnlock()
	if ok {
		return a.Status
	}
 
	// Register as pending.
	m.mu.Lock()
	defer m.mu.Unlock()
	// Double-check after acquiring write lock.
	if a, ok := m.approvals[k]; ok {
		return a.Status
	}
	m.approvals[k] = &HostApproval{
		Host:      host,
		SkillID:   skillID,
		Status:    StatusPending,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return StatusPending
}
 
// WaitForDecision blocks until a decision is made for the host+skill.
// Returns the decision status. Caller should first call Check to register.
func (m *Manager) WaitForDecision(host, skillID string, timeout time.Duration) Status {
	k := key(host, skillID)
 
	// Check if already decided.
	m.mu.RLock()
	if a, ok := m.approvals[k]; ok && a.Status != StatusPending {
		m.mu.RUnlock()
		return a.Status
	}
	m.mu.RUnlock()
 
	ch := make(chan Status, 1)
	m.mu.Lock()
	// Check again under write lock.
	if a, ok := m.approvals[k]; ok && a.Status != StatusPending {
		m.mu.Unlock()
		return a.Status
	}
	m.waiters[k] = append(m.waiters[k], ch)
	m.mu.Unlock()
 
	timer := time.NewTimer(timeout)
	defer timer.Stop()
 
	select {
	case status := <-ch:
		return status
	case <-timer.C:
		return StatusDenied // timeout = deny
	}
}
 
// Decide sets the approval status for a host+skill and notifies waiters.
func (m *Manager) Decide(host, skillID string, status Status, note string) {
	k := key(host, skillID)
	m.mu.Lock()
	defer m.mu.Unlock()
 
	a, ok := m.approvals[k]
	if !ok {
		a = &HostApproval{
			Host:      host,
			SkillID:   skillID,
			CreatedAt: time.Now(),
		}
		m.approvals[k] = a
	}
	a.Status = status
	a.UpdatedAt = time.Now()
	a.Note = note
 
	// Notify all waiters.
	if waiters, ok := m.waiters[k]; ok {
		for _, ch := range waiters {
			select {
			case ch <- status:
			default:
			}
		}
		delete(m.waiters, k)
	}
}
 
// ListPending returns all pending approvals.
func (m *Manager) ListPending() []HostApproval {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []HostApproval
	for _, a := range m.approvals {
		if a.Status == StatusPending {
			result = append(result, *a)
		}
	}
	return result
}
 
// ListAll returns all approvals.
func (m *Manager) ListAll() []HostApproval {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]HostApproval, 0, len(m.approvals))
	for _, a := range m.approvals {
		result = append(result, *a)
	}
	return result
}
 
// LoadApprovals bulk-loads approvals (used at startup).
func (m *Manager) LoadApprovals(approvals []HostApproval) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.approvals = make(map[string]*HostApproval)
	for i := range approvals {
		a := &approvals[i]
		m.approvals[key(a.Host, a.SkillID)] = a
	}
}
 
// Export returns all approvals for persistence.
func (m *Manager) Export() []HostApproval {
	return m.ListAll()
}

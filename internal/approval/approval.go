// Package approval implements the default-deny host approval system
// with three levels: global, VM-specific (by source IP), and skill-specific.
package approval

import (
	"strings"
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

// HostApproval tracks the approval state for a host at a specific level.
// Three levels exist:
//   - Global:    SkillID="" and SourceIP="" — applies to all agents on all VMs
//   - VM:        SkillID="" and SourceIP set — applies to all agents on that VM
//   - Skill:     SkillID set and SourceIP="" — applies to agents using that skill
type HostApproval struct {
	Host      string    `json:"host"`
	SkillID   string    `json:"skill_id"`
	SourceIP  string    `json:"source_ip"`
	Status    Status    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Note      string    `json:"note"`
}

// key returns the unique key for a host+skill+sourceIP combination.
func key(host, skillID, sourceIP string) string {
	return sourceIP + "|" + skillID + "|" + host
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

// CheckExisting returns the current status for a host+skill+sourceIP without
// creating a pending entry. Returns the status and whether an entry exists.
func (m *Manager) CheckExisting(host, skillID, sourceIP string) (Status, bool) {
	k := key(host, skillID, sourceIP)
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.approvals[k]
	if !ok {
		return "", false
	}
	return a.Status, true
}

// Check returns the current status for a host+skill+sourceIP, or StatusPending
// if unknown. If the combination is new, it registers it as pending.
func (m *Manager) Check(host, skillID, sourceIP string) Status {
	k := key(host, skillID, sourceIP)
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
		SourceIP:  sourceIP,
		Status:    StatusPending,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return StatusPending
}

// WaitForDecision blocks until a decision is made for the host+skill+sourceIP.
// Returns the decision status. Caller should first call Check to register.
func (m *Manager) WaitForDecision(host, skillID, sourceIP string, timeout time.Duration) Status {
	k := key(host, skillID, sourceIP)

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

// Decide sets the approval status and notifies waiters. When a broader level
// is approved (e.g. global), it cascades notifications to narrower pending
// entries (e.g. VM-specific or skill-specific waiters for the same host).
func (m *Manager) Decide(host, skillID, sourceIP string, status Status, note string) {
	k := key(host, skillID, sourceIP)
	m.mu.Lock()
	defer m.mu.Unlock()

	a, ok := m.approvals[k]
	if !ok {
		a = &HostApproval{
			Host:      host,
			SkillID:   skillID,
			SourceIP:  sourceIP,
			CreatedAt: time.Now(),
		}
		m.approvals[k] = a
	}
	a.Status = status
	a.UpdatedAt = time.Now()
	a.Note = note

	// Notify waiters with cascading based on approval level.
	hostSuffix := "|" + host
	isGlobal := skillID == "" && sourceIP == ""
	isVM := skillID == "" && sourceIP != ""

	for wk, waiters := range m.waiters {
		if !strings.HasSuffix(wk, hostSuffix) {
			continue
		}

		shouldNotify := false
		if wk == k {
			shouldNotify = true
		} else if isGlobal {
			// Global: notify all waiters for this host.
			shouldNotify = true
		} else if isVM {
			// VM: notify waiters from same IP for this host.
			shouldNotify = strings.HasPrefix(wk, sourceIP+"|")
		} else if skillID != "" {
			// Skill: notify waiters with same skill for this host.
			shouldNotify = strings.HasSuffix(wk, "|"+skillID+"|"+host)
		}

		if shouldNotify {
			for _, ch := range waiters {
				select {
				case ch <- status:
				default:
				}
			}
			delete(m.waiters, wk)
		}
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
		m.approvals[key(a.Host, a.SkillID, a.SourceIP)] = a
	}
}

// Export returns all approvals for persistence.
func (m *Manager) Export() []HostApproval {
	return m.ListAll()
}

// Package auth handles AI agent skill-token authentication and rulesets.
package auth
 
import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
)
 
// Skill represents an AI agent skill with its own token and rules.
type Skill struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Token       string   `json:"token"`
	AllowedHost []string `json:"allowed_hosts"` // hosts pre-approved for this skill
	Active      bool     `json:"active"`
}
 
// SkillStore manages skills and their tokens.
type SkillStore struct {
	mu     sync.RWMutex
	skills map[string]*Skill // keyed by token
	byID   map[string]*Skill // keyed by ID
}
 
// NewSkillStore creates a new empty skill store.
func NewSkillStore() *SkillStore {
	return &SkillStore{
		skills: make(map[string]*Skill),
		byID:   make(map[string]*Skill),
	}
}
 
// GenerateToken creates a cryptographically random token.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
 
// AddSkill registers a new skill with its token.
func (s *SkillStore) AddSkill(skill Skill) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byID[skill.ID]; exists {
		return fmt.Errorf("skill %q already exists", skill.ID)
	}
	s.skills[skill.Token] = &skill
	s.byID[skill.ID] = &skill
	return nil
}
 
// UpdateSkill updates an existing skill.
func (s *SkillStore) UpdateSkill(skill Skill) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.byID[skill.ID]
	if !ok {
		return fmt.Errorf("skill %q not found", skill.ID)
	}
	// Remove old token mapping.
	delete(s.skills, existing.Token)
	// Update.
	*existing = skill
	s.skills[skill.Token] = existing
	return nil
}
 
// DeleteSkill removes a skill.
func (s *SkillStore) DeleteSkill(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	skill, ok := s.byID[id]
	if !ok {
		return fmt.Errorf("skill %q not found", id)
	}
	delete(s.skills, skill.Token)
	delete(s.byID, id)
	return nil
}
 
// Authenticate checks a token and returns the associated skill.
func (s *SkillStore) Authenticate(token string) (*Skill, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	skill, ok := s.skills[token]
	if !ok || !skill.Active {
		return nil, false
	}
	return skill, true
}
 
// IsHostPreApproved checks if a host is in the skill's allowed list.
func (s *SkillStore) IsHostPreApproved(token, host string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	skill, ok := s.skills[token]
	if !ok {
		return false
	}
	for _, h := range skill.AllowedHost {
		if h == host || h == "*" {
			return true
		}
	}
	return false
}
 
// ListSkills returns all skills.
func (s *SkillStore) ListSkills() []Skill {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Skill, 0, len(s.byID))
	for _, sk := range s.byID {
		result = append(result, *sk)
	}
	return result
}
 
// LoadSkills bulk-loads skills (used at startup).
func (s *SkillStore) LoadSkills(skills []Skill) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.skills = make(map[string]*Skill)
	s.byID = make(map[string]*Skill)
	for i := range skills {
		sk := &skills[i]
		s.skills[sk.Token] = sk
		s.byID[sk.ID] = sk
	}
}

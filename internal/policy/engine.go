package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/harrykodden/s3-gateway/internal/config"
	"github.com/sirupsen/logrus"
)

// Engine evaluates S3 policies
type Engine struct {
	policies     map[string]*Policy
	policiesLock sync.RWMutex
	config       config.PoliciesConfig
	logger       *logrus.Logger
	lastLoad     time.Time
}

// Policy represents an S3 policy document
type Policy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// Statement represents a policy statement
type Statement struct {
	Sid       string                            `json:"Sid,omitempty"`
	Effect    string                            `json:"Effect"`   // Allow or Deny
	Action    interface{}                       `json:"Action"`   // string or []string
	Resource  interface{}                       `json:"Resource"` // string or []string
	Condition map[string]map[string]interface{} `json:"Condition,omitempty"`
}

// EvaluationContext contains request context for policy evaluation
type EvaluationContext struct {
	Action   string
	Bucket   string
	Key      string
	Resource string
	UserID   string
	Roles    []string
}

// Decision represents the result of policy evaluation
type Decision struct {
	Allowed bool
	Reason  string
	Policy  string
}

// NewEngine creates a new policy engine
func NewEngine(cfg config.PoliciesConfig, logger *logrus.Logger) (*Engine, error) {
	engine := &Engine{
		policies: make(map[string]*Policy),
		config:   cfg,
		logger:   logger,
	}

	// Load policies
	if err := engine.LoadPolicies(); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	// Start background refresh if caching is enabled
	if cfg.CacheEnabled {
		go engine.refreshLoop()
	}

	return engine, nil
}

// GetPolicyNames returns the names of all loaded policies
func (e *Engine) GetPolicyNames() []string {
	e.policiesLock.RLock()
	defer e.policiesLock.RUnlock()

	names := make([]string, 0, len(e.policies))
	for name := range e.policies {
		names = append(names, name)
	}
	return names
}

// LoadPolicies loads all policy files from the configured directory
func (e *Engine) LoadPolicies() error {
	e.policiesLock.Lock()
	defer e.policiesLock.Unlock()

	newPolicies := make(map[string]*Policy)

	// Check if directory exists
	if _, err := os.Stat(e.config.Directory); os.IsNotExist(err) {
		e.logger.WithField("directory", e.config.Directory).Warn("Policy directory does not exist")
		e.policies = newPolicies
		e.lastLoad = time.Now()
		return nil
	}

	// Read all JSON files in the directory
	entries, err := os.ReadDir(e.config.Directory)
	if err != nil {
		return fmt.Errorf("failed to read policy directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		policyName := strings.TrimSuffix(entry.Name(), ".json")
		policyPath := filepath.Join(e.config.Directory, entry.Name())

		policy, err := e.loadPolicyFile(policyPath)
		if err != nil {
			e.logger.WithError(err).WithField("file", entry.Name()).Error("Failed to load policy file")
			continue
		}

		newPolicies[policyName] = policy
		e.logger.WithFields(logrus.Fields{
			"policy": policyName,
			"file":   entry.Name(),
		}).Info("Loaded policy")
	}

	e.policies = newPolicies
	e.lastLoad = time.Now()
	e.logger.WithField("count", len(newPolicies)).Info("Policies loaded")

	return nil
}

// loadPolicyFile loads a single policy file
func (e *Engine) loadPolicyFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy JSON: %w", err)
	}

	return &policy, nil
}

// Evaluate evaluates policies for the given context
func (e *Engine) Evaluate(ctx *EvaluationContext) *Decision {
	e.policiesLock.RLock()
	defer e.policiesLock.RUnlock()

	e.logger.WithFields(logrus.Fields{
		"action":   ctx.Action,
		"bucket":   ctx.Bucket,
		"key":      ctx.Key,
		"resource": ctx.Resource,
		"roles":    ctx.Roles,
		"user":     ctx.UserID,
	}).Debug("Evaluating policies")

	// Collect applicable policies based on roles
	applicablePolicies := make([]*Policy, 0)
	matchedRoles := make([]string, 0)

	for _, role := range ctx.Roles {
		if policy, exists := e.policies[role]; exists {
			applicablePolicies = append(applicablePolicies, policy)
			matchedRoles = append(matchedRoles, role)
		}
	}

	if len(applicablePolicies) == 0 {
		if e.config.DefaultDeny {
			return &Decision{
				Allowed: false,
				Reason:  "No matching policies found for user roles",
			}
		} else {
			return &Decision{
				Allowed: true,
				Reason:  "Default allow (no policies configured)",
			}
		}
	}

	// Evaluate policies: explicit deny overrides allow
	hasExplicitDeny := false
	hasExplicitAllow := false
	var allowReason, denyReason string

	for i, policy := range applicablePolicies {
		for _, statement := range policy.Statement {
			if !e.matchesAction(statement, ctx.Action) {
				continue
			}

			if !e.matchesResource(statement, ctx.Resource) {
				continue
			}

			// Statement matches - check effect
			if statement.Effect == "Deny" {
				hasExplicitDeny = true
				denyReason = fmt.Sprintf("Denied by policy %s", matchedRoles[i])
				break
			} else if statement.Effect == "Allow" {
				hasExplicitAllow = true
				allowReason = fmt.Sprintf("Allowed by policy %s", matchedRoles[i])
			}
		}

		if hasExplicitDeny {
			break
		}
	}

	// Explicit deny always wins
	if hasExplicitDeny {
		return &Decision{
			Allowed: false,
			Reason:  denyReason,
			Policy:  strings.Join(matchedRoles, ","),
		}
	}

	// If we have an explicit allow, grant access
	if hasExplicitAllow {
		return &Decision{
			Allowed: true,
			Reason:  allowReason,
			Policy:  strings.Join(matchedRoles, ","),
		}
	}

	// Default deny if no explicit allow
	return &Decision{
		Allowed: false,
		Reason:  "No explicit allow statement found",
		Policy:  strings.Join(matchedRoles, ","),
	}
}

// matchesAction checks if the action matches the statement
func (e *Engine) matchesAction(statement Statement, action string) bool {
	actions := e.normalizeStringOrArray(statement.Action)
	for _, allowedAction := range actions {
		if e.matchesPattern(allowedAction, action) {
			return true
		}
	}
	return false
}

// matchesResource checks if the resource matches the statement
func (e *Engine) matchesResource(statement Statement, resource string) bool {
	resources := e.normalizeStringOrArray(statement.Resource)
	for _, allowedResource := range resources {
		if e.matchesPattern(allowedResource, resource) {
			return true
		}
	}
	return false
}

// matchesPattern checks if a pattern matches a value (supports wildcards)
func (e *Engine) matchesPattern(pattern, value string) bool {
	// Exact match
	if pattern == value {
		return true
	}

	// Wildcard match
	if strings.Contains(pattern, "*") {
		// Convert wildcard pattern to regex
		regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, "\\*", ".*")

		matched, err := regexp.MatchString(regexPattern, value)
		if err != nil {
			e.logger.WithError(err).WithFields(logrus.Fields{
				"pattern": pattern,
				"value":   value,
			}).Error("Failed to match pattern")
			return false
		}

		return matched
	}

	return false
}

// normalizeStringOrArray converts string or []string to []string
func (e *Engine) normalizeStringOrArray(value interface{}) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	default:
		return []string{}
	}
}

// refreshLoop periodically reloads policies
func (e *Engine) refreshLoop() {
	ticker := time.NewTicker(e.config.CacheTTL)
	defer ticker.Stop()

	for range ticker.C {
		e.logger.Debug("Refreshing policies")
		if err := e.LoadPolicies(); err != nil {
			e.logger.WithError(err).Error("Failed to refresh policies")
		}
	}
}

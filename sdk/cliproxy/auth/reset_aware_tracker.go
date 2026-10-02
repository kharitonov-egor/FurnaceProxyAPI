package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const resetAwareStateVersion = 1

// AccountLimits is the reset-aware view of one credential's limits, merged from response
// headers and usage endpoints. The freshest observation of each window wins.
type AccountLimits struct {
	Provider              string               `json:"provider"`
	FiveHour              LimitWindow          `json:"five_hour"`
	Weekly                LimitWindow          `json:"weekly"`
	Buckets               []LimitBucket        `json:"buckets,omitempty"`
	ObservedAt            time.Time            `json:"observed_at"`
	Source                string               `json:"source,omitempty"`
	HeaderObservedAt      time.Time            `json:"header_observed_at,omitempty"`
	ModelHeaderObservedAt map[string]time.Time `json:"model_header_observed_at,omitempty"`
	UsageObservedAt       time.Time            `json:"usage_observed_at,omitempty"`
	LastResetAt           time.Time            `json:"last_reset_detected_at,omitempty"`
	NextRefreshAt         time.Time            `json:"next_refresh_at,omitempty"`
	LastRefreshError      string               `json:"last_refresh_error,omitempty"`
}

func (a AccountLimits) clone() AccountLimits {
	out := a
	if len(a.Buckets) > 0 {
		out.Buckets = make([]LimitBucket, len(a.Buckets))
		for i, bucket := range a.Buckets {
			bucket.Models = append([]string(nil), bucket.Models...)
			out.Buckets[i] = bucket
		}
	}
	if len(a.ModelHeaderObservedAt) > 0 {
		out.ModelHeaderObservedAt = make(map[string]time.Time, len(a.ModelHeaderObservedAt))
		for model, at := range a.ModelHeaderObservedAt {
			out.ModelHeaderObservedAt[model] = at
		}
	}
	return out
}

// ResetAwareTracker caches per-credential limit data for the reset-aware strategy and
// persists it so ranking survives restarts before fresh data arrives.
type ResetAwareTracker struct {
	mu        sync.Mutex
	accounts  map[string]*AccountLimits
	statePath string
	dirty     bool
}

type resetAwareStateFile struct {
	Version  int                       `json:"version"`
	SavedAt  time.Time                 `json:"saved_at"`
	Accounts map[string]*AccountLimits `json:"accounts"`
}

// NewResetAwareTracker creates a tracker and loads statePath when it exists. An empty
// statePath keeps the cache in memory only.
func NewResetAwareTracker(statePath string) *ResetAwareTracker {
	tracker := &ResetAwareTracker{accounts: make(map[string]*AccountLimits), statePath: strings.TrimSpace(statePath)}
	if errLoad := tracker.load(); errLoad != nil && !errors.Is(errLoad, os.ErrNotExist) {
		log.Warnf("reset-aware: ignoring unreadable state file %s: %v", tracker.statePath, errLoad)
	}
	return tracker
}

// StatePath returns the file the tracker persists to, or "" for memory only.
func (t *ResetAwareTracker) StatePath() string {
	if t == nil {
		return ""
	}
	return t.statePath
}

func (t *ResetAwareTracker) load() error {
	if t.statePath == "" {
		return nil
	}
	data, errRead := os.ReadFile(t.statePath)
	if errRead != nil {
		return errRead
	}
	var state resetAwareStateFile
	if errDecode := json.Unmarshal(data, &state); errDecode != nil {
		return fmt.Errorf("decode: %w", errDecode)
	}
	if state.Version != resetAwareStateVersion {
		return fmt.Errorf("unsupported version %d", state.Version)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, limits := range state.Accounts {
		if limits != nil && strings.TrimSpace(id) != "" {
			t.accounts[id] = limits
		}
	}
	return nil
}

// Save writes the cache when it changed since the last save.
func (t *ResetAwareTracker) Save() error {
	if t == nil || t.statePath == "" {
		return nil
	}
	t.mu.Lock()
	if !t.dirty {
		t.mu.Unlock()
		return nil
	}
	state := resetAwareStateFile{Version: resetAwareStateVersion, SavedAt: time.Now(), Accounts: make(map[string]*AccountLimits, len(t.accounts))}
	for id, limits := range t.accounts {
		snapshot := limits.clone()
		state.Accounts[id] = &snapshot
	}
	t.dirty = false
	t.mu.Unlock()

	data, errEncode := json.MarshalIndent(state, "", "  ")
	if errEncode != nil {
		t.markDirty()
		return fmt.Errorf("encode reset-aware state: %w", errEncode)
	}
	if errWrite := writeFileAtomic(t.statePath, data); errWrite != nil {
		t.markDirty()
		return errWrite
	}
	return nil
}

func (t *ResetAwareTracker) markDirty() {
	t.mu.Lock()
	t.dirty = true
	t.mu.Unlock()
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if errMkdir := os.MkdirAll(dir, 0o700); errMkdir != nil {
		return fmt.Errorf("create state dir: %w", errMkdir)
	}
	tmp, errCreate := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if errCreate != nil {
		return fmt.Errorf("create temp state file: %w", errCreate)
	}
	tmpName := tmp.Name()
	defer func() {
		if errRemove := os.Remove(tmpName); errRemove != nil && !errors.Is(errRemove, os.ErrNotExist) {
			log.Debugf("reset-aware: remove temp state file: %v", errRemove)
		}
	}()
	if errChmod := tmp.Chmod(0o600); errChmod != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp state file: %w", errChmod)
	}
	if _, errWrite := tmp.Write(data); errWrite != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp state file: %w", errWrite)
	}
	if errClose := tmp.Close(); errClose != nil {
		return fmt.Errorf("close temp state file: %w", errClose)
	}
	if errRename := os.Rename(tmpName, path); errRename != nil {
		return fmt.Errorf("replace state file: %w", errRename)
	}
	return nil
}

func parseHeaderObservation(provider string, signals map[string]string, observedAt time.Time) (LimitObservation, bool) {
	if len(signals) == 0 {
		return LimitObservation{}, false
	}
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex":
		return ParseCodexHeaderSignals(signals, observedAt)
	case "claude":
		return ParseClaudeHeaderSignals(signals, observedAt)
	default:
		return LimitObservation{}, false
	}
}

// ObserveAuth folds the passive header snapshots upstream keeps on the auth (credential
// level and per model) into the tracker. Snapshots already seen are skipped.
func (t *ResetAwareTracker) ObserveAuth(auth *Auth) {
	if t == nil || auth == nil || !ResetAwareProviderSupported(auth.Provider) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	current := t.accounts[auth.ID]
	if observedAt := auth.Quota.ObservedAt; !observedAt.IsZero() && (current == nil || observedAt.After(current.HeaderObservedAt)) {
		if obs, ok := parseHeaderObservation(auth.Provider, auth.Quota.Signals, observedAt); ok {
			current = t.applyLocked(auth.ID, obs)
			current.HeaderObservedAt = observedAt
		}
	}
	for model, state := range auth.ModelStates {
		if state == nil || state.Quota.ObservedAt.IsZero() {
			continue
		}
		if current != nil && !state.Quota.ObservedAt.After(current.ModelHeaderObservedAt[model]) {
			continue
		}
		obs, ok := parseHeaderObservation(auth.Provider, state.Quota.Signals, state.Quota.ObservedAt)
		if !ok {
			continue
		}
		for i := range obs.Buckets {
			obs.Buckets[i].Models = []string{model}
		}
		current = t.applyLocked(auth.ID, obs)
		if current.ModelHeaderObservedAt == nil {
			current.ModelHeaderObservedAt = make(map[string]time.Time)
		}
		current.ModelHeaderObservedAt[model] = state.Quota.ObservedAt
	}
}

// ApplyObservation merges a usage-endpoint (or other) observation for authID.
func (t *ResetAwareTracker) ApplyObservation(authID string, obs LimitObservation) {
	if t == nil || strings.TrimSpace(authID) == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	current := t.applyLocked(authID, obs)
	if obs.Source == "usage" {
		if obs.ObservedAt.After(current.UsageObservedAt) {
			current.UsageObservedAt = obs.ObservedAt
		}
		current.LastRefreshError = ""
	}
}

func (t *ResetAwareTracker) applyLocked(authID string, obs LimitObservation) *AccountLimits {
	current := t.accounts[authID]
	if current == nil {
		current = &AccountLimits{Provider: obs.Provider}
		t.accounts[authID] = current
	}
	if obs.Provider != "" {
		current.Provider = obs.Provider
	}
	if !obs.ObservedAt.Before(current.ObservedAt) {
		if resetAt, detected := detectWeeklyReset(current.Weekly, obs.Weekly, obs.ObservedAt); detected {
			current.LastResetAt = resetAt
		}
		if obs.FiveHour.Known {
			current.FiveHour = obs.FiveHour
		}
		if obs.Weekly.Known {
			current.Weekly = obs.Weekly
		}
		if obs.FiveHour.Known || obs.Weekly.Known {
			current.ObservedAt = obs.ObservedAt
			current.Source = obs.Source
		}
	}
	current.Buckets = mergeBuckets(current.Buckets, obs.Buckets)
	t.dirty = true
	return current
}

// detectWeeklyReset reports a reset when the previous window's reset time passed before
// the new observation, or when utilization dropped sharply while the previous window was
// still running (an early reset such as a reset credit).
func detectWeeklyReset(previous, next LimitWindow, at time.Time) (time.Time, bool) {
	if !previous.Known || !next.Known {
		return time.Time{}, false
	}
	if !previous.ResetAt.IsZero() && !previous.ResetAt.After(at) {
		return previous.ResetAt, true
	}
	if next.UsedPercent+resetDropPoints <= previous.UsedPercent {
		return at, true
	}
	return time.Time{}, false
}

func mergeBuckets(current, incoming []LimitBucket) []LimitBucket {
	if len(incoming) == 0 {
		return current
	}
	byKey := make(map[string]LimitBucket, len(current)+len(incoming))
	order := make([]string, 0, len(current)+len(incoming))
	for _, bucket := range current {
		key := strings.ToLower(bucket.Name)
		if _, seen := byKey[key]; !seen {
			order = append(order, key)
		}
		byKey[key] = bucket
	}
	for _, bucket := range incoming {
		key := strings.ToLower(bucket.Name)
		existing, seen := byKey[key]
		if !seen {
			order = append(order, key)
			byKey[key] = bucket
			continue
		}
		merged := existing
		if !bucket.ObservedAt.Before(existing.ObservedAt) {
			merged.Window = bucket.Window
			merged.ObservedAt = bucket.ObservedAt
			merged.Routing = bucket.Routing
			if bucket.Match != "" {
				merged.Match = bucket.Match
			}
		}
		merged.Models = unionModels(existing.Models, bucket.Models)
		byKey[key] = merged
	}
	out := make([]LimitBucket, 0, len(order))
	for _, key := range order {
		out = append(out, byKey[key])
	}
	return out
}

func unionModels(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, model := range append(append([]string(nil), a...), b...) {
		key := canonicalModelKey(model)
		if _, ok := seen[key]; ok || key == "" {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, model)
	}
	return out
}

// Get returns a copy of the cached limits for authID.
func (t *ResetAwareTracker) Get(authID string) (AccountLimits, bool) {
	if t == nil {
		return AccountLimits{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	current, ok := t.accounts[authID]
	if !ok || current == nil {
		return AccountLimits{}, false
	}
	return current.clone(), true
}

// DueForRefresh reports whether authID should be refreshed from its usage endpoint.
// Codex headers carry every window, so recent header data counts as fresh. Claude headers
// lack model-specific buckets, so only the usage endpoint keeps a Claude account fresh.
func (t *ResetAwareTracker) DueForRefresh(authID, provider string, now time.Time, interval time.Duration) bool {
	if t == nil || interval <= 0 {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	current := t.accounts[authID]
	if current == nil {
		return true
	}
	if !current.NextRefreshAt.IsZero() && now.Before(current.NextRefreshAt) {
		return false
	}
	last := current.UsageObservedAt
	if strings.EqualFold(provider, "codex") && current.ObservedAt.After(last) {
		last = current.ObservedAt
	}
	return last.IsZero() || now.Sub(last) >= interval
}

// ScheduleRefresh records the earliest time authID may be refreshed again.
func (t *ResetAwareTracker) ScheduleRefresh(authID, provider string, next time.Time) {
	if t == nil || strings.TrimSpace(authID) == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	current := t.accounts[authID]
	if current == nil {
		current = &AccountLimits{Provider: provider}
		t.accounts[authID] = current
	}
	current.NextRefreshAt = next
	t.dirty = true
}

// RecordRefreshError stores a short, token-free description of a failed usage refresh.
func (t *ResetAwareTracker) RecordRefreshError(authID, provider, message string) {
	if t == nil || strings.TrimSpace(authID) == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	current := t.accounts[authID]
	if current == nil {
		current = &AccountLimits{Provider: provider}
		t.accounts[authID] = current
	}
	current.LastRefreshError = message
	t.dirty = true
}

// Prune drops cached data for credentials that no longer exist.
func (t *ResetAwareTracker) Prune(keep map[string]struct{}) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for id := range t.accounts {
		if _, ok := keep[id]; !ok {
			delete(t.accounts, id)
			t.dirty = true
		}
	}
}

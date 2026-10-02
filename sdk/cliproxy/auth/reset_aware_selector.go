package auth

import (
	"context"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// CandidateFilter is an optional interface for a session affinity fallback selector. When
// the fallback implements it, SessionAffinitySelector narrows the candidates before reusing
// a bound credential, so a session keeps its credential only while the filter allows it.
// An empty result leaves the candidates unchanged.
type CandidateFilter interface {
	FilterCandidates(ctx context.Context, provider, model string, auths []*Auth) []*Auth
}

// ResetAwareOptions holds the reset-aware eligibility thresholds, in percent.
type ResetAwareOptions struct {
	FiveHourThreshold float64
	WeeklyThreshold   float64
}

// DefaultResetAwareOptions returns the default thresholds.
func DefaultResetAwareOptions() ResetAwareOptions {
	return ResetAwareOptions{FiveHourThreshold: ResetAwareDefaultThreshold, WeeklyThreshold: ResetAwareDefaultThreshold}
}

func (o ResetAwareOptions) normalized() ResetAwareOptions {
	if o.FiveHourThreshold <= 0 || o.FiveHourThreshold > 100 {
		o.FiveHourThreshold = ResetAwareDefaultThreshold
	}
	if o.WeeklyThreshold <= 0 || o.WeeklyThreshold > 100 {
		o.WeeklyThreshold = ResetAwareDefaultThreshold
	}
	return o
}

// ResetAwareSelector drains the credential whose weekly window resets soonest, so quota
// that would expire unused at the reset is spent first. A credential is eligible while its
// five-hour window, its weekly window, and the requested model's weekly bucket are below
// the thresholds. Eligible credentials are ordered by soonest weekly reset, then by most
// weekly headroom, then round-robin; credentials without limit data come last. When no
// credential is eligible, all candidates are ordered the same way and upstream cooldown
// and retry handle any limit errors.
type ResetAwareSelector struct {
	tracker    *ResetAwareTracker
	opts       ResetAwareOptions
	now        func() time.Time
	mu         sync.Mutex
	lastPicked map[string]string
}

// NewResetAwareSelector creates a reset-aware selector backed by tracker.
func NewResetAwareSelector(tracker *ResetAwareTracker, opts ResetAwareOptions) *ResetAwareSelector {
	if tracker == nil {
		tracker = NewResetAwareTracker("")
	}
	return &ResetAwareSelector{tracker: tracker, opts: opts.normalized(), now: time.Now, lastPicked: make(map[string]string)}
}

// Tracker returns the limit cache behind the selector.
func (s *ResetAwareSelector) Tracker() *ResetAwareTracker {
	if s == nil {
		return nil
	}
	return s.tracker
}

// Options returns the normalized thresholds.
func (s *ResetAwareSelector) Options() ResetAwareOptions {
	if s == nil {
		return DefaultResetAwareOptions()
	}
	return s.opts
}

// ResetAwareSelectorOf returns the reset-aware selector behind selector, looking through
// session affinity.
func ResetAwareSelectorOf(selector Selector) (*ResetAwareSelector, bool) {
	switch typed := selector.(type) {
	case *ResetAwareSelector:
		return typed, typed != nil
	case *SessionAffinitySelector:
		if typed == nil {
			return nil, false
		}
		resetAware, ok := typed.fallback.(*ResetAwareSelector)
		return resetAware, ok && resetAware != nil
	default:
		return nil, false
	}
}

func (s *ResetAwareSelector) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

type resetAwareCandidate struct {
	auth      *Auth
	hasData   bool
	known     bool
	eligible  bool
	reasons   []string
	resetAt   time.Time
	remaining float64
	fiveHour  LimitWindow
	weekly    LimitWindow
}

func evaluateResetAware(auth *Auth, limits AccountLimits, ok bool, model string, now time.Time, opts ResetAwareOptions) resetAwareCandidate {
	candidate := resetAwareCandidate{auth: auth, eligible: true, hasData: ok}
	if !ok {
		return candidate
	}
	fixed := providerUsesFixedTimer(limits.Provider)
	candidate.fiveHour = limits.FiveHour.effectiveAt(now, fixed)
	candidate.weekly = limits.Weekly.effectiveAt(now, fixed)
	if candidate.fiveHour.Known && candidate.fiveHour.UsedPercent >= opts.FiveHourThreshold {
		candidate.eligible = false
		candidate.reasons = append(candidate.reasons, "five_hour")
	}
	if candidate.weekly.Known && candidate.weekly.UsedPercent >= opts.WeeklyThreshold {
		candidate.eligible = false
		candidate.reasons = append(candidate.reasons, "weekly")
	}
	applicable := candidate.weekly
	usingBucket := false
	for _, bucket := range limits.Buckets {
		if !bucket.Routing || !bucket.appliesTo(model) {
			continue
		}
		window := bucket.Window.effectiveAt(now, fixed)
		if !window.Known {
			continue
		}
		if window.UsedPercent >= opts.WeeklyThreshold {
			candidate.eligible = false
			candidate.reasons = append(candidate.reasons, "bucket:"+bucket.Name)
		}
		if !usingBucket {
			applicable = window
			usingBucket = true
		}
	}
	if applicable.Known && !applicable.ResetAt.IsZero() {
		candidate.known = true
		candidate.resetAt = applicable.ResetAt
		candidate.remaining = 100 - applicable.UsedPercent
	}
	return candidate
}

// compareResetAware orders known data first, then soonest reset (to the minute), then most
// headroom. It returns 0 for candidates that only differ by identity.
func compareResetAware(a, b resetAwareCandidate) int {
	if a.known != b.known {
		if a.known {
			return -1
		}
		return 1
	}
	if a.known {
		resetA, resetB := a.resetAt.Truncate(time.Minute), b.resetAt.Truncate(time.Minute)
		if !resetA.Equal(resetB) {
			if resetA.Before(resetB) {
				return -1
			}
			return 1
		}
		if math.Abs(a.remaining-b.remaining) >= 0.5 {
			if a.remaining > b.remaining {
				return -1
			}
			return 1
		}
	}
	return 0
}

func sortResetAware(candidates []resetAwareCandidate) {
	sort.SliceStable(candidates, func(i, j int) bool {
		if order := compareResetAware(candidates[i], candidates[j]); order != 0 {
			return order < 0
		}
		return candidates[i].auth.ID < candidates[j].auth.ID
	})
}

func (s *ResetAwareSelector) evaluate(auths []*Auth, model string, now time.Time) []resetAwareCandidate {
	candidates := make([]resetAwareCandidate, 0, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		s.tracker.ObserveAuth(auth)
		limits, ok := s.tracker.Get(auth.ID)
		candidates = append(candidates, evaluateResetAware(auth, limits, ok, model, now, s.opts))
	}
	return candidates
}

// Pick implements Selector.
func (s *ResetAwareSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := s.clock()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	candidates := s.evaluate(available, model, now)
	pool := make([]resetAwareCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.eligible {
			pool = append(pool, candidate)
		}
	}
	allLimited := len(pool) == 0
	if allLimited {
		pool = candidates
	}
	sortResetAware(pool)
	picked := s.pickLeadingGroup(provider, model, pool)
	selectorLogEntry(ctx).Debugf("reset-aware: picked | auth=%s provider=%s model=%s known=%t all_limited=%t", picked.ID, provider, model, pool[0].known, allLimited)
	return picked, nil
}

// pickLeadingGroup rotates among the leading candidates that tie on every ranking key.
func (s *ResetAwareSelector) pickLeadingGroup(provider, model string, pool []resetAwareCandidate) *Auth {
	group := 1
	for group < len(pool) && compareResetAware(pool[0], pool[group]) == 0 {
		group++
	}
	key := provider + ":" + canonicalModelKey(model)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastPicked == nil || (len(s.lastPicked) >= 4096 && s.lastPicked[key] == "") {
		s.lastPicked = make(map[string]string)
	}
	index := 0
	if last := s.lastPicked[key]; last != "" && group > 1 {
		for i := 0; i < group; i++ {
			if pool[i].auth.ID > last {
				index = i
				break
			}
		}
	}
	picked := pool[index].auth
	s.lastPicked[key] = picked.ID
	return picked
}

// FilterCandidates implements CandidateFilter. It keeps available credentials that are
// below every threshold. When none qualify, it returns auths unchanged so session affinity
// behaves exactly as upstream does.
func (s *ResetAwareSelector) FilterCandidates(ctx context.Context, provider, model string, auths []*Auth) []*Auth {
	if s == nil || len(auths) == 0 {
		return auths
	}
	now := s.clock()
	available, err := getSelectorAvailableAuthsAcrossPriorities(ctx, auths, provider, model, now)
	if err != nil || len(available) == 0 {
		return auths
	}
	eligible := make([]*Auth, 0, len(available))
	for _, candidate := range s.evaluate(available, model, now) {
		if candidate.eligible {
			eligible = append(eligible, candidate.auth)
		}
	}
	if len(eligible) == 0 {
		return auths
	}
	return eligible
}

// ResetAwareWindowReport describes one limit window for the management API.
type ResetAwareWindowReport struct {
	UsedPercent    *float64   `json:"used_percent"`
	ResetsAt       *time.Time `json:"resets_at"`
	WindowSeconds  int64      `json:"window_seconds,omitempty"`
	Estimated      bool       `json:"estimated,omitempty"`
	AffectsRouting bool       `json:"affects_routing"`
}

// ResetAwareBucketReport describes an extra window such as a model-specific weekly limit.
type ResetAwareBucketReport struct {
	Name       string     `json:"name"`
	AppliesTo  string     `json:"applies_to,omitempty"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
	ResetAwareWindowReport
}

// ResetAwareAccountReport is one credential in the limits report.
type ResetAwareAccountReport struct {
	AuthIndex              string                   `json:"auth_index"`
	Provider               string                   `json:"provider"`
	Label                  string                   `json:"label"`
	Status                 string                   `json:"status"`
	Rank                   int                      `json:"rank"`
	RankOf                 int                      `json:"rank_of"`
	Eligible               bool                     `json:"eligible"`
	IneligibleReasons      []string                 `json:"ineligible_reasons,omitempty"`
	HasData                bool                     `json:"has_data"`
	Source                 string                   `json:"source,omitempty"`
	ObservedAt             *time.Time               `json:"observed_at,omitempty"`
	UsageObservedAt        *time.Time               `json:"usage_observed_at,omitempty"`
	FiveHour               ResetAwareWindowReport   `json:"five_hour"`
	Weekly                 ResetAwareWindowReport   `json:"weekly"`
	Buckets                []ResetAwareBucketReport `json:"buckets"`
	ProjectedUnusedPercent *float64                 `json:"projected_unused_percent,omitempty"`
	LastResetDetectedAt    *time.Time               `json:"last_reset_detected_at,omitempty"`
	LastRefreshError       string                   `json:"last_refresh_error,omitempty"`
}

// ResetAwareLimitsReport is the payload of GET /v8/management/routing/limits.
type ResetAwareLimitsReport struct {
	Enabled                bool                      `json:"enabled"`
	Strategy               string                    `json:"strategy"`
	GeneratedAt            time.Time                 `json:"generated_at"`
	FiveHourThreshold      float64                   `json:"five_hour_threshold"`
	WeeklyThreshold        float64                   `json:"weekly_threshold"`
	RefreshIntervalSeconds int64                     `json:"refresh_interval_seconds"`
	Accounts               []ResetAwareAccountReport `json:"accounts"`
}

// BuildResetAwareLimitsReport ranks auths per provider the way a model-agnostic request
// would be routed and describes every limit window. With a nil tracker it reads only the
// header snapshots currently held on the auths.
func BuildResetAwareLimitsReport(auths []*Auth, tracker *ResetAwareTracker, opts ResetAwareOptions, now time.Time) ResetAwareLimitsReport {
	opts = opts.normalized()
	if tracker == nil {
		tracker = NewResetAwareTracker("")
	}
	report := ResetAwareLimitsReport{GeneratedAt: now, FiveHourThreshold: opts.FiveHourThreshold, WeeklyThreshold: opts.WeeklyThreshold, Accounts: []ResetAwareAccountReport{}}
	type entry struct {
		candidate resetAwareCandidate
		limits    AccountLimits
		status    string
	}
	byProvider := make(map[string][]entry)
	for _, auth := range auths {
		if auth == nil || !ResetAwareProviderSupported(auth.Provider) {
			continue
		}
		tracker.ObserveAuth(auth)
		limits, ok := tracker.Get(auth.ID)
		status := "active"
		if blocked, reason, _ := isAuthBlockedForModel(auth, "", now); blocked {
			status = "unavailable"
			switch reason {
			case blockReasonCooldown:
				status = "cooldown"
			case blockReasonDisabled:
				status = "disabled"
			}
		}
		provider := strings.ToLower(auth.Provider)
		byProvider[provider] = append(byProvider[provider], entry{candidate: evaluateResetAware(auth, limits, ok, "", now, opts), limits: limits, status: status})
	}
	providers := make([]string, 0, len(byProvider))
	for provider := range byProvider {
		providers = append(providers, provider)
	}
	sort.Strings(providers)
	for _, provider := range providers {
		entries := byProvider[provider]
		tier := func(e entry) int {
			switch {
			case e.status == "active" && e.candidate.eligible:
				return 0
			case e.status == "active":
				return 1
			default:
				return 2
			}
		}
		sort.SliceStable(entries, func(i, j int) bool {
			if ti, tj := tier(entries[i]), tier(entries[j]); ti != tj {
				return ti < tj
			}
			if order := compareResetAware(entries[i].candidate, entries[j].candidate); order != 0 {
				return order < 0
			}
			return entries[i].candidate.auth.ID < entries[j].candidate.auth.ID
		})
		for i, e := range entries {
			report.Accounts = append(report.Accounts, accountReport(e.candidate, e.limits, e.status, i+1, len(entries), now))
		}
	}
	return report
}

func accountReport(candidate resetAwareCandidate, limits AccountLimits, status string, rank, rankOf int, now time.Time) ResetAwareAccountReport {
	auth := candidate.auth
	out := ResetAwareAccountReport{
		AuthIndex:         auth.EnsureIndex(),
		Provider:          strings.ToLower(auth.Provider),
		Label:             maskedAuthLabel(auth),
		Status:            status,
		Rank:              rank,
		RankOf:            rankOf,
		Eligible:          candidate.eligible,
		IneligibleReasons: candidate.reasons,
		HasData:           candidate.hasData,
		Buckets:           []ResetAwareBucketReport{},
	}
	if !candidate.hasData {
		return out
	}
	out.Source = limits.Source
	out.ObservedAt = timePtr(limits.ObservedAt)
	out.UsageObservedAt = timePtr(limits.UsageObservedAt)
	out.LastResetDetectedAt = timePtr(limits.LastResetAt)
	out.LastRefreshError = limits.LastRefreshError
	out.FiveHour = windowReport(candidate.fiveHour, true)
	out.Weekly = windowReport(candidate.weekly, true)
	fixed := providerUsesFixedTimer(limits.Provider)
	for _, bucket := range limits.Buckets {
		routing := bucket.Routing && (len(bucket.Models) > 0 || bucket.Match != "")
		bucketReport := ResetAwareBucketReport{
			Name:                   bucket.Name,
			ObservedAt:             timePtr(bucket.ObservedAt),
			ResetAwareWindowReport: windowReport(bucket.Window.effectiveAt(now, fixed), routing),
		}
		switch {
		case len(bucket.Models) > 0:
			bucketReport.AppliesTo = strings.Join(bucket.Models, ", ")
		case bucket.Match != "":
			bucketReport.AppliesTo = "models containing \"" + bucket.Match + "\""
		}
		out.Buckets = append(out.Buckets, bucketReport)
	}
	out.ProjectedUnusedPercent = projectedUnused(candidate.weekly, now)
	return out
}

func windowReport(window LimitWindow, affectsRouting bool) ResetAwareWindowReport {
	if !window.Known {
		return ResetAwareWindowReport{AffectsRouting: affectsRouting}
	}
	used := window.UsedPercent
	return ResetAwareWindowReport{
		UsedPercent:    &used,
		ResetsAt:       timePtr(window.ResetAt),
		WindowSeconds:  window.WindowSeconds,
		Estimated:      window.Estimated,
		AffectsRouting: affectsRouting,
	}
}

// projectedUnused extrapolates the current weekly burn rate to the reset time and returns
// the share of the window that would be left unused. It needs at least an hour of elapsed
// window to avoid wild early projections.
func projectedUnused(weekly LimitWindow, now time.Time) *float64 {
	if !weekly.Known || weekly.Estimated || weekly.ResetAt.IsZero() || !weekly.ResetAt.After(now) || weekly.WindowSeconds <= 0 {
		return nil
	}
	remaining := weekly.ResetAt.Sub(now)
	elapsed := time.Duration(weekly.WindowSeconds)*time.Second - remaining
	if elapsed < time.Hour {
		return nil
	}
	rate := weekly.UsedPercent / elapsed.Hours()
	unused := math.Max(0, 100-(weekly.UsedPercent+rate*remaining.Hours()))
	unused = math.Round(unused*10) / 10
	return &unused
}

func timePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}

func maskedAuthLabel(auth *Auth) string {
	candidates := []string{}
	if auth.Metadata != nil {
		if email, ok := auth.Metadata["email"].(string); ok {
			candidates = append(candidates, email)
		}
	}
	if auth.Attributes != nil {
		candidates = append(candidates, auth.Attributes["email"])
	}
	candidates = append(candidates, auth.Label)
	for _, value := range candidates {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.Contains(value, "@") {
			return MaskEmail(value)
		}
		return maskToken(value)
	}
	return "account " + auth.EnsureIndex()
}

// MaskEmail hides most of an address but keeps both ends of the local part, so accounts
// that share a prefix stay distinguishable: "someone@example.test" -> "som•••ne@ex•••.test".
func MaskEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at <= 0 {
		return maskToken(email)
	}
	local, domain := email[:at], email[at+1:]
	tld := ""
	if dot := strings.LastIndex(domain, "."); dot > 0 {
		tld = domain[dot:]
		domain = domain[:dot]
	}
	return maskLocalPart(local) + "@" + maskToken(domain) + tld
}

func maskLocalPart(local string) string {
	runes := []rune(local)
	switch {
	case len(runes) <= 3:
		return maskToken(local)
	case len(runes) <= 6:
		return string(runes[:2]) + "•••" + string(runes[len(runes)-1:])
	default:
		return string(runes[:3]) + "•••" + string(runes[len(runes)-2:])
	}
}

func maskToken(value string) string {
	runes := []rune(value)
	keep := 2
	if len(runes) <= 3 {
		keep = 1
	}
	if len(runes) <= keep {
		return string(runes) + "•••"
	}
	return string(runes[:keep]) + "•••"
}

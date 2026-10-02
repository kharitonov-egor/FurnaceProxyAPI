package auth

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// ResetAwareDefaultThreshold is the default utilization percent at which an account
	// stops receiving new work under the reset-aware strategy.
	ResetAwareDefaultThreshold = 98.0

	fiveHourWindowSeconds = int64(5 * 60 * 60)
	weeklyWindowSeconds   = int64(7 * 24 * 60 * 60)

	// A weekly utilization drop of at least this many percentage points before the
	// known reset time is treated as an early reset (for example a reset credit).
	resetDropPoints = 5.0
)

// LimitWindow is one provider usage window: how much of it is used and when it resets.
type LimitWindow struct {
	Known         bool      `json:"known"`
	UsedPercent   float64   `json:"used_percent"`
	ResetAt       time.Time `json:"resets_at,omitempty"`
	WindowSeconds int64     `json:"window_seconds,omitempty"`
	// Estimated reports that the original window already reset and ResetAt is projected.
	Estimated bool `json:"estimated,omitempty"`
}

// LimitBucket is an extra window reported next to the account-wide ones, such as a
// model-specific weekly limit.
type LimitBucket struct {
	Name string `json:"name"`
	// Match is a lowercase token; the bucket applies to models whose ID contains it.
	Match string `json:"match,omitempty"`
	// Models lists exact model IDs the bucket was observed on.
	Models []string `json:"models,omitempty"`
	// Routing reports whether the bucket can affect credential selection.
	Routing    bool        `json:"routing"`
	Window     LimitWindow `json:"window"`
	ObservedAt time.Time   `json:"observed_at"`
}

// LimitObservation is one parsed snapshot from response headers or a usage endpoint.
type LimitObservation struct {
	Provider   string
	Source     string
	ObservedAt time.Time
	FiveHour   LimitWindow
	Weekly     LimitWindow
	Buckets    []LimitBucket
}

func (w LimitWindow) window() time.Duration {
	if w.WindowSeconds > 0 {
		return time.Duration(w.WindowSeconds) * time.Second
	}
	return 0
}

// effectiveAt returns the window as it stands at now. A window whose reset time has
// passed is treated as freshly reset: Claude keeps a fixed weekly timer, so the next reset
// is the old one plus whole periods; Codex starts a new window on first use, so the next
// reset is projected one full window from now.
func (w LimitWindow) effectiveAt(now time.Time, fixedTimer bool) LimitWindow {
	if !w.Known || w.ResetAt.IsZero() || w.ResetAt.After(now) {
		return w
	}
	period := w.window()
	if period <= 0 {
		period = time.Duration(weeklyWindowSeconds) * time.Second
	}
	out := w
	out.UsedPercent = 0
	out.Estimated = true
	if fixedTimer {
		elapsed := now.Sub(w.ResetAt)
		periods := int64(elapsed/period) + 1
		out.ResetAt = w.ResetAt.Add(time.Duration(periods) * period)
	} else {
		out.ResetAt = now.Add(period)
	}
	return out
}

func (b LimitBucket) appliesTo(model string) bool {
	model = strings.TrimSpace(model)
	if model == "" {
		return false
	}
	key := canonicalModelKey(model)
	for _, observed := range b.Models {
		if canonicalModelKey(observed) == key {
			return true
		}
	}
	match := strings.ToLower(strings.TrimSpace(b.Match))
	return match != "" && strings.Contains(strings.ToLower(model), match)
}

func providerUsesFixedTimer(provider string) bool {
	return strings.EqualFold(strings.TrimSpace(provider), "claude")
}

// ResetAwareProviderSupported reports whether the reset-aware strategy understands the
// provider's limit data. Other providers are still routed, with no limit data.
func ResetAwareProviderSupported(provider string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex", "claude":
		return true
	default:
		return false
	}
}

func lowerSignals(signals map[string]string) map[string]string {
	out := make(map[string]string, len(signals))
	for key, value := range signals {
		out[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return out
}

func parseNumber(value string) (float64, bool) {
	value = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), "%"))
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return 0, false
	}
	return parsed, true
}

func parseEpochSeconds(value string) (time.Time, bool) {
	seconds, ok := parseNumber(value)
	if !ok || seconds <= 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(seconds), 0), true
}

func clampPercent(value float64) float64 {
	return math.Max(0, math.Min(100, value))
}

// ParseCodexHeaderSignals reads the x-codex-* quota headers upstream captures per response.
// Primary and secondary windows are classified by their window length, so a weekly primary
// window is handled too.
func ParseCodexHeaderSignals(signals map[string]string, observedAt time.Time) (LimitObservation, bool) {
	lower := lowerSignals(signals)
	obs := LimitObservation{Provider: "codex", Source: "headers", ObservedAt: observedAt}
	found := false
	for _, slot := range []string{"primary", "secondary"} {
		window, ok := codexHeaderWindow(lower, "x-codex-"+slot, observedAt)
		if !ok {
			continue
		}
		found = true
		assignCodexWindow(&obs, window, slot)
	}
	obs.Buckets = codexHeaderBuckets(lower, observedAt)
	return obs, found || len(obs.Buckets) > 0
}

func assignCodexWindow(obs *LimitObservation, window LimitWindow, slot string) {
	switch {
	case window.WindowSeconds >= weeklyWindowSeconds:
		obs.Weekly = window
	case window.WindowSeconds > 0:
		obs.FiveHour = window
	case slot == "secondary":
		window.WindowSeconds = weeklyWindowSeconds
		obs.Weekly = window
	default:
		window.WindowSeconds = fiveHourWindowSeconds
		obs.FiveHour = window
	}
}

func codexHeaderWindow(lower map[string]string, prefix string, observedAt time.Time) (LimitWindow, bool) {
	used, ok := parseNumber(lower[prefix+"-used-percent"])
	if !ok {
		return LimitWindow{}, false
	}
	window := LimitWindow{Known: true, UsedPercent: clampPercent(used)}
	if minutes, okMinutes := parseNumber(lower[prefix+"-window-minutes"]); okMinutes && minutes > 0 {
		window.WindowSeconds = int64(minutes * 60)
	}
	if resetAt, okReset := parseEpochSeconds(lower[prefix+"-reset-at"]); okReset {
		window.ResetAt = resetAt
	} else if after, okAfter := parseNumber(lower[prefix+"-reset-after-seconds"]); okAfter && after >= 0 && !observedAt.IsZero() {
		window.ResetAt = observedAt.Add(time.Duration(after) * time.Second)
	}
	return window, true
}

var codexBucketUsedHeader = regexp.MustCompile(`^x-codex-(.+)-(primary|secondary)-used-percent$`)

// codexHeaderBuckets reads additional limits, which Codex namespaces as
// x-codex-additional-<limit>-<slot>-* on the websocket path and x-codex-<short>-<slot>-*
// on the HTTP path. Only the weekly-or-longest window of each limit is kept.
func codexHeaderBuckets(lower map[string]string, observedAt time.Time) []LimitBucket {
	byName := make(map[string]LimitBucket)
	for key := range lower {
		match := codexBucketUsedHeader.FindStringSubmatch(key)
		if match == nil {
			continue
		}
		namespace := match[1]
		if namespace == "primary" || namespace == "secondary" {
			continue
		}
		window, ok := codexHeaderWindow(lower, "x-codex-"+namespace+"-"+match[2], observedAt)
		if !ok {
			continue
		}
		name := strings.TrimPrefix(namespace, "additional-")
		if label := lower["x-codex-"+namespace+"-limit-name"]; label != "" {
			name = label
		}
		routing := !strings.HasPrefix(namespace, "code-review")
		existing, seen := byName[namespace]
		if seen && existing.Window.WindowSeconds >= window.WindowSeconds {
			continue
		}
		byName[namespace] = LimitBucket{Name: name, Routing: routing, Window: window, ObservedAt: observedAt}
	}
	return sortedBuckets(byName)
}

func sortedBuckets(byKey map[string]LimitBucket) []LimitBucket {
	if len(byKey) == 0 {
		return nil
	}
	out := make([]LimitBucket, 0, len(byKey))
	for _, bucket := range byKey {
		out = append(out, bucket)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ParseClaudeHeaderSignals reads anthropic-ratelimit-unified-* headers. Utilization is a
// 0-1 fraction there; reset values are Unix seconds.
func ParseClaudeHeaderSignals(signals map[string]string, observedAt time.Time) (LimitObservation, bool) {
	lower := lowerSignals(signals)
	obs := LimitObservation{Provider: "claude", Source: "headers", ObservedAt: observedAt}
	found := false
	if window, ok := claudeHeaderWindow(lower, "5h", fiveHourWindowSeconds); ok {
		obs.FiveHour = window
		found = true
	}
	if window, ok := claudeHeaderWindow(lower, "7d", weeklyWindowSeconds); ok {
		obs.Weekly = window
		found = true
	}
	if window, ok := claudeHeaderWindow(lower, "7d_oi", weeklyWindowSeconds); ok {
		obs.Buckets = append(obs.Buckets, LimitBucket{Name: "Weekly (overage included)", Window: window, ObservedAt: observedAt})
	}
	return obs, found || len(obs.Buckets) > 0
}

func claudeHeaderWindow(lower map[string]string, claim string, windowSeconds int64) (LimitWindow, bool) {
	prefix := "anthropic-ratelimit-unified-" + claim
	utilization, ok := parseNumber(lower[prefix+"-utilization"])
	if !ok {
		return LimitWindow{}, false
	}
	window := LimitWindow{Known: true, UsedPercent: clampPercent(fractionToPercent(utilization)), WindowSeconds: windowSeconds}
	if resetAt, okReset := parseEpochSeconds(lower[prefix+"-reset"]); okReset {
		window.ResetAt = resetAt
	}
	return window, true
}

// fractionToPercent converts a 0-1 utilization fraction. Values above 1.5 are assumed to
// be percentages already, so a future format change cannot inflate them a hundredfold.
func fractionToPercent(value float64) float64 {
	if value > 1.5 {
		return value
	}
	return value * 100
}

type codexUsageWindowJSON struct {
	UsedPercent        *float64 `json:"used_percent"`
	LimitWindowSeconds int64    `json:"limit_window_seconds"`
	ResetAfterSeconds  *float64 `json:"reset_after_seconds"`
	ResetAt            *float64 `json:"reset_at"`
}

type codexRateLimitJSON struct {
	PrimaryWindow   *codexUsageWindowJSON `json:"primary_window"`
	SecondaryWindow *codexUsageWindowJSON `json:"secondary_window"`
}

type codexAdditionalLimitJSON struct {
	LimitName      string              `json:"limit_name"`
	MeteredFeature string              `json:"metered_feature"`
	RateLimit      *codexRateLimitJSON `json:"rate_limit"`
}

type codexUsageJSON struct {
	RateLimit            *codexRateLimitJSON `json:"rate_limit"`
	CodeReviewRateLimit  *codexRateLimitJSON `json:"code_review_rate_limit"`
	AdditionalRateLimits json.RawMessage     `json:"additional_rate_limits"`
}

// ParseCodexUsage reads the body of chatgpt.com/backend-api/wham/usage, the endpoint the
// Codex CLI uses for /status.
func ParseCodexUsage(body []byte, observedAt time.Time) (LimitObservation, error) {
	var payload codexUsageJSON
	if err := json.Unmarshal(body, &payload); err != nil {
		return LimitObservation{}, fmt.Errorf("decode codex usage: %w", err)
	}
	obs := LimitObservation{Provider: "codex", Source: "usage", ObservedAt: observedAt}
	if payload.RateLimit == nil {
		return obs, fmt.Errorf("codex usage has no rate_limit")
	}
	for slot, raw := range map[string]*codexUsageWindowJSON{"primary": payload.RateLimit.PrimaryWindow, "secondary": payload.RateLimit.SecondaryWindow} {
		if window, ok := codexUsageWindow(raw, observedAt); ok {
			assignCodexWindow(&obs, window, slot)
		}
	}
	byName := make(map[string]LimitBucket)
	if review := codexLongestWindow(payload.CodeReviewRateLimit, observedAt); review.Known {
		byName["code-review"] = LimitBucket{Name: "Code review", Window: review, ObservedAt: observedAt}
	}
	for _, extra := range decodeCodexAdditionalLimits(payload.AdditionalRateLimits) {
		window := codexLongestWindow(extra.RateLimit, observedAt)
		if !window.Known {
			continue
		}
		name := strings.TrimSpace(extra.LimitName)
		if name == "" {
			name = strings.TrimSpace(extra.MeteredFeature)
		}
		if name == "" {
			continue
		}
		byName["additional:"+name] = LimitBucket{
			Name:       name,
			Match:      strings.ToLower(strings.TrimSpace(extra.MeteredFeature)),
			Routing:    true,
			Window:     window,
			ObservedAt: observedAt,
		}
	}
	obs.Buckets = sortedBuckets(byName)
	return obs, nil
}

// decodeCodexAdditionalLimits accepts both a list and a map keyed by limit name.
func decodeCodexAdditionalLimits(raw json.RawMessage) []codexAdditionalLimitJSON {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var list []codexAdditionalLimitJSON
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var byName map[string]codexAdditionalLimitJSON
	if err := json.Unmarshal(raw, &byName); err != nil {
		return nil
	}
	out := make([]codexAdditionalLimitJSON, 0, len(byName))
	for name, entry := range byName {
		if entry.LimitName == "" {
			entry.LimitName = name
		}
		out = append(out, entry)
	}
	return out
}

func codexLongestWindow(rateLimit *codexRateLimitJSON, observedAt time.Time) LimitWindow {
	if rateLimit == nil {
		return LimitWindow{}
	}
	best := LimitWindow{}
	for _, raw := range []*codexUsageWindowJSON{rateLimit.PrimaryWindow, rateLimit.SecondaryWindow} {
		window, ok := codexUsageWindow(raw, observedAt)
		if ok && (!best.Known || window.WindowSeconds > best.WindowSeconds) {
			best = window
		}
	}
	return best
}

func codexUsageWindow(raw *codexUsageWindowJSON, observedAt time.Time) (LimitWindow, bool) {
	if raw == nil || raw.UsedPercent == nil {
		return LimitWindow{}, false
	}
	window := LimitWindow{Known: true, UsedPercent: clampPercent(*raw.UsedPercent), WindowSeconds: raw.LimitWindowSeconds}
	if raw.ResetAt != nil && *raw.ResetAt > 0 {
		window.ResetAt = time.Unix(int64(*raw.ResetAt), 0)
	} else if raw.ResetAfterSeconds != nil && !observedAt.IsZero() {
		window.ResetAt = observedAt.Add(time.Duration(*raw.ResetAfterSeconds) * time.Second)
	}
	return window, true
}

type claudeUsageWindowJSON struct {
	Utilization *float64 `json:"utilization"`
	ResetsAt    *string  `json:"resets_at"`
}

type claudeUsageLimitJSON struct {
	Kind     string   `json:"kind"`
	Group    string   `json:"group"`
	Percent  *float64 `json:"percent"`
	ResetsAt *string  `json:"resets_at"`
	Scope    *struct {
		Model *struct {
			DisplayName string `json:"display_name"`
		} `json:"model"`
		Surface *struct {
			DisplayName string `json:"display_name"`
		} `json:"surface"`
	} `json:"scope"`
}

type claudeUsageJSON struct {
	FiveHour                *claudeUsageWindowJSON `json:"five_hour"`
	SevenDay                *claudeUsageWindowJSON `json:"seven_day"`
	SevenDayOpus            *claudeUsageWindowJSON `json:"seven_day_opus"`
	SevenDaySonnet          *claudeUsageWindowJSON `json:"seven_day_sonnet"`
	SevenDayOverageIncluded *claudeUsageWindowJSON `json:"seven_day_overage_included"`
	SevenDayOAuthApps       *claudeUsageWindowJSON `json:"seven_day_oauth_apps"`
	SevenDayCowork          *claudeUsageWindowJSON `json:"seven_day_cowork"`
	Limits                  []claudeUsageLimitJSON `json:"limits"`
}

// ParseClaudeUsage reads the body of api.anthropic.com/api/oauth/usage, the endpoint
// Claude Code uses for /usage. Utilization is a 0-100 percentage there. Model-specific
// weekly windows come from limits[] rows of kind "weekly_scoped" with a model scope.
func ParseClaudeUsage(body []byte, observedAt time.Time) (LimitObservation, error) {
	var payload claudeUsageJSON
	if err := json.Unmarshal(body, &payload); err != nil {
		return LimitObservation{}, fmt.Errorf("decode claude usage: %w", err)
	}
	obs := LimitObservation{Provider: "claude", Source: "usage", ObservedAt: observedAt}
	if window, ok := claudeUsageWindow(payload.FiveHour, fiveHourWindowSeconds); ok {
		obs.FiveHour = window
	}
	if window, ok := claudeUsageWindow(payload.SevenDay, weeklyWindowSeconds); ok {
		obs.Weekly = window
	}
	byName := make(map[string]LimitBucket)
	addBucket := func(name, match string, routing bool, raw *claudeUsageWindowJSON) {
		if window, ok := claudeUsageWindow(raw, weeklyWindowSeconds); ok {
			byName[strings.ToLower(name)] = LimitBucket{Name: name, Match: match, Routing: routing, Window: window, ObservedAt: observedAt}
		}
	}
	addBucket("Opus", "opus", true, payload.SevenDayOpus)
	addBucket("Sonnet", "sonnet", true, payload.SevenDaySonnet)
	addBucket("Weekly (overage included)", "", false, payload.SevenDayOverageIncluded)
	addBucket("OAuth apps", "", false, payload.SevenDayOAuthApps)
	addBucket("Cowork", "", false, payload.SevenDayCowork)
	for _, row := range payload.Limits {
		if row.Percent == nil {
			continue
		}
		window := LimitWindow{Known: true, UsedPercent: clampPercent(*row.Percent)}
		if row.ResetsAt != nil {
			window.ResetAt, _ = parseISOTime(*row.ResetsAt)
		}
		switch strings.ToLower(strings.TrimSpace(row.Kind)) {
		case "session":
			window.WindowSeconds = fiveHourWindowSeconds
			if !obs.FiveHour.Known {
				obs.FiveHour = window
			}
		case "weekly_all":
			window.WindowSeconds = weeklyWindowSeconds
			if !obs.Weekly.Known {
				obs.Weekly = window
			}
		case "weekly_scoped":
			window.WindowSeconds = weeklyWindowSeconds
			if row.Scope != nil && row.Scope.Model != nil && strings.TrimSpace(row.Scope.Model.DisplayName) != "" {
				name := strings.TrimSpace(row.Scope.Model.DisplayName)
				byName[strings.ToLower(name)] = LimitBucket{Name: name, Match: strings.ToLower(name), Routing: true, Window: window, ObservedAt: observedAt}
			} else if row.Scope != nil && row.Scope.Surface != nil && strings.TrimSpace(row.Scope.Surface.DisplayName) != "" {
				name := strings.TrimSpace(row.Scope.Surface.DisplayName)
				byName["surface:"+strings.ToLower(name)] = LimitBucket{Name: name, Window: window, ObservedAt: observedAt}
			}
		}
	}
	obs.Buckets = sortedBuckets(byName)
	if !obs.FiveHour.Known && !obs.Weekly.Known && len(obs.Buckets) == 0 {
		return obs, fmt.Errorf("claude usage has no limit windows")
	}
	return obs, nil
}

func claudeUsageWindow(raw *claudeUsageWindowJSON, windowSeconds int64) (LimitWindow, bool) {
	if raw == nil || raw.Utilization == nil {
		return LimitWindow{}, false
	}
	window := LimitWindow{Known: true, UsedPercent: clampPercent(*raw.Utilization), WindowSeconds: windowSeconds}
	if raw.ResetsAt != nil {
		window.ResetAt, _ = parseISOTime(*raw.ResetsAt)
	}
	return window, true
}

func parseISOTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

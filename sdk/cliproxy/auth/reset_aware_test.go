package auth

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// All fixtures below are synthetic: made-up IDs and limit values only.

func fixedResetAwareSelector(now time.Time, opts ResetAwareOptions) *ResetAwareSelector {
	selector := NewResetAwareSelector(NewResetAwareTracker(""), opts)
	selector.now = func() time.Time { return now }
	return selector
}

func codexSignals(fiveUsed, weeklyUsed float64, fiveReset, weeklyReset time.Time) map[string]string {
	return map[string]string{
		"X-Codex-Primary-Used-Percent":     strconv.FormatFloat(fiveUsed, 'f', -1, 64),
		"X-Codex-Primary-Window-Minutes":   "300",
		"X-Codex-Primary-Reset-At":         strconv.FormatInt(fiveReset.Unix(), 10),
		"X-Codex-Secondary-Used-Percent":   strconv.FormatFloat(weeklyUsed, 'f', -1, 64),
		"X-Codex-Secondary-Window-Minutes": "10080",
		"X-Codex-Secondary-Reset-At":       strconv.FormatInt(weeklyReset.Unix(), 10),
	}
}

func codexTestAuth(id string, observedAt time.Time, fiveUsed, weeklyUsed float64, weeklyReset time.Time) *Auth {
	return &Auth{
		ID:       id,
		Provider: "codex",
		Status:   StatusActive,
		Quota: QuotaState{
			ObservedAt: observedAt,
			Signals:    codexSignals(fiveUsed, weeklyUsed, observedAt.Add(2*time.Hour), weeklyReset),
		},
	}
}

func claudeSignals(fiveFraction, weeklyFraction float64, fiveReset, weeklyReset time.Time) map[string]string {
	return map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Utilization": strconv.FormatFloat(fiveFraction, 'f', -1, 64),
		"Anthropic-Ratelimit-Unified-5h-Reset":       strconv.FormatInt(fiveReset.Unix(), 10),
		"Anthropic-Ratelimit-Unified-7d-Utilization": strconv.FormatFloat(weeklyFraction, 'f', -1, 64),
		"Anthropic-Ratelimit-Unified-7d-Reset":       strconv.FormatInt(weeklyReset.Unix(), 10),
	}
}

func claudeTestAuth(id string, observedAt time.Time, fiveFraction, weeklyFraction float64, weeklyReset time.Time) *Auth {
	return &Auth{
		ID:       id,
		Provider: "claude",
		Status:   StatusActive,
		Quota: QuotaState{
			ObservedAt: observedAt,
			Signals:    claudeSignals(fiveFraction, weeklyFraction, observedAt.Add(3*time.Hour), weeklyReset),
		},
	}
}

func mustPick(t *testing.T, selector Selector, model string, opts cliproxyexecutor.Options, auths []*Auth) string {
	t.Helper()
	picked, err := selector.Pick(context.Background(), "codex", model, opts, auths)
	if err != nil {
		t.Fatalf("Pick returned error: %v", err)
	}
	if picked == nil {
		t.Fatalf("Pick returned nil auth")
	}
	return picked.ID
}

func TestResetAwarePicksSoonestWeeklyReset(t *testing.T) {
	now := time.Now().Truncate(time.Minute)
	auths := []*Auth{
		codexTestAuth("acct-a", now, 10, 40, now.Add(72*time.Hour)),
		codexTestAuth("acct-b", now, 10, 60, now.Add(24*time.Hour)),
		codexTestAuth("acct-c", now, 10, 5, now.Add(120*time.Hour)),
	}
	selector := fixedResetAwareSelector(now, DefaultResetAwareOptions())
	if got := mustPick(t, selector, "gpt-test", cliproxyexecutor.Options{}, auths); got != "acct-b" {
		t.Fatalf("picked %q, want the soonest weekly reset acct-b", got)
	}
}

func TestResetAwareBreaksResetTiesByHeadroom(t *testing.T) {
	now := time.Now().Truncate(time.Minute)
	reset := now.Add(24 * time.Hour)
	auths := []*Auth{
		codexTestAuth("acct-a", now, 10, 70, reset),
		codexTestAuth("acct-b", now, 10, 20, reset),
	}
	selector := fixedResetAwareSelector(now, DefaultResetAwareOptions())
	if got := mustPick(t, selector, "gpt-test", cliproxyexecutor.Options{}, auths); got != "acct-b" {
		t.Fatalf("picked %q, want acct-b with more weekly headroom", got)
	}
}

func TestResetAwareSkipsFiveHourLimitedAccount(t *testing.T) {
	now := time.Now().Truncate(time.Minute)
	auths := []*Auth{
		codexTestAuth("acct-a", now, 10, 40, now.Add(72*time.Hour)),
		codexTestAuth("acct-b", now, 99, 60, now.Add(24*time.Hour)),
	}
	selector := fixedResetAwareSelector(now, DefaultResetAwareOptions())
	if got := mustPick(t, selector, "gpt-test", cliproxyexecutor.Options{}, auths); got != "acct-a" {
		t.Fatalf("picked %q, want acct-a because acct-b is over the five-hour threshold", got)
	}
}

func TestResetAwareSkipsWeeklyLimitedAccount(t *testing.T) {
	now := time.Now().Truncate(time.Minute)
	auths := []*Auth{
		codexTestAuth("acct-a", now, 10, 40, now.Add(72*time.Hour)),
		codexTestAuth("acct-b", now, 10, 98, now.Add(24*time.Hour)),
	}
	selector := fixedResetAwareSelector(now, DefaultResetAwareOptions())
	if got := mustPick(t, selector, "gpt-test", cliproxyexecutor.Options{}, auths); got != "acct-a" {
		t.Fatalf("picked %q, want acct-a because acct-b reached the weekly threshold", got)
	}
}

func TestResetAwareRespectsModelSpecificBucket(t *testing.T) {
	now := time.Now().Truncate(time.Minute)
	soon, later := now.Add(24*time.Hour), now.Add(48*time.Hour)
	authA := claudeTestAuth("acct-a", now, 0.10, 0.30, soon)
	authB := claudeTestAuth("acct-b", now, 0.10, 0.30, later)
	selector := fixedResetAwareSelector(now, DefaultResetAwareOptions())
	selector.tracker.ApplyObservation("acct-a", LimitObservation{
		Provider:   "claude",
		Source:     "usage",
		ObservedAt: now.Add(-time.Minute),
		Buckets: []LimitBucket{{
			Name: "Fable", Match: "fable", Routing: true, ObservedAt: now.Add(-time.Minute),
			Window: LimitWindow{Known: true, UsedPercent: 99, ResetAt: soon, WindowSeconds: weeklyWindowSeconds},
		}},
	})
	auths := []*Auth{authA, authB}
	if got := mustPick(t, selector, "claude-fable-test", cliproxyexecutor.Options{}, auths); got != "acct-b" {
		t.Fatalf("fable request picked %q, want acct-b because acct-a's Fable bucket is full", got)
	}
	if got := mustPick(t, selector, "claude-opus-test", cliproxyexecutor.Options{}, auths); got != "acct-a" {
		t.Fatalf("opus request picked %q, want acct-a because the Fable bucket does not apply", got)
	}
}

func TestResetAwareCodexPerModelHeaderBucket(t *testing.T) {
	now := time.Now().Truncate(time.Minute)
	authA := codexTestAuth("acct-a", now, 10, 30, now.Add(24*time.Hour))
	signals := codexSignals(10, 30, now.Add(2*time.Hour), now.Add(24*time.Hour))
	signals["X-Codex-Additional-Spark-Secondary-Used-Percent"] = "100"
	signals["X-Codex-Additional-Spark-Secondary-Window-Minutes"] = "10080"
	signals["X-Codex-Additional-Spark-Secondary-Reset-At"] = strconv.FormatInt(now.Add(24*time.Hour).Unix(), 10)
	authA.ModelStates = map[string]*ModelState{"gpt-spark-test": {Status: StatusActive, Quota: QuotaState{ObservedAt: now, Signals: signals}}}
	authB := codexTestAuth("acct-b", now, 10, 30, now.Add(48*time.Hour))
	selector := fixedResetAwareSelector(now, DefaultResetAwareOptions())
	auths := []*Auth{authA, authB}
	if got := mustPick(t, selector, "gpt-spark-test", cliproxyexecutor.Options{}, auths); got != "acct-b" {
		t.Fatalf("spark request picked %q, want acct-b because acct-a's spark bucket is full", got)
	}
	if got := mustPick(t, selector, "gpt-other-test", cliproxyexecutor.Options{}, auths); got != "acct-a" {
		t.Fatalf("other request picked %q, want acct-a with the soonest weekly reset", got)
	}
}

func TestResetAwareRanksUnknownDataLast(t *testing.T) {
	now := time.Now().Truncate(time.Minute)
	unknown := &Auth{ID: "acct-a", Provider: "codex", Status: StatusActive}
	auths := []*Auth{unknown, codexTestAuth("acct-b", now, 10, 10, now.Add(160*time.Hour))}
	selector := fixedResetAwareSelector(now, DefaultResetAwareOptions())
	if got := mustPick(t, selector, "gpt-test", cliproxyexecutor.Options{}, auths); got != "acct-b" {
		t.Fatalf("picked %q, want acct-b because acct-a has no limit data", got)
	}
}

func TestResetAwareRotatesAmongUnknownAccounts(t *testing.T) {
	now := time.Now().Truncate(time.Minute)
	auths := []*Auth{
		{ID: "acct-a", Provider: "codex", Status: StatusActive},
		{ID: "acct-b", Provider: "codex", Status: StatusActive},
	}
	selector := fixedResetAwareSelector(now, DefaultResetAwareOptions())
	first := mustPick(t, selector, "gpt-test", cliproxyexecutor.Options{}, auths)
	second := mustPick(t, selector, "gpt-test", cliproxyexecutor.Options{}, auths)
	if first == second {
		t.Fatalf("expected round-robin among accounts without data, got %q twice", first)
	}
}

func TestResetAwareFallsBackWhenEveryAccountIsLimited(t *testing.T) {
	now := time.Now().Truncate(time.Minute)
	auths := []*Auth{
		codexTestAuth("acct-a", now, 99, 99, now.Add(72*time.Hour)),
		codexTestAuth("acct-b", now, 99, 99, now.Add(24*time.Hour)),
	}
	selector := fixedResetAwareSelector(now, DefaultResetAwareOptions())
	if got := mustPick(t, selector, "gpt-test", cliproxyexecutor.Options{}, auths); got != "acct-b" {
		t.Fatalf("picked %q, want acct-b (soonest reset) when every account is limited", got)
	}
	filtered := selector.FilterCandidates(context.Background(), "codex", "gpt-test", auths)
	if len(filtered) != len(auths) {
		t.Fatalf("FilterCandidates kept %d of %d; it must keep all when none are eligible", len(filtered), len(auths))
	}
}

func TestResetAwareSessionAffinityKeepsBindingThenFailsOver(t *testing.T) {
	now := time.Now().Truncate(time.Minute)
	authA := codexTestAuth("acct-a", now, 10, 40, now.Add(24*time.Hour))
	authB := codexTestAuth("acct-b", now, 10, 40, now.Add(72*time.Hour))
	resetAware := fixedResetAwareSelector(now, DefaultResetAwareOptions())
	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: resetAware, TTL: time.Hour})
	defer affinity.Stop()
	session := func(id string) cliproxyexecutor.Options {
		return cliproxyexecutor.Options{Metadata: map[string]any{cliproxyexecutor.DerivedSessionIDMetadataKey: id}}
	}
	auths := []*Auth{authA, authB}

	if got := mustPick(t, affinity, "gpt-test", session("session-1"), auths); got != "acct-a" {
		t.Fatalf("new session picked %q, want top-ranked acct-a", got)
	}

	// acct-b now resets sooner, but the bound session keeps acct-a and its warm cache.
	authB.Quota = QuotaState{ObservedAt: now.Add(time.Minute), Signals: codexSignals(10, 40, now.Add(2*time.Hour), now.Add(12*time.Hour))}
	if got := mustPick(t, affinity, "gpt-test", session("session-1"), auths); got != "acct-a" {
		t.Fatalf("bound session moved to %q, want it to stay on acct-a", got)
	}
	if got := mustPick(t, affinity, "gpt-test", session("session-2"), auths); got != "acct-b" {
		t.Fatalf("new session picked %q, want acct-b which now resets soonest", got)
	}

	// acct-a hits its five-hour limit, so the bound session fails over and stays there.
	authA.Quota = QuotaState{ObservedAt: now.Add(2 * time.Minute), Signals: codexSignals(99, 40, now.Add(2*time.Hour), now.Add(24*time.Hour))}
	if got := mustPick(t, affinity, "gpt-test", session("session-1"), auths); got != "acct-b" {
		t.Fatalf("session on a limited account picked %q, want failover to acct-b", got)
	}
	authA.Quota = QuotaState{ObservedAt: now.Add(3 * time.Minute), Signals: codexSignals(5, 40, now.Add(2*time.Hour), now.Add(6*time.Hour))}
	if got := mustPick(t, affinity, "gpt-test", session("session-1"), auths); got != "acct-b" {
		t.Fatalf("session moved back to %q after failover, want it to stay on acct-b", got)
	}
}

func TestResetAwareDetectsEarlyResetFromUtilizationDrop(t *testing.T) {
	now := time.Now().Truncate(time.Minute)
	tracker := NewResetAwareTracker("")
	reset := now.Add(72 * time.Hour)
	tracker.ApplyObservation("acct-a", LimitObservation{Provider: "codex", Source: "usage", ObservedAt: now, Weekly: LimitWindow{Known: true, UsedPercent: 80, ResetAt: reset, WindowSeconds: weeklyWindowSeconds}})
	tracker.ApplyObservation("acct-a", LimitObservation{Provider: "codex", Source: "usage", ObservedAt: now.Add(time.Hour), Weekly: LimitWindow{Known: true, UsedPercent: 3, ResetAt: now.Add(7 * 24 * time.Hour), WindowSeconds: weeklyWindowSeconds}})
	limits, _ := tracker.Get("acct-a")
	if !limits.LastResetAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("LastResetAt = %v, want the drop observation time %v", limits.LastResetAt, now.Add(time.Hour))
	}
	if limits.Weekly.UsedPercent != 3 {
		t.Fatalf("weekly used = %v, want the freshest value 3", limits.Weekly.UsedPercent)
	}
}

func TestResetAwareIgnoresOlderObservation(t *testing.T) {
	now := time.Now().Truncate(time.Minute)
	tracker := NewResetAwareTracker("")
	tracker.ApplyObservation("acct-a", LimitObservation{Provider: "codex", ObservedAt: now, Weekly: LimitWindow{Known: true, UsedPercent: 50, ResetAt: now.Add(time.Hour)}})
	tracker.ApplyObservation("acct-a", LimitObservation{Provider: "codex", ObservedAt: now.Add(-time.Hour), Weekly: LimitWindow{Known: true, UsedPercent: 10, ResetAt: now.Add(time.Hour)}})
	limits, _ := tracker.Get("acct-a")
	if limits.Weekly.UsedPercent != 50 {
		t.Fatalf("weekly used = %v, want 50 from the newer observation", limits.Weekly.UsedPercent)
	}
}

func TestResetAwareWindowRolloverStyles(t *testing.T) {
	start := time.Now().Truncate(time.Minute)
	window := LimitWindow{Known: true, UsedPercent: 60, ResetAt: start, WindowSeconds: weeklyWindowSeconds}
	now := start.Add(2 * time.Hour)

	codex := window.effectiveAt(now, false)
	if codex.UsedPercent != 0 || !codex.Estimated || !codex.ResetAt.Equal(now.Add(7*24*time.Hour)) {
		t.Fatalf("codex rollover = %+v, want 0%% used and a new window starting now", codex)
	}
	claude := window.effectiveAt(now, true)
	if claude.UsedPercent != 0 || !claude.Estimated || !claude.ResetAt.Equal(start.Add(7*24*time.Hour)) {
		t.Fatalf("claude rollover = %+v, want 0%% used and the timer kept on its old schedule", claude)
	}
}

func TestResetAwareTrackerPersistsState(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "state.json")
	tracker := NewResetAwareTracker(path)
	tracker.ApplyObservation("acct-a", LimitObservation{Provider: "claude", Source: "usage", ObservedAt: now, Weekly: LimitWindow{Known: true, UsedPercent: 42, ResetAt: now.Add(time.Hour), WindowSeconds: weeklyWindowSeconds}})
	if err := tracker.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("state file mode = %o, want 600", mode)
	}
	reloaded, ok := NewResetAwareTracker(path).Get("acct-a")
	if !ok || reloaded.Weekly.UsedPercent != 42 || !reloaded.UsageObservedAt.Equal(now) {
		t.Fatalf("reloaded = %+v (ok=%t), want the saved weekly window", reloaded, ok)
	}
}

func TestResetAwareRefreshScheduling(t *testing.T) {
	now := time.Now().Truncate(time.Minute)
	tracker := NewResetAwareTracker("")
	if !tracker.DueForRefresh("acct-a", "codex", now, 15*time.Minute) {
		t.Fatalf("an account with no data must be due for refresh")
	}
	tracker.ApplyObservation("acct-a", LimitObservation{Provider: "codex", Source: "headers", ObservedAt: now, Weekly: LimitWindow{Known: true, UsedPercent: 1, ResetAt: now.Add(time.Hour)}})
	if tracker.DueForRefresh("acct-a", "codex", now.Add(5*time.Minute), 15*time.Minute) {
		t.Fatalf("fresh codex header data must not trigger a usage refresh")
	}
	tracker.ApplyObservation("acct-b", LimitObservation{Provider: "claude", Source: "headers", ObservedAt: now, Weekly: LimitWindow{Known: true, UsedPercent: 1, ResetAt: now.Add(time.Hour)}})
	if !tracker.DueForRefresh("acct-b", "claude", now.Add(5*time.Minute), 15*time.Minute) {
		t.Fatalf("claude headers lack model buckets, so only usage data keeps the account fresh")
	}
	tracker.ScheduleRefresh("acct-b", "claude", now.Add(10*time.Minute))
	if tracker.DueForRefresh("acct-b", "claude", now.Add(5*time.Minute), 15*time.Minute) {
		t.Fatalf("a scheduled next refresh must be respected")
	}
	if tracker.DueForRefresh("acct-a", "codex", now, 0) {
		t.Fatalf("a zero interval disables refreshes")
	}
}

func TestParseCodexHeaderSignals(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	obs, ok := ParseCodexHeaderSignals(map[string]string{
		"X-Codex-Primary-Used-Percent":             "4",
		"X-Codex-Primary-Window-Minutes":           "300",
		"X-Codex-Primary-Reset-After-Seconds":      "600",
		"X-Codex-Secondary-Used-Percent":           "59",
		"X-Codex-Secondary-Window-Minutes":         "10080",
		"X-Codex-Secondary-Reset-At":               "1800100000",
		"X-Codex-Code-Review-Primary-Used-Percent": "7",
	}, now)
	if !ok {
		t.Fatalf("expected codex signals to parse")
	}
	if obs.FiveHour.UsedPercent != 4 || !obs.FiveHour.ResetAt.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("five-hour = %+v", obs.FiveHour)
	}
	if obs.Weekly.UsedPercent != 59 || obs.Weekly.ResetAt.Unix() != 1_800_100_000 || obs.Weekly.WindowSeconds != weeklyWindowSeconds {
		t.Fatalf("weekly = %+v", obs.Weekly)
	}
	if len(obs.Buckets) != 1 || obs.Buckets[0].Routing {
		t.Fatalf("code review bucket = %+v, want one informational bucket", obs.Buckets)
	}
}

func TestParseClaudeHeaderSignalsConvertsFractions(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	obs, ok := ParseClaudeHeaderSignals(map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Utilization":    "0.24",
		"Anthropic-Ratelimit-Unified-5h-Reset":          "1800010000",
		"Anthropic-Ratelimit-Unified-7d-Utilization":    "0.34",
		"Anthropic-Ratelimit-Unified-7d-Reset":          "1800200000",
		"Anthropic-Ratelimit-Unified-7d_oi-Utilization": "0.5",
	}, now)
	if !ok {
		t.Fatalf("expected claude signals to parse")
	}
	if obs.FiveHour.UsedPercent != 24 || obs.Weekly.UsedPercent != 34 || obs.Weekly.ResetAt.Unix() != 1_800_200_000 {
		t.Fatalf("claude windows = %+v %+v", obs.FiveHour, obs.Weekly)
	}
	if len(obs.Buckets) != 1 || obs.Buckets[0].Routing {
		t.Fatalf("overage-included bucket = %+v, want one informational bucket", obs.Buckets)
	}
}

func TestParseCodexUsage(t *testing.T) {
	body := []byte(`{
		"plan_type": "plus",
		"rate_limit": {
			"primary_window": {"used_percent": 3, "limit_window_seconds": 18000, "reset_after_seconds": 100, "reset_at": 1800000100},
			"secondary_window": {"used_percent": 51, "limit_window_seconds": 604800, "reset_after_seconds": 5000, "reset_at": 1800005000}
		},
		"code_review_rate_limit": null,
		"additional_rate_limits": [
			{"limit_name": "Spark", "metered_feature": "gpt-spark", "rate_limit": {
				"primary_window": {"used_percent": 10, "limit_window_seconds": 18000, "reset_at": 1800000200},
				"secondary_window": {"used_percent": 70, "limit_window_seconds": 604800, "reset_at": 1800300000}
			}}
		]
	}`)
	obs, err := ParseCodexUsage(body, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatalf("ParseCodexUsage: %v", err)
	}
	if obs.FiveHour.UsedPercent != 3 || obs.Weekly.UsedPercent != 51 || obs.Weekly.ResetAt.Unix() != 1_800_005_000 {
		t.Fatalf("codex usage windows = %+v %+v", obs.FiveHour, obs.Weekly)
	}
	if len(obs.Buckets) != 1 || obs.Buckets[0].Name != "Spark" || obs.Buckets[0].Window.UsedPercent != 70 || !obs.Buckets[0].appliesTo("gpt-spark-2") {
		t.Fatalf("codex usage buckets = %+v", obs.Buckets)
	}
}

func TestParseClaudeUsageReadsModelScopedLimits(t *testing.T) {
	body := []byte(`{
		"five_hour": {"utilization": 25, "resets_at": "2027-01-01T04:00:00Z"},
		"seven_day": {"utilization": 35, "resets_at": "2027-01-03T14:00:00Z"},
		"seven_day_opus": null,
		"limits": [
			{"kind": "session", "group": "session", "percent": 25, "resets_at": "2027-01-01T04:00:00Z"},
			{"kind": "weekly_all", "group": "weekly", "percent": 35, "resets_at": "2027-01-03T14:00:00Z"},
			{"kind": "weekly_scoped", "group": "weekly", "percent": 17, "resets_at": "2027-01-03T14:00:00Z", "scope": {"model": {"display_name": "Fable"}}}
		]
	}`)
	obs, err := ParseClaudeUsage(body, time.Now())
	if err != nil {
		t.Fatalf("ParseClaudeUsage: %v", err)
	}
	if obs.FiveHour.UsedPercent != 25 || obs.Weekly.UsedPercent != 35 {
		t.Fatalf("claude usage windows = %+v %+v", obs.FiveHour, obs.Weekly)
	}
	if len(obs.Buckets) != 1 || obs.Buckets[0].Name != "Fable" || !obs.Buckets[0].appliesTo("claude-fable-test") || obs.Buckets[0].appliesTo("claude-opus-test") {
		t.Fatalf("claude usage buckets = %+v", obs.Buckets)
	}
}

func TestResetAwareLimitsReportRanksAndMasks(t *testing.T) {
	now := time.Now().Truncate(time.Minute)
	authA := codexTestAuth("acct-a", now, 10, 40, now.Add(72*time.Hour))
	authA.Metadata = map[string]any{"email": "someone@example.test"}
	authB := codexTestAuth("acct-b", now, 99, 40, now.Add(24*time.Hour))
	authC := codexTestAuth("acct-c", now, 10, 40, now.Add(48*time.Hour))
	report := BuildResetAwareLimitsReport([]*Auth{authA, authB, authC}, nil, DefaultResetAwareOptions(), now)
	if len(report.Accounts) != 3 {
		t.Fatalf("report has %d accounts, want 3", len(report.Accounts))
	}
	order := []string{report.Accounts[0].Label, report.Accounts[1].Label, report.Accounts[2].Label}
	if report.Accounts[0].Rank != 1 || report.Accounts[2].Eligible {
		t.Fatalf("unexpected ranking %+v", report.Accounts)
	}
	for _, label := range order {
		if label == "someone@example.test" {
			t.Fatalf("email was not masked: %v", order)
		}
	}
	if got := MaskEmail("someone@example.test"); got != "so•••@ex•••.test" {
		t.Fatalf("MaskEmail = %q", got)
	}
}

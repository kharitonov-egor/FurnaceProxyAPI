package cliproxy

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	log "github.com/sirupsen/logrus"
)

const (
	resetAwareStrategy           = "reset-aware"
	resetAwareDefaultStateFile   = "reset-aware-state.json"
	resetAwarePollTick           = time.Minute
	resetAwareFirstPollDelay     = 10 * time.Second
	resetAwareUsageTimeout       = 30 * time.Second
	resetAwareMaxUsageBodyBytes  = 1 << 20
	resetAwareCodexUsageURL      = "https://chatgpt.com/backend-api/wham/usage"
	resetAwareClaudeUsageURL     = "https://api.anthropic.com/api/oauth/usage"
	resetAwareClaudeBetaHeader   = "oauth-2025-04-20"
	resetAwareClaudeUserAgent    = "claude-cli/2.1.287 (external, cli)"
	resetAwareCodexUserAgent     = "codex_cli_rs/0.160.0"
	resetAwareCodexAccountHeader = "ChatGPT-Account-Id"
)

// resetAwareSettings is the comparable part of routing.reset-aware.
type resetAwareSettings struct {
	fiveHourThreshold float64
	weeklyThreshold   float64
	refreshInterval   time.Duration
	refreshJitter     time.Duration
	stateFile         string
}

func normalizedResetAwareSettings(cfg *config.Config) resetAwareSettings {
	if cfg == nil {
		cfg = &config.Config{}
	}
	raw := cfg.Routing.ResetAware
	return resetAwareSettings{
		fiveHourThreshold: raw.FiveHourThreshold,
		weeklyThreshold:   raw.WeeklyThreshold,
		refreshInterval:   raw.RefreshIntervalDuration(),
		refreshJitter:     raw.RefreshJitterDuration(),
		stateFile:         strings.TrimSpace(raw.StateFile),
	}
}

func (s *Service) currentResetAwareConfig() *config.Config {
	if s == nil {
		return nil
	}
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

// resetAwareRuntime owns the limit tracker and the usage poller. The tracker outlives
// selector swaps on config reload so cached limits are not lost.
type resetAwareRuntime struct {
	mu         sync.Mutex
	configPath string
	tracker    *coreauth.ResetAwareTracker
	cancel     context.CancelFunc
	done       chan struct{}
	running    resetAwareSettings
}

func newResetAwareRuntime(configPath string) *resetAwareRuntime {
	return &resetAwareRuntime{configPath: configPath}
}

func (r *resetAwareRuntime) statePath(settings resetAwareSettings) string {
	path := settings.stateFile
	if path == "" {
		dir := "."
		if r != nil && strings.TrimSpace(r.configPath) != "" {
			dir = filepath.Dir(r.configPath)
		}
		path = filepath.Join(dir, resetAwareDefaultStateFile)
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, path[2:])
		}
	}
	return path
}

// trackerFor returns the shared tracker, reopening it when the state path changes.
func (r *resetAwareRuntime) trackerFor(settings resetAwareSettings) *coreauth.ResetAwareTracker {
	if r == nil {
		return coreauth.NewResetAwareTracker("")
	}
	path := r.statePath(settings)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tracker == nil || r.tracker.StatePath() != path {
		if r.tracker != nil {
			if errSave := r.tracker.Save(); errSave != nil {
				log.Warnf("reset-aware: save state before switching files: %v", errSave)
			}
		}
		r.tracker = coreauth.NewResetAwareTracker(path)
	}
	return r.tracker
}

func (r *resetAwareRuntime) selector(settings resetAwareSettings) coreauth.Selector {
	return coreauth.NewResetAwareSelector(r.trackerFor(settings), coreauth.ResetAwareOptions{
		FiveHourThreshold: settings.fiveHourThreshold,
		WeeklyThreshold:   settings.weeklyThreshold,
	})
}

// reconcile starts, restarts, or stops the usage poller to match the routing state.
func (r *resetAwareRuntime) reconcile(manager *coreauth.Manager, cfgFn func() *config.Config, state routingRuntimeState) {
	if r == nil {
		return
	}
	wantPoller := state.strategy == resetAwareStrategy && state.resetAware.refreshInterval > 0 && manager != nil
	r.mu.Lock()
	if r.cancel != nil && (!wantPoller || r.running != state.resetAware) {
		cancel, done := r.cancel, r.done
		r.cancel, r.done = nil, nil
		r.mu.Unlock()
		cancel()
		<-done
		r.mu.Lock()
	}
	if !wantPoller || r.cancel != nil {
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()
	tracker := r.trackerFor(state.resetAware)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	r.mu.Lock()
	r.cancel, r.done, r.running = cancel, done, state.resetAware
	r.mu.Unlock()
	go func() {
		defer close(done)
		runResetAwarePoller(ctx, manager, cfgFn, tracker, state.resetAware)
	}()
	log.Infof("reset-aware: usage poller started (interval=%s jitter=%s state=%s)", state.resetAware.refreshInterval, state.resetAware.refreshJitter, tracker.StatePath())
}

func (r *resetAwareRuntime) stop() {
	if r == nil {
		return
	}
	r.mu.Lock()
	cancel, done, tracker := r.cancel, r.done, r.tracker
	r.cancel, r.done = nil, nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	if tracker != nil {
		if errSave := tracker.Save(); errSave != nil {
			log.Warnf("reset-aware: save state on shutdown: %v", errSave)
		}
	}
}

func runResetAwarePoller(ctx context.Context, manager *coreauth.Manager, cfgFn func() *config.Config, tracker *coreauth.ResetAwareTracker, settings resetAwareSettings) {
	timer := time.NewTimer(resetAwareFirstPollDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		pollResetAwareUsage(ctx, manager, cfgFn, tracker, settings)
		if errSave := tracker.Save(); errSave != nil {
			log.Warnf("reset-aware: save state: %v", errSave)
		}
		timer.Reset(resetAwarePollTick)
	}
}

func pollResetAwareUsage(ctx context.Context, manager *coreauth.Manager, cfgFn func() *config.Config, tracker *coreauth.ResetAwareTracker, settings resetAwareSettings) {
	auths := manager.List()
	keep := make(map[string]struct{}, len(auths))
	for _, auth := range auths {
		if auth != nil {
			keep[auth.ID] = struct{}{}
		}
	}
	tracker.Prune(keep)
	var cfg *config.Config
	if cfgFn != nil {
		cfg = cfgFn()
	}
	for _, auth := range auths {
		if ctx.Err() != nil {
			return
		}
		if auth == nil || auth.Disabled || !coreauth.ResetAwareProviderSupported(auth.Provider) {
			continue
		}
		tracker.ObserveAuth(auth)
		now := time.Now()
		if !tracker.DueForRefresh(auth.ID, auth.Provider, now, settings.refreshInterval) {
			continue
		}
		next := now.Add(settings.refreshInterval)
		if settings.refreshJitter > 0 {
			next = next.Add(time.Duration(rand.Int64N(int64(settings.refreshJitter))))
		}
		tracker.ScheduleRefresh(auth.ID, auth.Provider, next)
		obs, errFetch := fetchResetAwareUsage(ctx, cfg, auth)
		if errFetch != nil {
			tracker.RecordRefreshError(auth.ID, auth.Provider, errFetch.Error())
			log.Debugf("reset-aware: usage refresh failed | auth=%s provider=%s err=%v", auth.ID, auth.Provider, errFetch)
			continue
		}
		tracker.ApplyObservation(auth.ID, obs)
	}
}

func metadataString(auth *coreauth.Auth, key string) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	value, _ := auth.Metadata[key].(string)
	return strings.TrimSpace(value)
}

// fetchResetAwareUsage calls the usage endpoint the official CLI uses for this provider.
// Errors never include the token or the response body.
func fetchResetAwareUsage(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) (coreauth.LimitObservation, error) {
	token := metadataString(auth, "access_token")
	if token == "" {
		return coreauth.LimitObservation{}, fmt.Errorf("no access token")
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	// A bounded probe: this is a background status read, not proxied traffic.
	requestCtx, cancel := context.WithTimeout(ctx, resetAwareUsageTimeout)
	defer cancel()
	var target string
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)
	headers.Set("Accept", "application/json")
	switch provider {
	case "codex":
		target = resetAwareCodexUsageURL
		headers.Set("User-Agent", resetAwareCodexUserAgent)
		if accountID := metadataString(auth, "account_id"); accountID != "" {
			headers.Set(resetAwareCodexAccountHeader, accountID)
		}
	case "claude":
		target = resetAwareClaudeUsageURL
		headers.Set("User-Agent", resetAwareClaudeUserAgent)
		headers.Set("anthropic-beta", resetAwareClaudeBetaHeader)
		headers.Set("Content-Type", "application/json")
	default:
		return coreauth.LimitObservation{}, fmt.Errorf("unsupported provider")
	}
	request, errRequest := http.NewRequestWithContext(requestCtx, http.MethodGet, target, nil)
	if errRequest != nil {
		return coreauth.LimitObservation{}, fmt.Errorf("build request: %w", errRequest)
	}
	request.Header = headers
	client := helps.NewProxyAwareHTTPClient(requestCtx, cfg, auth, 0)
	response, errDo := client.Do(request)
	if errDo != nil {
		return coreauth.LimitObservation{}, fmt.Errorf("request failed")
	}
	defer func() {
		if errClose := response.Body.Close(); errClose != nil {
			log.Debugf("reset-aware: close usage body: %v", errClose)
		}
	}()
	body, errRead := io.ReadAll(io.LimitReader(response.Body, resetAwareMaxUsageBodyBytes))
	if errRead != nil {
		return coreauth.LimitObservation{}, fmt.Errorf("read response failed")
	}
	if response.StatusCode != http.StatusOK {
		return coreauth.LimitObservation{}, fmt.Errorf("usage endpoint returned HTTP %d", response.StatusCode)
	}
	observedAt := time.Now()
	if provider == "codex" {
		return coreauth.ParseCodexUsage(body, observedAt)
	}
	return coreauth.ParseClaudeUsage(body, observedAt)
}

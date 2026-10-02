package cliproxy

import (
	"path/filepath"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestNormalizedRoutingRuntimeStateResetAware(t *testing.T) {
	cfg := &internalconfig.Config{}
	cfg.Routing.Strategy = "Reset-Aware"
	cfg.Routing.SessionAffinity = true
	cfg.Routing.ResetAware = internalconfig.ResetAwareRoutingConfig{WeeklyThreshold: 90, RefreshInterval: "0", RefreshJitter: "30s"}

	state := normalizedRoutingRuntimeState(cfg)
	if state.strategy != resetAwareStrategy {
		t.Fatalf("strategy = %q, want %q", state.strategy, resetAwareStrategy)
	}
	if state.resetAware.weeklyThreshold != 90 || state.resetAware.refreshInterval != 0 || state.resetAware.refreshJitter != 30*time.Second {
		t.Fatalf("reset-aware settings = %+v", state.resetAware)
	}

	runtime := newResetAwareRuntime(filepath.Join(t.TempDir(), "config.yaml"))
	selector := newRoutingSelectorWithResetAware(state, runtime)
	resetAware, ok := coreauth.ResetAwareSelectorOf(selector)
	if !ok {
		t.Fatalf("selector %T does not wrap a reset-aware selector", selector)
	}
	if _, affinity := selector.(*coreauth.SessionAffinitySelector); !affinity {
		t.Fatalf("selector = %T, want session affinity around reset-aware", selector)
	}
	if got := resetAware.Options().WeeklyThreshold; got != 90 {
		t.Fatalf("weekly threshold = %v, want 90", got)
	}
	if got, want := resetAware.Tracker().StatePath(), filepath.Join(filepath.Dir(runtime.configPath), resetAwareDefaultStateFile); got != want {
		t.Fatalf("state path = %q, want %q", got, want)
	}
	if again, _ := coreauth.ResetAwareSelectorOf(newRoutingSelectorWithResetAware(state, runtime)); again.Tracker() != resetAware.Tracker() {
		t.Fatalf("a rebuilt selector must reuse the tracker so cached limits survive config reloads")
	}
}

func TestNormalizedRoutingRuntimeStateDefaultsUnchanged(t *testing.T) {
	cfg := &internalconfig.Config{}
	cfg.Routing.ResetAware.WeeklyThreshold = 50
	state := normalizedRoutingRuntimeState(cfg)
	if state.strategy != "round-robin" || state.resetAware != (resetAwareSettings{}) {
		t.Fatalf("default strategy state = %+v; reset-aware settings must stay inert", state)
	}
	if _, ok := newRoutingSelector(state).(*coreauth.RoundRobinSelector); !ok {
		t.Fatalf("default selector changed")
	}
}

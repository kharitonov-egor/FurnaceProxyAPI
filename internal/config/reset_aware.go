package config

import (
	"strconv"
	"strings"
	"time"
)

const (
	defaultResetAwareRefreshInterval = 15 * time.Minute
	defaultResetAwareRefreshJitter   = 3 * time.Minute
)

// ResetAwareRoutingConfig tunes routing.strategy "reset-aware", which drains the
// credential whose weekly limit resets soonest. Other strategies ignore it.
type ResetAwareRoutingConfig struct {
	// FiveHourThreshold is the five-hour utilization percent at which a credential stops
	// receiving new work. Default: 98.
	FiveHourThreshold float64 `yaml:"five-hour-threshold,omitempty" json:"five-hour-threshold,omitempty"`

	// WeeklyThreshold applies to the weekly window and to the requested model's weekly
	// bucket. Default: 98.
	WeeklyThreshold float64 `yaml:"weekly-threshold,omitempty" json:"weekly-threshold,omitempty"`

	// RefreshInterval is how often idle or stale credentials are refreshed from the
	// provider usage endpoints. "0" disables polling. Default: 15m.
	RefreshInterval string `yaml:"refresh-interval,omitempty" json:"refresh-interval,omitempty"`

	// RefreshJitter adds a random delay of up to this duration to each refresh. Default: 3m.
	RefreshJitter string `yaml:"refresh-jitter,omitempty" json:"refresh-jitter,omitempty"`

	// StateFile persists cached limits across restarts.
	// Default: reset-aware-state.json next to the config file.
	StateFile string `yaml:"state-file,omitempty" json:"state-file,omitempty"`
}

// RefreshIntervalDuration returns the usage refresh interval. Zero disables polling.
func (c ResetAwareRoutingConfig) RefreshIntervalDuration() time.Duration {
	return parseResetAwareDuration(c.RefreshInterval, defaultResetAwareRefreshInterval)
}

// RefreshJitterDuration returns the maximum random delay added to each refresh.
func (c ResetAwareRoutingConfig) RefreshJitterDuration() time.Duration {
	return parseResetAwareDuration(c.RefreshJitter, defaultResetAwareRefreshJitter)
}

// parseResetAwareDuration accepts Go durations ("15m") and plain seconds ("900").
// Empty, negative, or invalid values fall back to the default.
func parseResetAwareDuration(raw string, fallback time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	if seconds, err := strconv.ParseFloat(raw, 64); err == nil {
		if seconds < 0 {
			return fallback
		}
		return time.Duration(seconds * float64(time.Second))
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed < 0 {
		return fallback
	}
	return parsed
}

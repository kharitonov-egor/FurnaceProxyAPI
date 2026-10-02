package management

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// GetRoutingLimits reports each Codex and Claude credential's limit windows and its place
// in the reset-aware order. Under other strategies it still answers, using only the header
// snapshots currently held in memory, and reports enabled=false.
func (h *Handler) GetRoutingLimits(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth manager unavailable"})
		return
	}
	resetAware, enabled := coreauth.ResetAwareSelectorOf(h.authManager.Selector())
	var tracker *coreauth.ResetAwareTracker
	opts := coreauth.DefaultResetAwareOptions()
	if enabled {
		tracker = resetAware.Tracker()
		opts = resetAware.Options()
	}
	report := coreauth.BuildResetAwareLimitsReport(h.authManager.List(), tracker, opts, time.Now())
	report.Enabled = enabled
	if h.cfg != nil {
		report.Strategy = strings.TrimSpace(h.cfg.Routing.Strategy)
		if enabled {
			report.RefreshIntervalSeconds = int64(h.cfg.Routing.ResetAware.RefreshIntervalDuration() / time.Second)
		}
	}
	c.JSON(http.StatusOK, report)
}

package main

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// Get security events
func GetSecurityEvents(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "50")
	offsetStr := c.DefaultQuery("offset", "0")
	severity := c.Query("severity")

	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	events, err := GetSecurityEventsFromDB(limit, offset, severity)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"limit":  limit,
		"offset": offset,
	})
}

// Get single security event
func GetSecurityEvent(c *gin.Context) {
	id := c.Param("id")

	var event SecurityEvent
	var matchPattern sql.NullString
	var status sql.NullString
	query := `SELECT id, type, severity, ip, path, method, user_agent, details, payload, match_pattern, status, timestamp 
              FROM security_events WHERE id = ?`

	err := db.QueryRow(query, id).Scan(
		&event.ID, &event.Type, &event.Severity, &event.IP, &event.Path,
		&event.Method, &event.UserAgent, &event.Details, &event.Payload,
		&matchPattern, &status, &event.Timestamp,
	)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Event not found"})
		return
	}

	if matchPattern.Valid {
		event.MatchPattern = matchPattern.String
	}
	if status.Valid {
		event.Status = status.String
	} else {
		event.Status = "BLOCKED"
	}

	c.JSON(http.StatusOK, event)
}

// Get event statistics
func GetEventStats(c *gin.Context) {
	stats, err := GetEventStatsFromDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// Get rate limit status
func GetRateLimitStatus(c *gin.Context) {
	// Return the REAL config from the active firewall instance
	config := fw.GetConfig()
	
	c.JSON(http.StatusOK, gin.H{
		"active_limits": 0, // You could expand RateLimitEntry to count these if needed
		"blocked_ips":   []string{}, // Placeholder, or fetch from fw.blacklist
		"config": gin.H{
			"window_seconds": config.RateLimitWindow,
			"max_requests":   config.RateLimitMax,
		},
	})
}

// Update rate limit config (UPDATED: Now updates Live Firewall)
func UpdateRateLimitConfig(c *gin.Context) {
	var config struct {
		WindowSeconds int `json:"window_seconds"`
		MaxRequests   int `json:"max_requests"`
	}

	if err := c.BindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 1. Save to Database
	_, err := db.Exec("INSERT OR REPLACE INTO firewall_config (key, value) VALUES ('rate_limit_window', ?)", strconv.Itoa(config.WindowSeconds))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_, err = db.Exec("INSERT OR REPLACE INTO firewall_config (key, value) VALUES ('rate_limit_max', ?)", strconv.Itoa(config.MaxRequests))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 2. UPDATE LIVE FIREWALL INSTANCE
	// Retrieve current config
	currentConfig := fw.GetConfig()
	// Update relevant fields
	currentConfig.RateLimitWindow = config.WindowSeconds
	currentConfig.RateLimitMax = config.MaxRequests
	// Save back to firewall
	fw.UpdateConfig(currentConfig)

	c.JSON(http.StatusOK, gin.H{
		"message": "Rate limit updated successfully", 
		"new_config": config,
	})
}

// Get blocked IPs
func GetBlockedIPs(c *gin.Context) {
	ips, err := GetBlacklistFromDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"blocked_ips": ips})
}

// Get firewall config
func GetFirewallConfig(c *gin.Context) {
	c.JSON(http.StatusOK, fw.GetConfig())
}

// Update firewall config
func UpdateFirewallConfig(c *gin.Context) {
	var config FirewallConfig
	if err := c.BindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update the global firewall instance immediately
	fw.UpdateConfig(config)

	c.JSON(http.StatusOK, gin.H{"message": "Configuration updated", "config": config})
}

// Get live metrics
func GetLiveMetrics(c *gin.Context) {
	stats, _ := GetEventStatsFromDB()
	recentLogs, _ := GetRequestLogsFromDB(10, 0)

	c.JSON(http.StatusOK, gin.H{
		"total_events":     stats.TotalEvents,
		"events_last_hour": stats.EventsLastHour,
		"events_last_24h":  stats.EventsLast24h,
		"critical_events":  stats.CriticalEvents,
		"recent_requests":  recentLogs,
	})
}

// Get threat analysis
func GetThreatAnalysis(c *gin.Context) {
	stats, err := GetEventStatsFromDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"events_by_type": stats.EventsByType,
		"top_attackers":  stats.TopAttackers,
		"severity_breakdown": gin.H{
			"critical": stats.CriticalEvents,
			"high":     stats.HighEvents,
			"medium":   stats.MediumEvents,
			"low":      stats.LowEvents,
		},
	})
}

// IP Management endpoints
func AddToWhitelist(c *gin.Context) {
	var req struct {
		IP string `json:"ip" binding:"required"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := AddIPToWhitelist(req.IP); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	fw.AddToWhitelist(req.IP)
	c.JSON(http.StatusOK, gin.H{"message": "IP added to whitelist"})
}

func AddToBlacklist(c *gin.Context) {
	var req struct {
		IP     string `json:"ip" binding:"required"`
		Reason string `json:"reason"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := AddIPToBlacklist(req.IP, req.Reason); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	fw.AddToBlacklist(req.IP)
	c.JSON(http.StatusOK, gin.H{"message": "IP added to blacklist"})
}

func RemoveFromWhitelist(c *gin.Context) {
	ip := c.Param("ip")
	if err := RemoveIPFromWhitelist(ip); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	fw.RemoveFromWhitelist(ip)
	c.JSON(http.StatusOK, gin.H{"message": "IP removed from whitelist"})
}

func RemoveFromBlacklist(c *gin.Context) {
	ip := c.Param("ip")
	if err := RemoveIPFromBlacklist(ip); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	fw.RemoveFromBlacklist(ip)
	c.JSON(http.StatusOK, gin.H{"message": "IP removed from blacklist"})
}

func GetWhitelist(c *gin.Context) {
	ips, err := GetWhitelistFromDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"whitelist": ips})
}

func GetBlacklist(c *gin.Context) {
	ips, err := GetBlacklistFromDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"blacklist": ips})
}

// OWASP status
func GetOWASPStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"checks": []gin.H{
			{"id": 1, "name": "Broken Access Control", "enabled": true, "status": "active"},
			{"id": 2, "name": "Cryptographic Failures", "enabled": true, "status": "active"},
			{"id": 3, "name": "Injection", "enabled": true, "status": "active"},
			{"id": 4, "name": "Insecure Design", "enabled": true, "status": "active"},
			{"id": 5, "name": "Security Misconfiguration", "enabled": true, "status": "active"},
			{"id": 6, "name": "Vulnerable Components", "enabled": true, "status": "active"},
			{"id": 7, "name": "Authentication Failures", "enabled": true, "status": "active"},
			{"id": 8, "name": "Software/Data Integrity", "enabled": true, "status": "active"},
			{"id": 9, "name": "Logging/Monitoring Failures", "enabled": false, "status": "logging_active"},
			{"id": 10, "name": "SSRF", "enabled": true, "status": "active"},
		},
	})
}

// OWASP violations
func GetOWASPViolations(c *gin.Context) {
	events, _ := GetSecurityEventsFromDB(100, 0, "")

	violations := make(map[string]int)
	violations["SQL_INJECTION"] = 0
	violations["XSS_ATTEMPT"] = 0
	violations["PATH_TRAVERSAL"] = 0
	violations["RATE_LIMIT_EXCEEDED"] = 0
	violations["UNAUTHORIZED_ACCESS"] = 0

	for _, event := range events {
		if _, exists := violations[event.Type]; exists {
			violations[event.Type]++
		}
	}

	c.JSON(http.StatusOK, gin.H{"violations": violations})
}
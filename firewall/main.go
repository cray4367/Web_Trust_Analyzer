package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

var fw *Firewall

func main() {
	godotenv.Load()
	InitDB()
	defer CloseDB()
	InitRedis()
	defer CloseRedis()

	// 1. SETUP ROUTER
	router := gin.Default()

	// 2. ALLOW DASHBOARD (Running on 5173)
	// We explicitly allow localhost:5173 because that is where the Dashboard WILL run
	router.Use(CORSMiddleware())

	fw = NewFirewall(FirewallConfig{
		RateLimitWindow:     60,
		RateLimitMax:        100,
		EnableCSRF:          true,
		EnableXSS:           true,
		EnableSQLi:          true,
		EnablePathTraversal: true,
		BlockSuspicious:     true,
		EnableBotDetection:  true, // toggle off via POST /api/config to allow curl/wget health checks
	})

	whitelist, _ := GetWhitelistFromDB()
	for _, ip := range whitelist {
		fw.AddToWhitelist(ip)
	}

	// Trust scoring middleware (first to track all requests)
	router.Use(fw.TrustScorer())
	router.Use(fw.SecurityHeaders())
	router.Use(fw.TrustBasedAccessControl()) // Apply trust-based policies
	router.Use(fw.RateLimiter())
	router.Use(fw.BotDetector())
	router.Use(fw.InputValidator())
	router.Use(fw.ThreatDetector())
	router.Use(fw.RequestLogger())

	api := router.Group("/api")
	api.Use(APIAuthMiddleware())
	{
		api.GET("/events", GetSecurityEvents)
		api.GET("/events/:id", GetSecurityEvent)
		api.GET("/events/stats", GetEventStats)
		api.GET("/ratelimit/status", GetRateLimitStatus)
		api.POST("/ratelimit/config", UpdateRateLimitConfig)
		api.GET("/ratelimit/blocked", GetBlockedIPs)
		api.GET("/config", GetFirewallConfig)
		api.POST("/config", UpdateFirewallConfig)
		api.GET("/monitor/live", GetLiveMetrics)
		api.GET("/monitor/threats", GetThreatAnalysis)
		api.POST("/attack/simulate", SimulateAttack) // New Attack Route
		api.POST("/ip/whitelist", AddToWhitelist)
		api.POST("/ip/blacklist", AddToBlacklist)
		api.DELETE("/ip/whitelist/:ip", RemoveFromWhitelist)
		api.DELETE("/ip/blacklist/:ip", RemoveFromBlacklist)
		api.GET("/ip/whitelist", GetWhitelist)
		api.GET("/ip/blacklist", GetBlacklist)
		api.GET("/owasp/status", GetOWASPStatus)
		api.GET("/owasp/violations", GetOWASPViolations)

		// Trust API endpoints
		api.GET("/trust/profile/:ip", GetTrustProfileHandler)
		api.GET("/trust/profiles", GetAllTrustProfilesHandler)
		api.GET("/trust/top-trusted", GetTopTrustedHandler)
		api.GET("/trust/suspicious", GetSuspiciousIPsHandler)
		api.GET("/trust/distribution", GetTrustDistributionHandler)
		api.GET("/trust/history/:ip", GetTrustHistoryHandler)
		api.GET("/trust/stats", GetTrustStatsHandler)
	}

	// 3. POINT PROXY TO TARGET
	targetURL := os.Getenv("TARGET_URL")
	if targetURL == "" {
		targetURL = "http://localhost:3000"
	}
	// Handle all other traffic (Proxy to target)
	router.NoRoute(fw.ProxyMiddleware(targetURL))

	// 4. SET FIREWALL PORT TO 8080
	// This ensures it doesn't clash with Vite (5173) or React (3001)
	port := "8080"

	fmt.Printf("🛡️  Web Trust Analyzer Firewall starting on port %s\n", port)

	if err := router.Run(":" + port); err != nil {
		log.Fatal("Failed to start firewall:", err)
	}
}

// allowedOrigins is the strict allowlist for CORS.
// Only these two origins are permitted to make credentialed requests.
var allowedOrigins = map[string]bool{
	"http://localhost:80":   true,
	"http://localhost:5173": true,
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Only echo the origin back if it is explicitly in the allowlist.
		// Unknown origins get no CORS headers, so the browser blocks them.
		if allowedOrigins[origin] {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-API-Key")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		}

		if c.Request.Method == "OPTIONS" {
			if allowedOrigins[origin] {
				c.AbortWithStatus(204)
			} else {
				c.AbortWithStatus(403)
			}
			return
		}
		c.Next()
	}
}

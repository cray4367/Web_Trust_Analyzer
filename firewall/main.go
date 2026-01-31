package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	godotenv.Load()

	// Initialize database
	InitDB()
	defer CloseDB()

	// Set Gin to release mode in production
	if os.Getenv("ENV") == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// CORS middleware - configure for your frontend
	router.Use(CORSMiddleware())

	// Initialize firewall middleware
	fw := NewFirewall(FirewallConfig{
		RateLimitWindow:   60,  // 60 seconds
		RateLimitMax:      100, // 100 requests per window
		EnableCSRF:        true,
		EnableXSS:         true,
		EnableSQLi:        true,
		EnablePathTraversal: true,
		BlockSuspicious:   true,
	})

	// Apply firewall middleware globally
	router.Use(fw.SecurityHeaders())
	router.Use(fw.RateLimiter())
	router.Use(fw.InputValidator())
	router.Use(fw.ThreatDetector())
	router.Use(fw.RequestLogger())

	// Dashboard API routes
	api := router.Group("/api")
	{
		// Security events
		api.GET("/events", GetSecurityEvents)
		api.GET("/events/:id", GetSecurityEvent)
		api.GET("/events/stats", GetEventStats)
		
		// Rate limiting
		api.GET("/ratelimit/status", GetRateLimitStatus)
		api.POST("/ratelimit/config", UpdateRateLimitConfig)
		api.GET("/ratelimit/blocked", GetBlockedIPs)
		
		// Firewall configuration
		api.GET("/config", GetFirewallConfig)
		api.POST("/config", UpdateFirewallConfig)
		
		// Real-time monitoring
		api.GET("/monitor/live", GetLiveMetrics)
		api.GET("/monitor/threats", GetThreatAnalysis)
		
		// IP management
		api.POST("/ip/whitelist", AddToWhitelist)
		api.POST("/ip/blacklist", AddToBlacklist)
		api.DELETE("/ip/whitelist/:ip", RemoveFromWhitelist)
		api.DELETE("/ip/blacklist/:ip", RemoveFromBlacklist)
		api.GET("/ip/whitelist", GetWhitelist)
		api.GET("/ip/blacklist", GetBlacklist)
		
		// OWASP checks
		api.GET("/owasp/status", GetOWASPStatus)
		api.GET("/owasp/violations", GetOWASPViolations)
	}

	// Proxy to main app on port 3400
	router.Any("/app/*path", fw.ProxyMiddleware("http://localhost:3400"))

	port := os.Getenv("FIREWALL_PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("🛡️  Web Trust Analyzer Firewall starting on port %s\n", port)
	fmt.Println("📊 Dashboard API available at /api")
	fmt.Println("🔒 Protected app proxied at /app")
	
	if err := router.Run(":" + port); err != nil {
		log.Fatal("Failed to start firewall:", err)
	}
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
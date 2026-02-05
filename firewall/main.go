package main

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

var fw *Firewall

func main() {
	godotenv.Load()
	InitDB()
	defer CloseDB()

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
	})

	whitelist, _ := GetWhitelistFromDB()
	for _, ip := range whitelist {
		fw.AddToWhitelist(ip)
	}

	router.Use(fw.SecurityHeaders())
	router.Use(fw.RateLimiter())
	router.Use(fw.BotDetector()) // New Bot Detector
	router.Use(fw.InputValidator())
	router.Use(fw.ThreatDetector())
	router.Use(fw.RequestLogger())

	api := router.Group("/api")
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
	}

	// 3. POINT PROXY TO TARGET (Port 3001)
	// This connects the firewall to your "react-resume-template"
	router.Any("/app/*path", fw.ProxyMiddleware("http://localhost:3000"))

	// 4. SET FIREWALL PORT TO 8080
	// This ensures it doesn't clash with Vite (5173) or React (3001)
	port := "8080"

	fmt.Printf("🛡️  Web Trust Analyzer Firewall starting on port %s\n", port)

	if err := router.Run(":" + port); err != nil {
		log.Fatal("Failed to start firewall:", err)
	}
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Allow any origin for development convenience (or specifically 5173, 3000, 3001)
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		}

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

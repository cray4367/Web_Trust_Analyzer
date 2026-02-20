package main

import (
	"net/http"
	"strconv"
	"web-trust-analyzer/trust"

	"github.com/gin-gonic/gin"
)

// ============================================
// TRUST API ENDPOINTS
// ============================================

// GetTrustProfileHandler retrieves trust profile for a specific IP
func GetTrustProfileHandler(c *gin.Context) {
	ip := c.Param("ip")

	profile, err := GetTrustProfile(ip)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Profile not found"})
		return
	}

	trustScore := trust.CalculateTrustScore(profile)

	c.JSON(http.StatusOK, gin.H{
		"profile": profile,
		"score":   trustScore,
	})
}

// GetAllTrustProfilesHandler retrieves all trust profiles with pagination
func GetAllTrustProfilesHandler(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "50")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	profiles, err := GetAllTrustProfiles(limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"profiles": profiles,
		"limit":    limit,
		"offset":   offset,
	})
}

// GetTopTrustedHandler retrieves most trusted IPs
func GetTopTrustedHandler(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "10")
	limit, _ := strconv.Atoi(limitStr)

	profiles, err := GetTopTrustedIPs(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"profiles": profiles})
}

// GetSuspiciousIPsHandler retrieves suspicious IPs
func GetSuspiciousIPsHandler(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "10")
	limit, _ := strconv.Atoi(limitStr)

	profiles, err := GetSuspiciousIPs(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"profiles": profiles})
}

// GetTrustDistributionHandler returns trust level distribution
func GetTrustDistributionHandler(c *gin.Context) {
	distribution, err := GetTrustDistribution()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"distribution": distribution})
}

// GetTrustHistoryHandler retrieves trust history for an IP
func GetTrustHistoryHandler(c *gin.Context) {
	ip := c.Param("ip")
	limitStr := c.DefaultQuery("limit", "50")
	limit, _ := strconv.Atoi(limitStr)

	history, err := GetTrustHistory(ip, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"history": history})
}

// GetTrustStatsHandler returns overall trust statistics
func GetTrustStatsHandler(c *gin.Context) {
	stats, err := GetTrustStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, stats)
}

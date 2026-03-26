package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
	"web-trust-analyzer/trust"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// redisTrustKey returns the Redis key for a given IP's trust cache.
const redisTrustTTL = 60 * time.Second

func redisTrustKey(ip string) string {
	return fmt.Sprintf("waf:trust:%s", ip)
}

// cacheTrustScore writes a trust score to Redis with a 60s TTL.
// No-op when Redis is unavailable.
func cacheTrustScore(ip string, score float64) {
	if !redisAvailable() {
		return
	}
	data, _ := json.Marshal(score)
	rdb.Set(context.Background(), redisTrustKey(ip), data, redisTrustTTL)
}

// getCachedTrustScore retrieves a trust score from Redis.
// Returns (score, true) on hit, (0, false) on miss or any error.
func getCachedTrustScore(ip string) (float64, bool) {
	if !redisAvailable() {
		return 0, false
	}
	val, err := rdb.Get(context.Background(), redisTrustKey(ip)).Bytes()
	if err == redis.Nil || err != nil {
		return 0, false
	}
	var score float64
	if json.Unmarshal(val, &score) != nil {
		return 0, false
	}
	return score, true
}

// TrustScorer middleware calculates and tracks trust scores for all requests
func (fw *Firewall) TrustScorer() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip for OPTIONS requests
		if c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		ip := c.ClientIP()

		// Get or create trust profile
		profile, err := GetOrCreateTrustProfile(ip)
		if err != nil {
			log.Printf("Error getting trust profile for %s: %v", ip, err)
			c.Next()
			return
		}

		// Update last seen and request count
		profile.LastSeen = time.Now()
		profile.RequestCount++

		// Calculate trust score — use Redis cache when available to avoid
		// redundant recalculation on every request for known IPs.
		var trustScore trust.TrustScore
		if cachedScore, ok := getCachedTrustScore(ip); ok {
			// Reconstruct a lightweight TrustScore from the cached overall value
			trustScore = trust.TrustScore{
				OverallScore: cachedScore,
				TrustLevel:   profile.Reputation,
				Confidence:   1.0,
			}
		} else {
			trustScore = trust.CalculateTrustScore(profile)
			// Populate cache for subsequent requests
			cacheTrustScore(ip, trustScore.OverallScore)
		}

		// Store in context for other middleware
		c.Set("trust_profile", profile)
		c.Set("trust_score", trustScore)
		c.Set("trust_level", trustScore.TrustLevel)

		// Update profile asynchronously
		go func() {
			oldScore := profile.TrustScore
			profile.TrustScore = trustScore.OverallScore
			profile.Reputation = trustScore.TrustLevel
			profile.LastUpdated = time.Now()

			if err := UpdateTrustProfile(profile); err != nil {
				log.Printf("Error updating trust profile: %v", err)
			}

			// Refresh Redis cache after SQLite write
			cacheTrustScore(ip, profile.TrustScore)

			// Log significant trust changes
			if abs(oldScore-trustScore.OverallScore) > 10 {
				LogTrustEvent(trust.TrustEvent{
					IP:        ip,
					EventType: "SCORE_CHANGE",
					OldScore:  oldScore,
					NewScore:  trustScore.OverallScore,
					Reason:    "Normal request processing",
					Timestamp: time.Now(),
				})
			}
		}()

		c.Next()
	}
}

// TrustBasedAccessControl applies different security policies based on trust level.
// New IPs (score 40-59, RequestCount < 20) enter a WARMING_UP phase with tighter
// rate limits until they establish a clean request history.
func (fw *Firewall) TrustBasedAccessControl() gin.HandlerFunc {
	return func(c *gin.Context) {
		trustScoreVal, exists := c.Get("trust_score")
		if !exists {
			c.Next()
			return
		}

		trustScore := trustScoreVal.(trust.TrustScore)
		score := trustScore.OverallScore

		// Pull request count from the profile stored in context.
		var requestCount int
		if profileVal, ok := c.Get("trust_profile"); ok {
			if profile, ok := profileVal.(*trust.TrustProfile); ok {
				requestCount = profile.RequestCount
			}
		}

		// Warm-up threshold: require 20 clean requests before granting full NEUTRAL limits.
		const warmupThreshold = 20

		switch {
		case score >= 80:
			// Highly trusted — fast track with doubled rate limits
			c.Set("rate_limit_multiplier", 2.0)
			c.Set("skip_extra_checks", true)
			c.Header("X-Trust-Level", "HIGHLY_TRUSTED")

		case score >= 60:
			// Trusted — normal flow
			c.Set("rate_limit_multiplier", 1.0)
			c.Header("X-Trust-Level", "TRUSTED")

		case score >= 40 && requestCount >= warmupThreshold:
			// Neutral with established history — standard security
			c.Set("rate_limit_multiplier", 0.8)
			c.Header("X-Trust-Level", "NEUTRAL")

		case score >= 40 && requestCount < warmupThreshold:
			// Neutral score but brand-new IP — half rate limits until warmed up
			c.Set("rate_limit_multiplier", 0.5)
			c.Header("X-Trust-Level", "WARMING_UP")

		case score >= 20:
			// Suspicious — extra validation required
			c.Set("rate_limit_multiplier", 0.5)
			c.Set("require_extra_validation", true)
			c.Header("X-Trust-Level", "SUSPICIOUS")

		default:
			// Malicious — block outright
			fw.logThreat(c, "LOW_TRUST_SCORE",
				fmt.Sprintf("Trust score: %.2f - %s", score, trustScore.TrustLevel),
				"", "", "BLOCKED")
			fw.respondBlocked(c, "Access denied due to low trust score")
			return
		}

		c.Next()
	}
}

// UpdateTrustAfterThreatDetection updates trust profile when a threat is detected
func UpdateTrustAfterThreatDetection(c *gin.Context, threatType string) {
	profileVal, exists := c.Get("trust_profile")
	if !exists {
		return
	}

	profile := profileVal.(*trust.TrustProfile)
	oldScore := profile.TrustScore

	// Increment threat count
	profile.ThreatCount++

	// Recalculate trust score
	newTrustScore := trust.CalculateTrustScore(profile)
	profile.TrustScore = newTrustScore.OverallScore
	profile.Reputation = newTrustScore.TrustLevel
	profile.LastUpdated = time.Now()

	// Update in database
	go func() {
		if err := UpdateTrustProfile(profile); err != nil {
			log.Printf("Error updating trust profile after threat: %v", err)
		}

		// Log the trust event
		LogTrustEvent(trust.TrustEvent{
			IP:        profile.IP,
			EventType: "THREAT_DETECTED",
			OldScore:  oldScore,
			NewScore:  profile.TrustScore,
			Reason:    threatType,
			Timestamp: time.Now(),
		})
	}()
}

// UpdateTrustAfterCleanRequest updates trust profile after a clean request
func UpdateTrustAfterCleanRequest(c *gin.Context) {
	profileVal, exists := c.Get("trust_profile")
	if !exists {
		return
	}

	profile := profileVal.(*trust.TrustProfile)

	// Increment clean count
	profile.CleanCount++

	// Recalculate trust score
	newTrustScore := trust.CalculateTrustScore(profile)
	oldScore := profile.TrustScore
	profile.TrustScore = newTrustScore.OverallScore
	profile.Reputation = newTrustScore.TrustLevel
	profile.LastUpdated = time.Now()

	// Update in database asynchronously
	go func() {
		if err := UpdateTrustProfile(profile); err != nil {
			log.Printf("Error updating trust profile after clean request: %v", err)
		}

		// Log significant improvements
		if newTrustScore.OverallScore-oldScore > 5 {
			LogTrustEvent(trust.TrustEvent{
				IP:        profile.IP,
				EventType: "SCORE_INCREASE",
				OldScore:  oldScore,
				NewScore:  newTrustScore.OverallScore,
				Reason:    "Clean request",
				Timestamp: time.Now(),
			})
		}
	}()
}

// Helper function to calculate absolute value
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

package main

import (
	"fmt"
	"log"
	"time"
	"web-trust-analyzer/trust"

	"github.com/gin-gonic/gin"
)

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

		// Calculate trust score using the trust engine
		trustScore := trust.CalculateTrustScore(profile)

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

// TrustBasedAccessControl applies different security policies based on trust level
func (fw *Firewall) TrustBasedAccessControl() gin.HandlerFunc {
	return func(c *gin.Context) {
		trustScoreVal, exists := c.Get("trust_score")
		if !exists {
			c.Next()
			return
		}

		trustScore := trustScoreVal.(trust.TrustScore)
		score := trustScore.OverallScore

		switch {
		case score >= 80:
			// Highly trusted - fast track
			c.Set("rate_limit_multiplier", 2.0)
			c.Set("skip_extra_checks", true)
			c.Header("X-Trust-Level", "HIGHLY_TRUSTED")

		case score >= 60:
			// Trusted - normal flow
			c.Set("rate_limit_multiplier", 1.0)
			c.Header("X-Trust-Level", "TRUSTED")

		case score >= 40:
			// Neutral - standard security
			c.Set("rate_limit_multiplier", 0.8)
			c.Header("X-Trust-Level", "NEUTRAL")

		case score >= 20:
			// Suspicious - extra validation
			c.Set("rate_limit_multiplier", 0.5)
			c.Set("require_extra_validation", true)
			c.Header("X-Trust-Level", "SUSPICIOUS")

		default:
			// Malicious - block or heavy challenge
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

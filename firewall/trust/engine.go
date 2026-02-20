package trust

import (
	"math"
	"time"
)

// Scoring weights for different trust factors
var (
	WeightAccountAge       = 0.25
	WeightCleanRatio       = 0.30
	WeightRequestFrequency = 0.15
	WeightThreatHistory    = 0.20
	WeightConsistency      = 0.10
)

// CalculateTrustScore computes the overall trust score for a profile
func CalculateTrustScore(profile *TrustProfile) TrustScore {
	factors := extractTrustFactors(profile)

	// Weighted scoring
	score := 0.0
	score += factors.AccountAge * WeightAccountAge
	score += factors.CleanRequestRatio * WeightCleanRatio
	score += factors.RequestFrequency * WeightRequestFrequency
	score += (100.0 - factors.ThreatHistory) * WeightThreatHistory
	score += factors.ConsistencyScore * WeightConsistency

	// Ensure score is within bounds
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	trustLevel := getTrustLevel(score)
	confidence := calculateConfidence(profile)
	recommendations := generateRecommendations(score, factors)

	return TrustScore{
		OverallScore:    score,
		ThreatScore:     factors.ThreatHistory,
		TrustLevel:      trustLevel,
		Confidence:      confidence,
		Factors:         factorsToMap(factors),
		Recommendations: recommendations,
	}
}

// extractTrustFactors calculates individual trust factors from a profile
func extractTrustFactors(profile *TrustProfile) TrustFactors {
	accountAgeDays := time.Since(profile.FirstSeen).Hours() / 24

	cleanRatio := 0.0
	if profile.RequestCount > 0 {
		cleanRatio = float64(profile.CleanCount) / float64(profile.RequestCount) * 100.0
	}

	return TrustFactors{
		AccountAge:        normalizeAccountAge(accountAgeDays),
		CleanRequestRatio: cleanRatio,
		RequestFrequency:  normalizeFrequency(profile),
		ThreatHistory:     normalizeThreatCount(profile.ThreatCount, profile.RequestCount),
		ConsistencyScore:  50.0, // Placeholder - can be enhanced with behavioral analysis
	}
}

// normalizeAccountAge converts account age in days to a 0-100 score
// Newer accounts have lower scores, older accounts have higher scores
func normalizeAccountAge(days float64) float64 {
	// Use logarithmic scale: 1 day = ~30, 7 days = ~60, 30 days = ~80, 90+ days = ~95+
	if days <= 0 {
		return 0
	}

	score := 30.0 * math.Log10(days+1)
	if score > 100 {
		score = 100
	}
	return score
}

// normalizeFrequency converts request patterns to a 0-100 score
// Moderate, consistent frequency is best
func normalizeFrequency(profile *TrustProfile) float64 {
	if profile.RequestCount == 0 {
		return 50.0 // Neutral for new users
	}

	accountAgeDays := time.Since(profile.FirstSeen).Hours() / 24
	if accountAgeDays < 0.01 {
		accountAgeDays = 0.01 // Prevent division by zero
	}

	requestsPerDay := float64(profile.RequestCount) / accountAgeDays

	// Optimal range: 10-100 requests per day = 100 score
	// Too few or too many = lower score
	switch {
	case requestsPerDay < 1:
		return 40.0 // Very low activity
	case requestsPerDay < 10:
		return 60.0 + (requestsPerDay * 4) // 60-100
	case requestsPerDay <= 100:
		return 100.0 // Optimal range
	case requestsPerDay <= 500:
		return 100.0 - ((requestsPerDay - 100) / 10) // 100-60
	default:
		return 30.0 // Suspiciously high activity
	}
}

// normalizeThreatCount converts threat count to a 0-100 score (higher = worse)
func normalizeThreatCount(threatCount, requestCount int) float64 {
	if requestCount == 0 {
		return 0
	}

	threatRatio := float64(threatCount) / float64(requestCount)

	// Convert to 0-100 scale (higher threat ratio = higher score = worse)
	score := threatRatio * 100.0

	// Apply exponential penalty for high threat ratios
	if threatRatio > 0.1 {
		score = 100.0
	} else if threatRatio > 0.01 {
		score = 50.0 + (threatRatio * 500.0)
	}

	if score > 100 {
		score = 100
	}

	return score
}

// getTrustLevel converts numeric score to categorical level
func getTrustLevel(score float64) string {
	switch {
	case score >= 80:
		return "HIGHLY_TRUSTED"
	case score >= 60:
		return "TRUSTED"
	case score >= 40:
		return "NEUTRAL"
	case score >= 20:
		return "SUSPICIOUS"
	default:
		return "MALICIOUS"
	}
}

// calculateConfidence determines how confident we are in the trust score
// More data = higher confidence
func calculateConfidence(profile *TrustProfile) float64 {
	// Confidence based on amount of data
	requestCount := float64(profile.RequestCount)
	accountAgeDays := time.Since(profile.FirstSeen).Hours() / 24

	// Combine request count and account age
	dataScore := math.Min(requestCount/100.0, 1.0) * 0.6
	ageScore := math.Min(accountAgeDays/30.0, 1.0) * 0.4

	confidence := dataScore + ageScore

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// factorsToMap converts TrustFactors struct to map for JSON serialization
func factorsToMap(factors TrustFactors) map[string]float64 {
	return map[string]float64{
		"account_age":         factors.AccountAge,
		"clean_request_ratio": factors.CleanRequestRatio,
		"request_frequency":   factors.RequestFrequency,
		"threat_history":      factors.ThreatHistory,
		"consistency_score":   factors.ConsistencyScore,
	}
}

// generateRecommendations provides actionable insights based on trust score
func generateRecommendations(score float64, factors TrustFactors) []string {
	recommendations := []string{}

	if score >= 80 {
		recommendations = append(recommendations, "User is highly trusted - consider fast-track processing")
	} else if score >= 60 {
		recommendations = append(recommendations, "User is trusted - normal security measures apply")
	} else if score >= 40 {
		recommendations = append(recommendations, "User is neutral - monitor for suspicious activity")
	} else if score >= 20 {
		recommendations = append(recommendations, "User is suspicious - apply extra validation")
	} else {
		recommendations = append(recommendations, "User is malicious - consider blocking")
	}

	// Factor-specific recommendations
	if factors.AccountAge < 30 {
		recommendations = append(recommendations, "New account - limited trust history")
	}

	if factors.CleanRequestRatio < 80 {
		recommendations = append(recommendations, "Low clean request ratio - review threat history")
	}

	if factors.ThreatHistory > 50 {
		recommendations = append(recommendations, "High threat activity detected - consider blacklisting")
	}

	return recommendations
}

// UpdateTrustAfterThreat adjusts trust score after detecting a threat
func UpdateTrustAfterThreat(profile *TrustProfile, threatType string) {
	profile.ThreatCount++

	// Recalculate trust score
	newScore := CalculateTrustScore(profile)
	profile.TrustScore = newScore.OverallScore
	profile.Reputation = newScore.TrustLevel
	profile.LastUpdated = time.Now()
}

// UpdateTrustAfterCleanRequest adjusts trust score after a clean request
func UpdateTrustAfterCleanRequest(profile *TrustProfile) {
	profile.CleanCount++

	// Recalculate trust score
	newScore := CalculateTrustScore(profile)
	profile.TrustScore = newScore.OverallScore
	profile.Reputation = newScore.TrustLevel
	profile.LastUpdated = time.Now()
}

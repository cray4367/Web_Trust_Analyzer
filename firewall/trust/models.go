package trust

import (
	"time"
)

// TrustProfile represents a user's trust profile
type TrustProfile struct {
	ID           int       `json:"id"`
	IP           string    `json:"ip"`
	TrustScore   float64   `json:"trust_score"`    // 0-100
	Reputation   string    `json:"reputation"`     // NEW, TRUSTED, NEUTRAL, SUSPICIOUS, MALICIOUS
	RequestCount int       `json:"request_count"`
	ThreatCount  int       `json:"threat_count"`
	CleanCount   int       `json:"clean_count"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	LastUpdated  time.Time `json:"last_updated"`
}

// TrustScore represents the calculated trust score with details
type TrustScore struct {
	OverallScore    float64            `json:"overall_score"`    // 0-100
	ThreatScore     float64            `json:"threat_score"`     // 0-100 (inverse)
	TrustLevel      string             `json:"trust_level"`      // HIGHLY_TRUSTED, TRUSTED, etc.
	Confidence      float64            `json:"confidence"`       // 0-1
	Factors         map[string]float64 `json:"factors"`          // Individual factor scores
	Recommendations []string           `json:"recommendations"`
}

// TrustFactors contains individual factors used in trust calculation
type TrustFactors struct {
	AccountAge        float64 `json:"account_age"`         // Days since first seen (normalized 0-100)
	CleanRequestRatio float64 `json:"clean_request_ratio"` // % of clean requests (0-100)
	RequestFrequency  float64 `json:"request_frequency"`   // Requests per day (normalized 0-100)
	ThreatHistory     float64 `json:"threat_history"`      // Historical threat count (normalized 0-100, inverse)
	ConsistencyScore  float64 `json:"consistency_score"`   // Behavioral consistency (0-100)
}

// TrustEvent represents a change in trust score
type TrustEvent struct {
	ID        int       `json:"id"`
	IP        string    `json:"ip"`
	EventType string    `json:"event_type"` // SCORE_INCREASE, SCORE_DECREASE, THREAT_DETECTED, CLEAN_REQUEST
	OldScore  float64   `json:"old_score"`
	NewScore  float64   `json:"new_score"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
}

// TrustStats represents overall trust statistics
type TrustStats struct {
	TotalProfiles   int     `json:"total_profiles"`
	HighlyTrusted   int     `json:"highly_trusted"`
	Trusted         int     `json:"trusted"`
	Neutral         int     `json:"neutral"`
	Suspicious      int     `json:"suspicious"`
	Malicious       int     `json:"malicious"`
	AverageScore    float64 `json:"average_score"`
}

package main

import (
	"database/sql"
	"time"
	"web-trust-analyzer/trust"
)

// Trust-related types are now imported from the trust package

// GetOrCreateTrustProfile retrieves or creates a trust profile for an IP
func GetOrCreateTrustProfile(ip string) (*trust.TrustProfile, error) {
	var profile trust.TrustProfile

	query := `SELECT id, ip, trust_score, reputation, request_count, threat_count, clean_count, 
	          first_seen, last_seen, last_updated FROM user_trust_profiles WHERE ip = ?`

	err := db.QueryRow(query, ip).Scan(
		&profile.ID, &profile.IP, &profile.TrustScore, &profile.Reputation,
		&profile.RequestCount, &profile.ThreatCount, &profile.CleanCount,
		&profile.FirstSeen, &profile.LastSeen, &profile.LastUpdated,
	)

	if err == sql.ErrNoRows {
		// Create new profile
		now := time.Now()
		profile = trust.TrustProfile{
			IP:           ip,
			TrustScore:   50.0,
			Reputation:   "NEW",
			RequestCount: 0,
			ThreatCount:  0,
			CleanCount:   0,
			FirstSeen:    now,
			LastSeen:     now,
			LastUpdated:  now,
		}

		insertQuery := `INSERT INTO user_trust_profiles 
		                (ip, trust_score, reputation, request_count, threat_count, clean_count, 
		                 first_seen, last_seen, last_updated)
		                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

		result, err := db.Exec(insertQuery, profile.IP, profile.TrustScore, profile.Reputation,
			profile.RequestCount, profile.ThreatCount, profile.CleanCount,
			profile.FirstSeen, profile.LastSeen, profile.LastUpdated)

		if err != nil {
			return nil, err
		}

		id, _ := result.LastInsertId()
		profile.ID = int(id)

		return &profile, nil
	}

	if err != nil {
		return nil, err
	}

	return &profile, nil
}

// UpdateTrustProfile updates an existing trust profile
func UpdateTrustProfile(profile *trust.TrustProfile) error {
	query := `UPDATE user_trust_profiles 
	          SET trust_score = ?, reputation = ?, request_count = ?, 
	              threat_count = ?, clean_count = ?, last_seen = ?, last_updated = ?
	          WHERE ip = ?`

	_, err := db.Exec(query, profile.TrustScore, profile.Reputation, profile.RequestCount,
		profile.ThreatCount, profile.CleanCount, profile.LastSeen, profile.LastUpdated, profile.IP)

	return err
}

// GetTrustProfile retrieves a trust profile by IP
func GetTrustProfile(ip string) (*trust.TrustProfile, error) {
	var profile trust.TrustProfile

	query := `SELECT id, ip, trust_score, reputation, request_count, threat_count, clean_count, 
	          first_seen, last_seen, last_updated FROM user_trust_profiles WHERE ip = ?`

	err := db.QueryRow(query, ip).Scan(
		&profile.ID, &profile.IP, &profile.TrustScore, &profile.Reputation,
		&profile.RequestCount, &profile.ThreatCount, &profile.CleanCount,
		&profile.FirstSeen, &profile.LastSeen, &profile.LastUpdated,
	)

	if err != nil {
		return nil, err
	}

	return &profile, nil
}

// GetAllTrustProfiles retrieves all trust profiles with pagination
func GetAllTrustProfiles(limit, offset int) ([]*trust.TrustProfile, error) {
	var profiles []*trust.TrustProfile

	query := `SELECT id, ip, trust_score, reputation, request_count, threat_count, clean_count, 
	          first_seen, last_seen, last_updated 
	          FROM user_trust_profiles 
	          ORDER BY trust_score DESC 
	          LIMIT ? OFFSET ?`

	rows, err := db.Query(query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var profile trust.TrustProfile
		err := rows.Scan(
			&profile.ID, &profile.IP, &profile.TrustScore, &profile.Reputation,
			&profile.RequestCount, &profile.ThreatCount, &profile.CleanCount,
			&profile.FirstSeen, &profile.LastSeen, &profile.LastUpdated,
		)
		if err == nil {
			profiles = append(profiles, &profile)
		}
	}

	return profiles, nil
}

// GetTopTrustedIPs retrieves the most trusted IPs
func GetTopTrustedIPs(limit int) ([]*trust.TrustProfile, error) {
	var profiles []*trust.TrustProfile

	query := `SELECT id, ip, trust_score, reputation, request_count, threat_count, clean_count, 
	          first_seen, last_seen, last_updated 
	          FROM user_trust_profiles 
	          WHERE trust_score >= 60
	          ORDER BY trust_score DESC 
	          LIMIT ?`

	rows, err := db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var profile trust.TrustProfile
		err := rows.Scan(
			&profile.ID, &profile.IP, &profile.TrustScore, &profile.Reputation,
			&profile.RequestCount, &profile.ThreatCount, &profile.CleanCount,
			&profile.FirstSeen, &profile.LastSeen, &profile.LastUpdated,
		)
		if err == nil {
			profiles = append(profiles, &profile)
		}
	}

	return profiles, nil
}

// GetSuspiciousIPs retrieves suspicious IPs
func GetSuspiciousIPs(limit int) ([]*trust.TrustProfile, error) {
	var profiles []*trust.TrustProfile

	query := `SELECT id, ip, trust_score, reputation, request_count, threat_count, clean_count, 
	          first_seen, last_seen, last_updated 
	          FROM user_trust_profiles 
	          WHERE trust_score < 40
	          ORDER BY trust_score ASC 
	          LIMIT ?`

	rows, err := db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var profile trust.TrustProfile
		err := rows.Scan(
			&profile.ID, &profile.IP, &profile.TrustScore, &profile.Reputation,
			&profile.RequestCount, &profile.ThreatCount, &profile.CleanCount,
			&profile.FirstSeen, &profile.LastSeen, &profile.LastUpdated,
		)
		if err == nil {
			profiles = append(profiles, &profile)
		}
	}

	return profiles, nil
}

// LogTrustEvent logs a trust score change event
func LogTrustEvent(event trust.TrustEvent) error {
	query := `INSERT INTO trust_history (ip, event_type, old_score, new_score, reason, timestamp)
	          VALUES (?, ?, ?, ?, ?, ?)`

	_, err := db.Exec(query, event.IP, event.EventType, event.OldScore, event.NewScore, event.Reason, event.Timestamp)
	return err
}

// GetTrustHistory retrieves trust history for an IP
func GetTrustHistory(ip string, limit int) ([]trust.TrustEvent, error) {
	var events []trust.TrustEvent

	query := `SELECT id, ip, event_type, old_score, new_score, reason, timestamp 
	          FROM trust_history 
	          WHERE ip = ? 
	          ORDER BY timestamp DESC 
	          LIMIT ?`

	rows, err := db.Query(query, ip, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var event trust.TrustEvent
		err := rows.Scan(&event.ID, &event.IP, &event.EventType, &event.OldScore,
			&event.NewScore, &event.Reason, &event.Timestamp)
		if err == nil {
			events = append(events, event)
		}
	}

	return events, nil
}

// GetTrustDistribution returns count of profiles by trust level
func GetTrustDistribution() (map[string]int, error) {
	distribution := make(map[string]int)

	query := `SELECT reputation, COUNT(*) as count 
	          FROM user_trust_profiles 
	          GROUP BY reputation`

	rows, err := db.Query(query)
	if err != nil {
		return distribution, err
	}
	defer rows.Close()

	for rows.Next() {
		var reputation string
		var count int
		if err := rows.Scan(&reputation, &count); err == nil {
			distribution[reputation] = count
		}
	}

	return distribution, nil
}

// GetTrustStats returns overall trust statistics
func GetTrustStats() (trust.TrustStats, error) {
	stats := trust.TrustStats{}

	// Helper function to scan a single int count
	scanCount := func(query string) int {
		var count int
		_ = db.QueryRow(query).Scan(&count)
		return count
	}

	stats.TotalProfiles = scanCount("SELECT COUNT(*) FROM user_trust_profiles")
	stats.HighlyTrusted = scanCount("SELECT COUNT(*) FROM user_trust_profiles WHERE reputation = 'HIGHLY_TRUSTED'")
	stats.Trusted = scanCount("SELECT COUNT(*) FROM user_trust_profiles WHERE reputation = 'TRUSTED'")
	stats.Neutral = scanCount("SELECT COUNT(*) FROM user_trust_profiles WHERE reputation = 'NEUTRAL'")
	stats.Suspicious = scanCount("SELECT COUNT(*) FROM user_trust_profiles WHERE reputation = 'SUSPICIOUS'")
	stats.Malicious = scanCount("SELECT COUNT(*) FROM user_trust_profiles WHERE reputation = 'MALICIOUS'")

	// Use COALESCE to handle case where table is empty (AVG returns NULL)
	// IFNULL is the SQLite equivalent, but COALESCE works too
	err := db.QueryRow("SELECT COALESCE(AVG(trust_score), 0) FROM user_trust_profiles").Scan(&stats.AverageScore)
	if err != nil {
		// Fallback if query fails
		stats.AverageScore = 0
	}

	return stats, nil
}

// CountTrustProfiles returns total count of trust profiles
func CountTrustProfiles() int {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM user_trust_profiles").Scan(&count)
	return count
}

// CountByReputation returns count of profiles with specific reputation
func CountByReputation(reputation string) int {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM user_trust_profiles WHERE reputation = ?", reputation).Scan(&count)
	return count
}

// GetAverageTrustScore returns the average trust score across all profiles
func GetAverageTrustScore() float64 {
	var avg float64
	db.QueryRow("SELECT AVG(trust_score) FROM user_trust_profiles").Scan(&avg)
	return avg
}

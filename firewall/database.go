package main

import (
	"database/sql"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

type SecurityEvent struct {
	ID        int64     `json:"id"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	IP        string    `json:"ip"`
	Path      string    `json:"path"`
	Method    string    `json:"method"`
	UserAgent string    `json:"user_agent"`
	Details   string    `json:"details"`
	Payload   string    `json:"payload"`
	Timestamp time.Time `json:"timestamp"`
}

type RequestLog struct {
	ID         int64     `json:"id"`
	IP         string    `json:"ip"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	StatusCode int       `json:"status_code"`
	Duration   int64     `json:"duration"`
	UserAgent  string    `json:"user_agent"`
	Timestamp  time.Time `json:"timestamp"`
}

type EventStats struct {
	TotalEvents      int            `json:"total_events"`
	CriticalEvents   int            `json:"critical_events"`
	HighEvents       int            `json:"high_events"`
	MediumEvents     int            `json:"medium_events"`
	LowEvents        int            `json:"low_events"`
	EventsByType     map[string]int `json:"events_by_type"`
	TopAttackers     []IPStats      `json:"top_attackers"`
	EventsLast24h    int            `json:"events_last_24h"`
	EventsLastHour   int            `json:"events_last_hour"`
	BlockedRequests  int            `json:"blocked_requests"`
}

type IPStats struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

type RateLimitStatus struct {
	ActiveLimits  int              `json:"active_limits"`
	BlockedIPs    []string         `json:"blocked_ips"`
	TopRequesters []IPRequestStats `json:"top_requesters"`
}

type IPRequestStats struct {
	IP           string `json:"ip"`
	RequestCount int    `json:"request_count"`
	IsBlocked    bool   `json:"is_blocked"`
}

func InitDB() {
	var err error
	db, err = sql.Open("sqlite3", "./firewall.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}

	// Create tables
	createTables := `
	CREATE TABLE IF NOT EXISTS security_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		type TEXT NOT NULL,
		severity TEXT NOT NULL,
		ip TEXT NOT NULL,
		path TEXT,
		method TEXT,
		user_agent TEXT,
		details TEXT,
		payload TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS request_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		method TEXT NOT NULL,
		path TEXT NOT NULL,
		status_code INTEGER,
		duration INTEGER,
		user_agent TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS ip_whitelist (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT UNIQUE NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS ip_blacklist (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT UNIQUE NOT NULL,
		reason TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS firewall_config (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		key TEXT UNIQUE NOT NULL,
		value TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(type);
	CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_events(ip);
	CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_request_logs_ip ON request_logs(ip);
	`

	if _, err := db.Exec(createTables); err != nil {
		log.Fatal("Failed to create tables:", err)
	}

	log.Println("✅ Database initialized successfully")
}

func CloseDB() {
	if db != nil {
		db.Close()
	}
}

// Log security event
func LogSecurityEvent(event SecurityEvent) error {
	query := `
		INSERT INTO security_events (type, severity, ip, path, method, user_agent, details, payload, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query, event.Type, event.Severity, event.IP, event.Path, event.Method, event.UserAgent, event.Details, event.Payload, event.Timestamp)
	if err != nil {
		log.Printf("Error logging security event: %v", err)
		return err
	}
	return nil
}

// Log request
func LogRequest(reqLog RequestLog) error {
	query := `
		INSERT INTO request_logs (ip, method, path, status_code, duration, user_agent, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query, reqLog.IP, reqLog.Method, reqLog.Path, reqLog.StatusCode, reqLog.Duration, reqLog.UserAgent, reqLog.Timestamp)
	if err != nil {
		log.Printf("Error logging request: %v", err)
		return err
	}
	return nil
}

// Get security events with pagination
func GetSecurityEventsFromDB(limit, offset int, severity string) ([]SecurityEvent, error) {
	var events []SecurityEvent
	
	query := `SELECT id, type, severity, ip, path, method, user_agent, details, payload, timestamp 
			  FROM security_events`
	
	args := []interface{}{}
	if severity != "" {
		query += " WHERE severity = ?"
		args = append(args, severity)
	}
	
	query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var event SecurityEvent
		err := rows.Scan(&event.ID, &event.Type, &event.Severity, &event.IP, &event.Path, &event.Method, &event.UserAgent, &event.Details, &event.Payload, &event.Timestamp)
		if err != nil {
			log.Printf("Error scanning event: %v", err)
			continue
		}
		events = append(events, event)
	}

	return events, nil
}

// Get event statistics
func GetEventStatsFromDB() (EventStats, error) {
	stats := EventStats{
		EventsByType: make(map[string]int),
	}

	// Total events
	err := db.QueryRow("SELECT COUNT(*) FROM security_events").Scan(&stats.TotalEvents)
	if err != nil {
		return stats, err
	}

	// Events by severity
	db.QueryRow("SELECT COUNT(*) FROM security_events WHERE severity = 'CRITICAL'").Scan(&stats.CriticalEvents)
	db.QueryRow("SELECT COUNT(*) FROM security_events WHERE severity = 'HIGH'").Scan(&stats.HighEvents)
	db.QueryRow("SELECT COUNT(*) FROM security_events WHERE severity = 'MEDIUM'").Scan(&stats.MediumEvents)
	db.QueryRow("SELECT COUNT(*) FROM security_events WHERE severity = 'LOW'").Scan(&stats.LowEvents)

	// Events last 24 hours
	db.QueryRow("SELECT COUNT(*) FROM security_events WHERE timestamp > datetime('now', '-24 hours')").Scan(&stats.EventsLast24h)

	// Events last hour
	db.QueryRow("SELECT COUNT(*) FROM security_events WHERE timestamp > datetime('now', '-1 hour')").Scan(&stats.EventsLastHour)

	// Events by type
	rows, err := db.Query("SELECT type, COUNT(*) as count FROM security_events GROUP BY type ORDER BY count DESC LIMIT 10")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var eventType string
			var count int
			if err := rows.Scan(&eventType, &count); err == nil {
				stats.EventsByType[eventType] = count
			}
		}
	}

	// Top attackers
	rows, err = db.Query("SELECT ip, COUNT(*) as count FROM security_events GROUP BY ip ORDER BY count DESC LIMIT 10")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ipStat IPStats
			if err := rows.Scan(&ipStat.IP, &ipStat.Count); err == nil {
				stats.TopAttackers = append(stats.TopAttackers, ipStat)
			}
		}
	}

	// Blocked requests (rate limit exceeded)
	db.QueryRow("SELECT COUNT(*) FROM security_events WHERE type = 'RATE_LIMIT_EXCEEDED'").Scan(&stats.BlockedRequests)

	return stats, nil
}

// Get request logs
func GetRequestLogsFromDB(limit, offset int) ([]RequestLog, error) {
	var logs []RequestLog
	
	query := `SELECT id, ip, method, path, status_code, duration, user_agent, timestamp 
			  FROM request_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?`
	
	rows, err := db.Query(query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var log RequestLog
		err := rows.Scan(&log.ID, &log.IP, &log.Method, &log.Path, &log.StatusCode, &log.Duration, &log.UserAgent, &log.Timestamp)
		if err != nil {
			continue
		}
		logs = append(logs, log)
	}

	return logs, nil
}

// Whitelist/Blacklist operations
func AddIPToWhitelist(ip string) error {
	_, err := db.Exec("INSERT INTO ip_whitelist (ip) VALUES (?) ON CONFLICT(ip) DO NOTHING", ip)
	return err
}

func AddIPToBlacklist(ip, reason string) error {
	_, err := db.Exec("INSERT INTO ip_blacklist (ip, reason) VALUES (?, ?) ON CONFLICT(ip) DO NOTHING", ip, reason)
	return err
}

func RemoveIPFromWhitelist(ip string) error {
	_, err := db.Exec("DELETE FROM ip_whitelist WHERE ip = ?", ip)
	return err
}

func RemoveIPFromBlacklist(ip string) error {
	_, err := db.Exec("DELETE FROM ip_blacklist WHERE ip = ?", ip)
	return err
}

func GetWhitelistFromDB() ([]string, error) {
	var ips []string
	rows, err := db.Query("SELECT ip FROM ip_whitelist ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err == nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

func GetBlacklistFromDB() ([]string, error) {
	var ips []string
	rows, err := db.Query("SELECT ip FROM ip_blacklist ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err == nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}
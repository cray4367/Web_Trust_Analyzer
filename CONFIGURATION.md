# Web Trust Analyzer Configuration Guide

## Firewall Configuration

### Environment Variables (.env)

```env
# Server Configuration
ENV=development                    # development | production
FIREWALL_PORT=8080                # Port for firewall to listen on
MAIN_APP_URL=http://localhost:3400  # Your application URL

# Database
DB_PATH=./firewall.db             # SQLite database path

# Logging
LOG_LEVEL=info                    # debug | info | warn | error
LOG_FILE=./firewall.log          # Log file path
```

### Rate Limiting

Default configuration in code:
```go
RateLimitWindow: 60,   // Time window in seconds
RateLimitMax: 100,     // Maximum requests per window
```

Dynamic configuration via API:
```bash
curl -X POST http://localhost:8080/api/ratelimit/config \
  -H "Content-Type: application/json" \
  -d '{
    "window_seconds": 60,
    "max_requests": 100
  }'
```

### OWASP Protection Toggles

Configure in code:
```go
FirewallConfig{
    EnableCSRF:          true,  // Cross-Site Request Forgery protection
    EnableXSS:           true,  // Cross-Site Scripting protection
    EnableSQLi:          true,  // SQL Injection protection
    EnablePathTraversal: true,  // Path Traversal protection
    BlockSuspicious:     true,  // Block suspicious patterns
}
```

### Security Headers

Configured automatically via Helmet-style headers:

- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `Content-Security-Policy: default-src 'self'; ...`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`

## Dashboard Configuration

### API Endpoint

Update in `dashboard/src/Dashboard.jsx`:
```javascript
const API_BASE = 'http://localhost:8080/api';
```

For production, use your actual firewall URL:
```javascript
const API_BASE = 'https://firewall.yourdomain.com/api';
```

### Auto-Refresh Interval

Default: 5 seconds

Update in `Dashboard.jsx`:
```javascript
const interval = setInterval(fetchData, 5000); // 5000ms = 5 seconds
```

### Theme Customization

Customize colors in the `<style jsx>` section:

```css
/* Primary colors */
--primary-cyan: #00f5ff;
--primary-blue: #0080ff;

/* Danger/Alert colors */
--danger-red: #ff1744;
--warning-orange: #ff6b35;
--warning-yellow: #ffa726;

/* Success color */
--success-green: #66bb6a;

/* Background */
--bg-dark: #0a0e27;
--bg-card: rgba(15, 23, 42, 0.6);
```

## IP Management

### Whitelist Configuration

Add trusted IPs programmatically:
```bash
curl -X POST http://localhost:8080/api/ip/whitelist \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100"}'
```

Or directly in database:
```sql
INSERT INTO ip_whitelist (ip) VALUES ('192.168.1.100');
```

### Blacklist Configuration

Block malicious IPs:
```bash
curl -X POST http://localhost:8080/api/ip/blacklist \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "10.0.0.50",
    "reason": "Multiple SQL injection attempts"
  }'
```

## Custom Detection Patterns

### Adding SQL Injection Patterns

Edit `firewall/middleware.go`:

```go
fw.sqlPatterns = []*regexp.Regexp{
    // Existing patterns...
    regexp.MustCompile(`(?i)YOUR_CUSTOM_PATTERN`),
}
```

### Adding XSS Patterns

```go
fw.xssPatterns = []*regexp.Regexp{
    // Existing patterns...
    regexp.MustCompile(`(?i)YOUR_CUSTOM_XSS_PATTERN`),
}
```

### Adding Path Traversal Patterns

```go
fw.pathTraversalPatterns = []*regexp.Regexp{
    // Existing patterns...
    regexp.MustCompile(`YOUR_CUSTOM_PATH_PATTERN`),
}
```

## Production Deployment

### Recommended Settings

```env
# Production .env
ENV=production
FIREWALL_PORT=443
MAIN_APP_URL=http://localhost:3400
LOG_LEVEL=warn
```

### TLS/SSL Configuration

For production, add TLS support:

```go
// In main.go
if os.Getenv("ENV") == "production" {
    err := router.RunTLS(":443", "cert.pem", "key.pem")
    if err != nil {
        log.Fatal("Failed to start HTTPS server:", err)
    }
} else {
    router.Run(":8080")
}
```

### Reverse Proxy Setup (Nginx)

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Database Maintenance

### Backup

```bash
# Backup database
sqlite3 firewall/firewall.db ".backup firewall_backup.db"

# Scheduled backup (cron)
0 2 * * * sqlite3 /path/to/firewall.db ".backup /backups/firewall_$(date +\%Y\%m\%d).db"
```

### Cleanup Old Logs

```sql
-- Delete events older than 30 days
DELETE FROM security_events WHERE timestamp < datetime('now', '-30 days');

-- Delete request logs older than 7 days
DELETE FROM request_logs WHERE timestamp < datetime('now', '-7 days');

-- Vacuum to reclaim space
VACUUM;
```

### Database Optimization

```sql
-- Analyze for query optimization
ANALYZE;

-- Rebuild indexes
REINDEX;
```

## Monitoring and Alerts

### Log Monitoring

Monitor critical events:
```bash
# Watch for critical events
watch -n 5 "sqlite3 firewall.db 'SELECT COUNT(*) as critical_events FROM security_events WHERE severity=\"CRITICAL\" AND timestamp > datetime(\"now\", \"-1 hour\");'"
```

### Email Alerts (Example Integration)

Add to `handlers.go`:
```go
func sendAlert(event SecurityEvent) {
    if event.Severity == "CRITICAL" {
        // Send email notification
        // Implement your email service here
    }
}
```

## Performance Tuning

### Connection Pool

```go
// In database.go
db.SetMaxOpenConns(25)
db.SetMaxIdleConns(5)
db.SetConnMaxLifetime(5 * time.Minute)
```

### Rate Limit Cleanup

Periodically clean up old rate limit entries:
```go
// Add to firewall struct
func (fw *Firewall) cleanupRateLimits() {
    ticker := time.NewTicker(5 * time.Minute)
    go func() {
        for range ticker.C {
            fw.mutex.Lock()
            now := time.Now()
            for ip, entry := range fw.rateLimitStore {
                if now.Sub(entry.StartTime).Seconds() > float64(fw.config.RateLimitWindow * 2) {
                    delete(fw.rateLimitStore, ip)
                }
            }
            fw.mutex.Unlock()
        }
    }()
}
```

## Troubleshooting

### Enable Debug Logging

```env
LOG_LEVEL=debug
```

### View Real-time Logs

```bash
# Firewall logs
tail -f firewall/firewall.log

# Database events
watch -n 1 "sqlite3 firewall.db 'SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 10;'"
```

### Reset Configuration

```bash
# Clear all rate limits
sqlite3 firewall.db "DELETE FROM firewall_config WHERE key LIKE 'rate_limit%';"

# Clear whitelist/blacklist
sqlite3 firewall.db "DELETE FROM ip_whitelist; DELETE FROM ip_blacklist;"

# Reset database (⚠️ WARNING: Deletes all data)
rm firewall.db
# Restart firewall to recreate tables
```
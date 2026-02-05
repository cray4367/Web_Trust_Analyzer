# 🛡️ Web Trust Analyzer

Advanced Web Application Firewall with OWASP Top 10 Protection, Rate Limiting, and Real-time Monitoring Dashboard

## 🌟 Features

### Firewall Protection (Go-based)
- ✅ **OWASP Top 10 Protection**
  1. Broken Access Control
  2. Cryptographic Failures (Security Headers)
  3. Injection (SQL Injection, XSS)
  4. Insecure Design
  5. Security Misconfiguration
  6. Vulnerable and Outdated Components
  7. Identification and Authentication Failures
  8. Software and Data Integrity Failures
  9. Security Logging and Monitoring
  10. Server-Side Request Forgery (SSRF)

- 🚦 **Rate Limiting**
  - Configurable time windows
  - Per-IP request limits
  - Automatic blocking of excessive requests
  - Whitelist/Blacklist management

- 📊 **Advanced Logging**
  - SQLite database storage
  - Security event tracking
  - Request logging with performance metrics
  - Threat pattern analysis

- 🔍 **Real-time Threat Detection**
  - SQL injection pattern matching
  - XSS attack detection
  - Path traversal prevention
  - Malicious payload identification

### Dashboard (React-based)
- 📈 **Real-time Monitoring**
  - Live security event feed
  - Attack statistics and trends
  - Threat distribution analysis
  - Performance metrics

- 🎨 **Cybersecurity-themed UI**
  - Dark theme with neon accents
  - Animated backgrounds
  - Interactive data visualizations
  - Responsive design

- ⚙️ **Configuration Management**
  - Firewall settings control
  - Rate limit configuration
  - IP whitelist/blacklist management
  - OWASP check toggles

## 🏗️ Architecture

```
┌─────────────────┐
│  Your React App │ (Port 3000)
│   (Protected)   │
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│   Go Firewall   │ (Port 8080)
│  - OWASP Checks │
│  - Rate Limit   │
│  - Logging      │
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│ SQLite Database │
│  - Events       │
│  - Requests     │
│  - Config       │
└─────────────────┘

┌─────────────────┐
│ React Dashboard │ (Port 3001)
│  - Monitoring   │
│  - Analytics    │
│  - Config UI    │
└─────────────────┘
```

## 📦 Installation

### Prerequisites
- Go 1.21 or higher
- Node.js 18 or higher
- npm or yarn

### 1. Clone or Copy the Project

```bash
cd web-trust-analyzer
```

### 2. Setup the Firewall (Go)

```bash
cd firewall

# Install dependencies
go mod download

# Build the firewall
go build -o firewall

# Or run directly
go run .
```

### 3. Setup the Dashboard (React)

```bash
cd dashboard

# Install dependencies
npm install

# Start development server
npm run dev
```

## 🚀 Usage

### Starting the System

1. **Start your main React application** (on port 3400):
```bash
# In your main app directory
npm start
```

2. **Start the Go Firewall**:
```bash
cd firewall
go run .
```

The firewall will:
- Listen on port 8080
- Proxy requests to your app on port 3400 via `/app/*` routes
- Provide API endpoints on `/api/*` for the dashboard
- Log all security events to `firewall.db`

3. **Start the Dashboard**:
```bash
cd dashboard
npm run dev
```

Access the dashboard at `http://localhost:3000`

### Accessing Your Protected App

Instead of accessing your app directly at `http://localhost:3400`, use:
```
http://localhost:8080/app
```

All requests will be filtered through the firewall.

## 🔧 Configuration

### Firewall Configuration

Edit `firewall/.env`:

```env
ENV=development
FIREWALL_PORT=8080
MAIN_APP_URL=http://localhost:3400
```

### Rate Limiting

Configure via the dashboard or directly in the database:

```go
RateLimitWindow:   60,  // seconds
RateLimitMax:      100, // requests per window
```

### OWASP Protection Toggles

Enable/disable specific checks:

```go
FirewallConfig{
    EnableCSRF:          true,
    EnableXSS:           true,
    EnableSQLi:          true,
    EnablePathTraversal: true,
    BlockSuspicious:     true,
}
```

## 📊 Dashboard Features

### Overview Tab
- Total security events
- Events in last 24 hours
- Blocked requests count
- Unique attacker IPs
- Severity distribution chart
- Threat type distribution
- Recent events table

### Threats Tab
- Detailed event logs
- Filtering by severity
- Search functionality
- Export capabilities

### OWASP Tab
- Status of all 10 OWASP checks
- Visual indicators for enabled protections
- Quick toggle controls

### Settings Tab
- Rate limit configuration
- Protection toggles
- Whitelist/blacklist management
- Real-time config updates

## 🧪 Testing the Firewall

### Test SQL Injection Protection

```bash
# This should be blocked
curl "http://localhost:8080/app?id=1' OR '1'='1"
```

### Test XSS Protection

```bash
# This should be blocked
curl "http://localhost:8080/app?search=<script>alert('xss')</script>"
```

### Test Path Traversal

```bash
# This should be blocked
curl "http://localhost:8080/app/../../etc/passwd"
```

### Test Rate Limiting

```bash
# Exceed the rate limit
for i in {1..150}; do
  curl "http://localhost:8080/app"
done
```

## 📡 API Endpoints

### Security Events
- `GET /api/events` - Get security events (with pagination)
- `GET /api/events/:id` - Get specific event
- `GET /api/events/stats` - Get event statistics

### Rate Limiting
- `GET /api/ratelimit/status` - Get rate limit status
- `POST /api/ratelimit/config` - Update rate limit config
- `GET /api/ratelimit/blocked` - Get blocked IPs

### Configuration
- `GET /api/config` - Get firewall configuration
- `POST /api/config` - Update firewall configuration

### Monitoring
- `GET /api/monitor/live` - Get live metrics
- `GET /api/monitor/threats` - Get threat analysis

### IP Management
- `POST /api/ip/whitelist` - Add IP to whitelist
- `POST /api/ip/blacklist` - Add IP to blacklist
- `DELETE /api/ip/whitelist/:ip` - Remove from whitelist
- `DELETE /api/ip/blacklist/:ip` - Remove from blacklist
- `GET /api/ip/whitelist` - Get whitelist
- `GET /api/ip/blacklist` - Get blacklist

### OWASP
- `GET /api/owasp/status` - Get OWASP check status
- `GET /api/owasp/violations` - Get violation counts

## 🗄️ Database Schema

### security_events
```sql
- id: INTEGER PRIMARY KEY
- type: TEXT (SQL_INJECTION, XSS_ATTEMPT, etc.)
- severity: TEXT (CRITICAL, HIGH, MEDIUM, LOW)
- ip: TEXT
- path: TEXT
- method: TEXT
- user_agent: TEXT
- details: TEXT
- payload: TEXT
- timestamp: DATETIME
```

### request_logs
```sql
- id: INTEGER PRIMARY KEY
- ip: TEXT
- method: TEXT
- path: TEXT
- status_code: INTEGER
- duration: INTEGER (milliseconds)
- user_agent: TEXT
- timestamp: DATETIME
```

### ip_whitelist / ip_blacklist
```sql
- id: INTEGER PRIMARY KEY
- ip: TEXT UNIQUE
- reason: TEXT (blacklist only)
- created_at: DATETIME
```

## 🔒 Security Best Practices

1. **Always run the firewall in production** - Never expose your app directly
2. **Monitor the dashboard regularly** - Check for attack patterns
3. **Update rate limits** - Adjust based on your traffic patterns
4. **Whitelist trusted IPs** - Reduce false positives
5. **Review logs daily** - Identify persistent attackers
6. **Keep dependencies updated** - Run `go get -u` and `npm update` regularly
7. **Use HTTPS in production** - Add TLS termination
8. **Set strong CSP headers** - Customize Content-Security-Policy
9. **Enable all OWASP checks** - Maximum protection
10. **Backup the database** - Regular backups of firewall.db

## 🚨 Common Issues

### Firewall won't start
- Check if port 8080 is already in use
- Verify Go version: `go version`
- Check database permissions

### Dashboard shows no data
- Ensure firewall is running
- Check CORS configuration
- Verify API_BASE URL in Dashboard.jsx

### App not accessible
- Confirm your app is running on port 3400
- Check firewall proxy configuration
- Review firewall logs

### High false positive rate
- Adjust detection patterns in `middleware.go`
- Whitelist your IP
- Fine-tune rate limits

## 📝 Customization

### Adding Custom Detection Patterns

Edit `firewall/middleware.go`:

```go
// Add to suspiciousPatterns
fw.customPatterns = []*regexp.Regexp{
    regexp.MustCompile(`your-pattern-here`),
}
```

### Custom Dashboard Theme

Edit the `<style jsx>` section in `Dashboard.jsx`:

```css
:root {
    --primary-color: #00f5ff;
    --secondary-color: #0080ff;
    --danger-color: #ff1744;
}
```

### Additional OWASP Checks

Implement in `middleware.go`:

```go
func (fw *Firewall) CustomCheck() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Your custom security check
        c.Next()
    }
}
```

## 🛠️ Development

### Running Tests

```bash
cd firewall
go test ./...
```

### Building for Production

```bash
# Firewall
cd firewall
go build -ldflags="-s -w" -o firewall

# Dashboard
cd dashboard
npm run build
```

### Docker Deployment (Optional)

Create a `Dockerfile` for the firewall:

```dockerfile
FROM golang:1.21-alpine
WORKDIR /app
COPY . .
RUN go build -o firewall
CMD ["./firewall"]
```

## 📈 Performance Considerations

- **Database indexes** are created automatically for optimal query performance
- **Rate limiting** uses in-memory storage for fast lookups
- **Pattern matching** is optimized with compiled regex
- **Connection pooling** for database operations
- **Middleware ordering** is optimized for minimal overhead

## 🤝 Contributing

This is a complete, production-ready firewall system. To extend:

1. Add new detection patterns in `middleware.go`
2. Create new API endpoints in `handlers.go`
3. Add dashboard visualizations in `Dashboard.jsx`
4. Implement custom OWASP checks
5. Add machine learning threat detection

## 📄 License

MIT License - Feel free to use in your projects

## 🆘 Support

For issues or questions:
1. Check the logs: `tail -f firewall/firewall.log`
2. Review the database: `sqlite3 firewall/firewall.db`
3. Enable debug mode: Set `ENV=development` in `.env`
4. Check dashboard console for errors

## 🎯 Roadmap

- [ ] Machine learning-based threat detection
- [ ] Geographic IP blocking
- [ ] Integration with threat intelligence feeds
- [ ] Advanced DDoS protection
- [ ] Automated IP reputation checking
- [ ] Multi-factor authentication for admin
- [ ] Webhook notifications for critical events
- [ ] Custom rule engine
- [ ] Performance optimization
- [ ] Cloud deployment templates

---

**Built with ❤️ for web application security**

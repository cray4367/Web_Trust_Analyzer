package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type FirewallConfig struct {
	RateLimitWindow     int  `json:"rate_limit_window"`
	RateLimitMax        int  `json:"rate_limit_max"`
	EnableCSRF          bool `json:"enable_csrf"`
	EnableXSS           bool `json:"enable_xss"`
	EnableSQLi          bool `json:"enable_sqli"`
	EnablePathTraversal bool `json:"enable_path_traversal"`
	BlockSuspicious     bool `json:"block_suspicious"`
}

type Firewall struct {
	config                FirewallConfig
	rateLimitStore        map[string]*RateLimitEntry
	mutex                 sync.RWMutex
	whitelist             map[string]bool
	blacklist             map[string]bool
	sqlPatterns           []*regexp.Regexp
	xssPatterns           []*regexp.Regexp
	pathTraversalPatterns []*regexp.Regexp
}

type RateLimitEntry struct {
	Count     int
	StartTime time.Time
	Blocked   bool
}

func NewFirewall(config FirewallConfig) *Firewall {
	fw := &Firewall{
		config:         config,
		rateLimitStore: make(map[string]*RateLimitEntry),
		whitelist:      make(map[string]bool),
		blacklist:      make(map[string]bool),
	}

	// SQL Injection Patterns
	fw.sqlPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(%27)|(\')|(\-\-)|(\%23)|(#)`),
		regexp.MustCompile(`(?i)((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(:))`),
		regexp.MustCompile(`(?i)UNION\s+SELECT`),
		regexp.MustCompile(`(?i)WAITFOR\s+DELAY`),
		regexp.MustCompile(`(?i)OR\s+1=1`),
		regexp.MustCompile(`(?i)DROP\s+TABLE`),
		regexp.MustCompile(`(?i);.*(DELETE|INSERT|UPDATE)`),
	}

	// XSS Patterns
	fw.xssPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`),
		regexp.MustCompile(`(?i)javascript:`),
		regexp.MustCompile(`(?i)on\w+\s*=`),
		regexp.MustCompile(`(?i)<iframe`),
		regexp.MustCompile(`(?i)<svg[^>]*on\w+`),
		regexp.MustCompile(`(?i)alert\(`),
	}

	// Path Traversal
	fw.pathTraversalPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\.\./`),
		regexp.MustCompile(`\.\.\\`),
		regexp.MustCompile(`%2e%2e%2f`),
	}

	return fw
}

func (fw *Firewall) UpdateConfig(newConfig FirewallConfig) {
	fw.mutex.Lock()
	defer fw.mutex.Unlock()
	fw.config = newConfig
}

func (fw *Firewall) GetConfig() FirewallConfig {
	fw.mutex.RLock()
	defer fw.mutex.RUnlock()
	return fw.config
}

// 1. Threat Detector (With Fix for XSS/SQLi order)
func (fw *Firewall) ThreatDetector() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		fw.mutex.RLock()
		enableSQLi := fw.config.EnableSQLi
		enableXSS := fw.config.EnableXSS
		fw.mutex.RUnlock()

		// Read Body safely
		var bodyString string
		if c.Request.Body != nil {
			bodyBytes, _ := io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			bodyString = string(bodyBytes)
		}

		// CHECK XSS FIRST
		if enableXSS {
			if fw.checkXSS(bodyString) {
				fw.logThreat(c, "XSS_ATTEMPT", "XSS detected in body", bodyString)
				fw.respondBlocked(c, "XSS Detected")
				return
			}
			for _, values := range c.Request.URL.Query() {
				for _, value := range values {
					if fw.checkXSS(value) {
						fw.logThreat(c, "XSS_ATTEMPT", "XSS detected in URL", value)
						fw.respondBlocked(c, "XSS Detected")
						return
					}
				}
			}
		}

		// CHECK SQLi SECOND
		if enableSQLi {
			if fw.checkSQLInjection(bodyString) {
				fw.logThreat(c, "SQL_INJECTION", "SQL injection detected in body", bodyString)
				fw.respondBlocked(c, "SQL Injection Detected")
				return
			}
			for _, values := range c.Request.URL.Query() {
				for _, value := range values {
					if fw.checkSQLInjection(value) {
						fw.logThreat(c, "SQL_INJECTION", "SQL injection detected in URL", value)
						fw.respondBlocked(c, "SQL Injection Detected")
						return
					}
				}
			}
		}

		c.Next()
	}
}

// 2. Rate Limiter (With Fix for live updates)
func (fw *Firewall) RateLimiter() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		clientIP := c.ClientIP()
		fw.mutex.RLock()
		limitWindow := fw.config.RateLimitWindow
		limitMax := fw.config.RateLimitMax
		isWhitelisted := fw.whitelist[clientIP]
		isBlacklisted := fw.blacklist[clientIP]
		fw.mutex.RUnlock()

		if isWhitelisted {
			c.Next()
			return
		}

		if isBlacklisted {
			fw.respondBlocked(c, "IP is Blacklisted")
			return
		}

		fw.mutex.Lock()
		entry, exists := fw.rateLimitStore[clientIP]

		if !exists {
			fw.rateLimitStore[clientIP] = &RateLimitEntry{Count: 1, StartTime: time.Now(), Blocked: false}
			fw.mutex.Unlock()
			c.Next()
			return
		}

		if time.Since(entry.StartTime).Seconds() > float64(limitWindow) {
			entry.Count = 1
			entry.StartTime = time.Now()
			entry.Blocked = false
			fw.mutex.Unlock()
			c.Next()
			return
		}

		entry.Count++
		if entry.Count > limitMax {
			if !entry.Blocked {
				entry.Blocked = true
				go LogSecurityEvent(SecurityEvent{
					Type:      "RATE_LIMIT_EXCEEDED",
					Severity:  "HIGH",
					IP:        clientIP,
					Path:      c.Request.URL.Path,
					Method:    c.Request.Method,
					UserAgent: c.Request.UserAgent(),
					Details:   "Rate limit exceeded",
					Timestamp: time.Now(),
				})
			}
			fw.mutex.Unlock()
			c.Header("Retry-After", "60")
			fw.respondBlocked(c, "Too Many Requests")
			return
		}

		fw.mutex.Unlock()
		c.Next()
	}
}

// 3. Request Logger (THIS IS THE MISSING PART YOU NEED)
func (fw *Firewall) RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		duration := time.Since(start)
		
		// Only log requests that are NOT internal API calls (to reduce noise)
		if !strings.HasPrefix(c.Request.URL.Path, "/api") {
			go LogRequest(RequestLog{
				IP:         c.ClientIP(),
				Method:     c.Request.Method,
				Path:       c.Request.URL.Path,
				StatusCode: c.Writer.Status(),
				Duration:   duration.Milliseconds(),
				UserAgent:  c.Request.UserAgent(),
				Timestamp:  start,
			})
		}
	}
}

// 4. Input Validator
func (fw *Firewall) InputValidator() gin.HandlerFunc {
	return func(c *gin.Context) {
		fw.mutex.RLock()
		enabled := fw.config.EnablePathTraversal
		fw.mutex.RUnlock()

		if enabled {
			if fw.checkPathTraversal(c.Request.URL.Path) {
				fw.logThreat(c, "PATH_TRAVERSAL", "Directory traversal attempt", c.Request.URL.Path)
				fw.respondBlocked(c, "Invalid Request")
				return
			}
		}
		c.Next()
	}
}

func (fw *Firewall) SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline';")
		c.Next()
	}
}

func (fw *Firewall) ProxyMiddleware(targetURL string) gin.HandlerFunc {
	target, _ := url.Parse(targetURL)
	proxy := httputil.NewSingleHostReverseProxy(target)

	return func(c *gin.Context) {
		if !c.IsAborted() {
			c.Request.URL.Path = strings.TrimPrefix(c.Request.URL.Path, "/app")
			proxy.ServeHTTP(c.Writer, c.Request)
		}
	}
}

// Helpers
func (fw *Firewall) checkSQLInjection(input string) bool {
	for _, pattern := range fw.sqlPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

func (fw *Firewall) checkXSS(input string) bool {
	for _, pattern := range fw.xssPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

func (fw *Firewall) checkPathTraversal(input string) bool {
	for _, pattern := range fw.pathTraversalPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

func (fw *Firewall) logThreat(c *gin.Context, threatType, details, payload string) {
	go LogSecurityEvent(SecurityEvent{
		Type:      threatType,
		Severity:  "CRITICAL",
		IP:        c.ClientIP(),
		Path:      c.Request.URL.Path,
		Method:    c.Request.Method,
		UserAgent: c.Request.UserAgent(),
		Details:   details,
		Payload:   payload,
		Timestamp: time.Now(),
	})
}

func (fw *Firewall) respondBlocked(c *gin.Context, reason string) {
	c.Header("Access-Control-Allow-Origin", "http://localhost:5173")
	c.Header("Access-Control-Allow-Credentials", "true")
	c.JSON(http.StatusForbidden, gin.H{"error": reason})
	c.Abort()
}

// IP Management
func (fw *Firewall) AddToWhitelist(ip string) {
	fw.mutex.Lock()
	defer fw.mutex.Unlock()
	fw.whitelist[ip] = true
}

func (fw *Firewall) AddToBlacklist(ip string) {
	fw.mutex.Lock()
	defer fw.mutex.Unlock()
	fw.blacklist[ip] = true
}

func (fw *Firewall) RemoveFromWhitelist(ip string) {
	fw.mutex.Lock()
	defer fw.mutex.Unlock()
	delete(fw.whitelist, ip)
}

func (fw *Firewall) RemoveFromBlacklist(ip string) {
	fw.mutex.Lock()
	defer fw.mutex.Unlock()
	delete(fw.blacklist, ip)
}
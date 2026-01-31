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
	RateLimitWindow     int
	RateLimitMax        int
	EnableCSRF          bool
	EnableXSS           bool
	EnableSQLi          bool
	EnablePathTraversal bool
	BlockSuspicious     bool
}

type Firewall struct {
	config          FirewallConfig
	rateLimitStore  map[string]*RateLimitEntry
	mutex           sync.RWMutex
	whitelist       map[string]bool
	blacklist       map[string]bool
	suspiciousPatterns []*regexp.Regexp
	sqlPatterns     []*regexp.Regexp
	xssPatterns     []*regexp.Regexp
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

	// Initialize SQL injection patterns (OWASP #3)
	fw.sqlPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)`),
		regexp.MustCompile(`(?i)((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(:))`),
		regexp.MustCompile(`(?i)\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))`),
		regexp.MustCompile(`(?i)UNION.*SELECT`),
		regexp.MustCompile(`(?i)INSERT.*INTO`),
		regexp.MustCompile(`(?i)DELETE.*FROM`),
		regexp.MustCompile(`(?i)DROP.*TABLE`),
		regexp.MustCompile(`(?i)UPDATE.*SET`),
		regexp.MustCompile(`(?i)SELECT.*FROM`),
		regexp.MustCompile(`(?i)exec(\s|\+)+(s|x)p\w+`),
		regexp.MustCompile(`(?i)/\*.*\*/`),
		regexp.MustCompile(`(?i);.*(\bDROP\b|\bCREATE\b|\bDELETE\b|\bINSERT\b|\bUPDATE\b)`),
	}

	// Initialize XSS patterns (OWASP #3)
	fw.xssPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`),
		regexp.MustCompile(`(?i)javascript:`),
		regexp.MustCompile(`(?i)on\w+\s*=`),
		regexp.MustCompile(`(?i)<iframe`),
		regexp.MustCompile(`(?i)<object`),
		regexp.MustCompile(`(?i)<embed`),
		regexp.MustCompile(`(?i)<img[^>]+src[^>]*>`),
		regexp.MustCompile(`(?i)eval\(`),
		regexp.MustCompile(`(?i)expression\(`),
		regexp.MustCompile(`(?i)<svg[^>]*on\w+`),
		regexp.MustCompile(`(?i)vbscript:`),
		regexp.MustCompile(`(?i)data:text/html`),
	}

	// Initialize path traversal patterns (OWASP #1)
	fw.pathTraversalPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\.\.\/`),
		regexp.MustCompile(`\.\.\\`),
		regexp.MustCompile(`%2e%2e%2f`),
		regexp.MustCompile(`%2e%2e/`),
		regexp.MustCompile(`..%2f`),
		regexp.MustCompile(`%2e%2e\\`),
	}

	return fw
}

// OWASP #5: Security Misconfiguration - Security Headers
func (fw *Firewall) SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent clickjacking
		c.Header("X-Frame-Options", "DENY")
		
		// Prevent MIME sniffing
		c.Header("X-Content-Type-Options", "nosniff")
		
		// XSS Protection
		c.Header("X-XSS-Protection", "1; mode=block")
		
		// Content Security Policy
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;")
		
		// HSTS
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		
		// Referrer Policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		
		// Permissions Policy
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		
		c.Next()
	}
}

// Rate Limiter - Prevents brute force and DDoS
func (fw *Firewall) RateLimiter() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		
		// Check if IP is whitelisted
		fw.mutex.RLock()
		if fw.whitelist[clientIP] {
			fw.mutex.RUnlock()
			c.Next()
			return
		}
		
		// Check if IP is blacklisted
		if fw.blacklist[clientIP] {
			fw.mutex.RUnlock()
			LogSecurityEvent(SecurityEvent{
				Type:      "BLACKLISTED_IP",
				Severity:  "CRITICAL",
				IP:        clientIP,
				Path:      c.Request.URL.Path,
				Method:    c.Request.Method,
				UserAgent: c.Request.UserAgent(),
				Details:   "Request from blacklisted IP",
				Timestamp: time.Now(),
			})
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			c.Abort()
			return
		}
		fw.mutex.RUnlock()
		
		fw.mutex.Lock()
		entry, exists := fw.rateLimitStore[clientIP]
		
		if !exists {
			fw.rateLimitStore[clientIP] = &RateLimitEntry{
				Count:     1,
				StartTime: time.Now(),
				Blocked:   false,
			}
			fw.mutex.Unlock()
			c.Next()
			return
		}
		
		// Check if window has expired
		if time.Since(entry.StartTime).Seconds() > float64(fw.config.RateLimitWindow) {
			entry.Count = 1
			entry.StartTime = time.Now()
			entry.Blocked = false
			fw.mutex.Unlock()
			c.Next()
			return
		}
		
		// Increment counter
		entry.Count++
		
		// Check if limit exceeded
		if entry.Count > fw.config.RateLimitMax {
			if !entry.Blocked {
				entry.Blocked = true
				LogSecurityEvent(SecurityEvent{
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
			
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many requests",
				"retry_after": fw.config.RateLimitWindow,
			})
			c.Abort()
			return
		}
		
		fw.mutex.Unlock()
		c.Next()
	}
}

// Input Validator - Validates and sanitizes input
func (fw *Firewall) InputValidator() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check URL parameters
		for key, values := range c.Request.URL.Query() {
			for _, value := range values {
				if fw.config.EnablePathTraversal && fw.checkPathTraversal(value) {
					fw.logThreat(c, "PATH_TRAVERSAL", "Attempt", value)
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input detected"})
					c.Abort()
					return
				}
			}
		}
		
		// Check path for traversal
		if fw.config.EnablePathTraversal && fw.checkPathTraversal(c.Request.URL.Path) {
			fw.logThreat(c, "PATH_TRAVERSAL", "Attempt in URL path", c.Request.URL.Path)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid path"})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// Threat Detector - Detects SQL injection, XSS, and other attacks
func (fw *Firewall) ThreatDetector() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Read body if present
		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
		
		bodyString := string(bodyBytes)
		
		// Check for SQL injection
		if fw.config.EnableSQLi && fw.checkSQLInjection(bodyString) {
			fw.logThreat(c, "SQL_INJECTION", "SQL injection attempt detected", bodyString)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input detected"})
			c.Abort()
			return
		}
		
		// Check URL parameters for SQL injection
		for _, values := range c.Request.URL.Query() {
			for _, value := range values {
				if fw.config.EnableSQLi && fw.checkSQLInjection(value) {
					fw.logThreat(c, "SQL_INJECTION", "SQL injection in URL parameter", value)
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input detected"})
					c.Abort()
					return
				}
			}
		}
		
		// Check for XSS
		if fw.config.EnableXSS && fw.checkXSS(bodyString) {
			fw.logThreat(c, "XSS_ATTEMPT", "XSS attempt detected", bodyString)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input detected"})
			c.Abort()
			return
		}
		
		// Check URL parameters for XSS
		for _, values := range c.Request.URL.Query() {
			for _, value := range values {
				if fw.config.EnableXSS && fw.checkXSS(value) {
					fw.logThreat(c, "XSS_ATTEMPT", "XSS in URL parameter", value)
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input detected"})
					c.Abort()
					return
				}
			}
		}
		
		c.Next()
	}
}

// Request Logger - Logs all requests
func (fw *Firewall) RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		
		c.Next()
		
		duration := time.Since(start)
		
		LogRequest(RequestLog{
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

// Helper functions
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
	LogSecurityEvent(SecurityEvent{
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

// Proxy Middleware - Proxies requests to the main app
func (fw *Firewall) ProxyMiddleware(targetURL string) gin.HandlerFunc {
	target, _ := url.Parse(targetURL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	
	return func(c *gin.Context) {
		c.Request.URL.Path = strings.TrimPrefix(c.Request.URL.Path, "/app")
		proxy.ServeHTTP(c.Writer, c.Request)
	}
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
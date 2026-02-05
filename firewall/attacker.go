package main

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Attack Simulation Module
// This module runs inside the firewall server and sends malicious requests to the proxy endpoint.
// It bypasses browser restrictions and allows for high-concurrency testing.

const (
	TargetURL = "http://localhost:8080/app" // The proxy endpoint we are attacking
)

type AttackRequest struct {
	Type      string `json:"type" binding:"required"` // SQL_INJECTION, XSS, FLOOD, BOT, PATH_TRAVERSAL
	Intensity int    `json:"intensity"`               // Number of requests (for flood)
	Target    string `json:"target"`                  // Override target (optional)
}

type AttackResult struct {
	Success      bool     `json:"success"`
	Message      string   `json:"message"`
	BlockedCount int      `json:"blocked_count"`
	PassedCount  int      `json:"passed_count"`
	Details      []string `json:"details"`
}

func SimulateAttack(c *gin.Context) {
	var req AttackRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result := AttackResult{Details: []string{}}

	switch req.Type {
	case "SQL_INJECTION":
		result = runSQLInjectionAttack()
	case "XSS":
		result = runXSSAttack()
	case "PATH_TRAVERSAL":
		result = runPathTraversalAttack()
	case "BOT":
		result = runBotAttack()
	case "FLOOD":
		intensity := req.Intensity
		if intensity <= 0 {
			intensity = 50
		}
		result = runFloodAttack(intensity)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown attack type"})
		return
	}

	c.JSON(http.StatusOK, result)
}

func runSQLInjectionAttack() AttackResult {
	payloads := []string{
		"' OR '1'='1",
		"UNION SELECT username, password FROM users",
		"admin' --",
		"1; DROP TABLE users",
	}

	return runPayloadAttack("SQL_INJECTION", payloads)
}

func runXSSAttack() AttackResult {
	payloads := []string{
		"<script>alert(1)</script>",
		"javascript:alert(1)",
		"<img src=x onerror=alert(1)>",
	}

	return runPayloadAttack("XSS", payloads)
}

func runPathTraversalAttack() AttackResult {
	payloads := []string{
		"../../etc/passwd",
		"..\\windows\\system32\\drivers\\etc\\hosts",
		"%2e%2e%2f%2e%2e%2f",
	}

	return runPayloadAttack("PATH_TRAVERSAL", payloads)
}

func runPayloadAttack(attackType string, payloads []string) AttackResult {
	blocked := 0
	passed := 0
	details := []string{}

	client := &http.Client{Timeout: 5 * time.Second}

	for _, payload := range payloads {
		// URL Encode the payload to ensure valid HTTP request
		safePayload := url.QueryEscape(payload)

		// Test Query Param
		reqUrl := fmt.Sprintf("%s?q=%s", TargetURL, safePayload)
		resp, err := client.Get(reqUrl)
		if err != nil {
			details = append(details, fmt.Sprintf("Error sending %s: %v", payload, err))
			continue
		}

		if resp.StatusCode == 403 {
			blocked++
			details = append(details, fmt.Sprintf("✅ BLOCKED: %s", payload))
		} else {
			passed++
			details = append(details, fmt.Sprintf("⚠️ PASSED: %s (Status: %d)", payload, resp.StatusCode))
		}
	}

	return AttackResult{
		Success:      true,
		Message:      fmt.Sprintf("Executed %d %s payloads", len(payloads), attackType),
		BlockedCount: blocked,
		PassedCount:  passed,
		Details:      details,
	}
}

func runBotAttack() AttackResult {
	// Simulates a bot accessing the site with suspicious User-Agents
	userAgents := []string{
		"EvilBot/1.0",
		"masscan/1.0",
		"sqlmap/1.4",
		"curl/7.68.0",
		"", // Empty User-Agent
	}

	blocked := 0
	passed := 0
	details := []string{}
	client := &http.Client{Timeout: 5 * time.Second}

	for _, ua := range userAgents {
		req, _ := http.NewRequest("GET", TargetURL, nil)
		req.Header.Set("User-Agent", ua)

		resp, err := client.Do(req)
		if err != nil {
			details = append(details, fmt.Sprintf("Error: %v", err))
			continue
		}

		uaDisplay := ua
		if ua == "" {
			uaDisplay = "<Empty>"
		}

		if resp.StatusCode == 403 {
			blocked++
			details = append(details, fmt.Sprintf("✅ BLOCKED User-Agent: %s", uaDisplay))
		} else {
			passed++
			details = append(details, fmt.Sprintf("⚠️ PASSED User-Agent: %s (Status: %d)", uaDisplay, resp.StatusCode))
		}
	}

	return AttackResult{
		Success:      true,
		Message:      "Bot Attack Simulation Complete",
		BlockedCount: blocked,
		PassedCount:  passed,
		Details:      details,
	}
}

func runFloodAttack(count int) AttackResult {
	// High concurrency flood
	var wg sync.WaitGroup
	var blocked, passed, errors int
	var mu sync.Mutex

	client := &http.Client{Timeout: 2 * time.Second}

	// Create a custom Transport to allow high concurrency
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 100
	t.MaxConnsPerHost = 100
	client.Transport = t

	startTime := time.Now()

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(TargetURL)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				errors++
				return
			}

			if resp.StatusCode == 429 || resp.StatusCode == 403 { // 429 Too Many Requests
				blocked++
			} else {
				passed++
			}
		}()
	}

	wg.Wait()
	duration := time.Since(startTime)

	return AttackResult{
		Success:      true,
		Message:      fmt.Sprintf("Flood Attack: Sent %d requests in %v", count, duration),
		BlockedCount: blocked,
		PassedCount:  passed,
		Details:      []string{fmt.Sprintf("Rate Limit Logic: Blocked %d, Allowed %d, Errors %d", blocked, passed, errors)},
	}
}

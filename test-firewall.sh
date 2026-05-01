#!/bin/bash

# Web Trust Analyzer - Testing Script
# This script demonstrates the firewall's protection capabilities

FIREWALL_URL="http://localhost:8080"
APP_URL="$FIREWALL_URL"
# Use a clear Mozilla user agent without 'curl' anywhere in the name
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

echo "🧪 Web Trust Analyzer - Security Testing Script"
echo "================================================"
echo ""
echo "⚠️  WARNING: Only run this against your own firewall for testing!"
echo ""
echo "Testing firewall at: $FIREWALL_URL"
echo ""

# Test 1: Normal Request
echo "✅ Test 1: Normal Request (Should Pass)"
curl -s -o /dev/null -w "Status: %{http_code}\n" -A "$USER_AGENT" "$APP_URL"
sleep 1

# Test 2: SQL Injection - UNION SELECT
echo ""
echo "🔴 Test 2: SQL Injection - UNION SELECT (Should Block)"
curl -g -s -o /dev/null -w "Status: %{http_code}\n" -A "$USER_AGENT" -G "$APP_URL" --data-urlencode "id=1 UNION SELECT * FROM users"
sleep 1

# Test 3: SQL Injection - OR 1=1
echo ""
echo "🔴 Test 3: SQL Injection - OR 1=1 (Should Block)"
curl -g -s -o /dev/null -w "Status: %{http_code}\n" -A "$USER_AGENT" -G "$APP_URL" --data-urlencode "username=admin' OR '1'='1"
sleep 1

# Test 4: SQL Injection - Comment
echo ""
echo "🔴 Test 4: SQL Injection - Comment (Should Block)"
curl -g -s -o /dev/null -w "Status: %{http_code}\n" -A "$USER_AGENT" -G "$APP_URL" --data-urlencode "id=1'--"
sleep 1

# Test 5: XSS - Script Tag
echo ""
echo "🔴 Test 5: XSS - Script Tag (Should Block)"
curl -g -s -o /dev/null -w "Status: %{http_code}\n" -A "$USER_AGENT" -G "$APP_URL" --data-urlencode "search=<script>alert('XSS')</script>"
sleep 1

# Test 6: XSS - JavaScript Event
echo ""
echo "🔴 Test 6: XSS - JavaScript Event (Should Block)"
curl -g -s -o /dev/null -w "Status: %{http_code}\n" -A "$USER_AGENT" -G "$APP_URL" --data-urlencode "name=<img src=x onerror=alert('XSS')>"
sleep 1

# Test 7: XSS - Iframe Injection
echo ""
echo "🔴 Test 7: XSS - Iframe Injection (Should Block)"
curl -g -s -o /dev/null -w "Status: %{http_code}\n" -A "$USER_AGENT" -G "$APP_URL" --data-urlencode "data=<iframe src='evil.com'></iframe>"
sleep 1

# Test 8: Path Traversal - Unix
echo ""
echo "🔴 Test 8: Path Traversal - Unix Style (Should Block)"
curl -g -s -o /dev/null -w "Status: %{http_code}\n" -A "$USER_AGENT" "$APP_URL/../../../etc/passwd"
sleep 1

# Test 9: Path Traversal - Windows
echo ""
echo "🔴 Test 9: Path Traversal - Windows Style (Should Block)"
curl -g -s -o /dev/null -w "Status: %{http_code}\n" -A "$USER_AGENT" "$APP_URL/..\\..\\..\\windows\\system32"
sleep 1

# Test 10: Path Traversal - URL Encoded
echo ""
echo "🔴 Test 10: Path Traversal - URL Encoded (Should Block)"
curl -g -s -o /dev/null -w "Status: %{http_code}\n" -A "$USER_AGENT" "$APP_URL/%2e%2e%2f%2e%2e%2f"
sleep 1

# Test 11: Rate Limiting (DDoS Simulation)
echo ""
echo "🔴 Test 11: Rate Limiting / DDoS Simulation (Sending 120 requests rapidly)"
echo "Sending requests in rapid succession..."

# Send requests as fast as possible in background
for i in {1..120}; do
    curl -s -o /dev/null -w "" -A "$USER_AGENT" "$APP_URL" &
done

# Wait for all background curl processes to complete
wait

# Now check if rate limiting kicked in by sending a few more requests
echo "Checking rate limit status..."
for i in {1..5}; do
    status=$(curl -s -o /dev/null -w "%{http_code}" -A "$USER_AGENT" "$APP_URL")
    echo "Status after limit: $status (Should be 429 Too Many Requests)"
done

echo ""
echo "Rate limit test complete!"

# Test 12: Multiple Attack Vectors
echo ""
echo "🔴 Test 12: Combined Attack (Should Block)"
curl -g -s -o /dev/null -w "Status: %{http_code}\n" -A "$USER_AGENT" -G "$APP_URL" --data-urlencode "id=1' OR 1=1--" --data-urlencode "search=<script>alert(1)</script>" --data-urlencode "path=../../etc"
sleep 1

echo ""
echo "================================================"
echo "✅ Testing Complete!"
echo ""
echo "📊 Check the dashboard at http://localhost:3001 to view:"
echo "   - All blocked requests"
echo "   - Threat type distribution"
echo "   - Attack patterns"
echo "   - Rate limit violations"
echo ""
echo "🗄️  Check the SQLite database for detailed logs:"
echo "   sqlite3 firewall/firewall.db 'SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 20;'"
echo ""
#!/bin/bash

# Web Trust Analyzer - Testing Script
# This script demonstrates the firewall's protection capabilities

FIREWALL_URL="http://localhost:8080"
APP_URL="$FIREWALL_URL/app"

echo "🧪 Web Trust Analyzer - Security Testing Script"
echo "================================================"
echo ""
echo "⚠️  WARNING: Only run this against your own firewall for testing!"
echo ""
echo "Testing firewall at: $FIREWALL_URL"
echo ""

# Test 1: Normal Request
echo "✅ Test 1: Normal Request (Should Pass)"
curl -s -o /dev/null -w "Status: %{http_code}\n" "$APP_URL"
sleep 1

# Test 2: SQL Injection - UNION SELECT
echo ""
echo "🔴 Test 2: SQL Injection - UNION SELECT (Should Block)"
curl -s -o /dev/null -w "Status: %{http_code}\n" "$APP_URL?id=1 UNION SELECT * FROM users"
sleep 1

# Test 3: SQL Injection - OR 1=1
echo ""
echo "🔴 Test 3: SQL Injection - OR 1=1 (Should Block)"
curl -s -o /dev/null -w "Status: %{http_code}\n" "$APP_URL?username=admin' OR '1'='1"
sleep 1

# Test 4: SQL Injection - Comment
echo ""
echo "🔴 Test 4: SQL Injection - Comment (Should Block)"
curl -s -o /dev/null -w "Status: %{http_code}\n" "$APP_URL?id=1'--"
sleep 1

# Test 5: XSS - Script Tag
echo ""
echo "🔴 Test 5: XSS - Script Tag (Should Block)"
curl -s -o /dev/null -w "Status: %{http_code}\n" "$APP_URL?search=<script>alert('XSS')</script>"
sleep 1

# Test 6: XSS - JavaScript Event
echo ""
echo "🔴 Test 6: XSS - JavaScript Event (Should Block)"
curl -s -o /dev/null -w "Status: %{http_code}\n" "$APP_URL?name=<img src=x onerror=alert('XSS')>"
sleep 1

# Test 7: XSS - Iframe Injection
echo ""
echo "🔴 Test 7: XSS - Iframe Injection (Should Block)"
curl -s -o /dev/null -w "Status: %{http_code}\n" "$APP_URL?data=<iframe src='evil.com'></iframe>"
sleep 1

# Test 8: Path Traversal - Unix
echo ""
echo "🔴 Test 8: Path Traversal - Unix Style (Should Block)"
curl -s -o /dev/null -w "Status: %{http_code}\n" "$APP_URL/../../../etc/passwd"
sleep 1

# Test 9: Path Traversal - Windows
echo ""
echo "🔴 Test 9: Path Traversal - Windows Style (Should Block)"
curl -s -o /dev/null -w "Status: %{http_code}\n" "$APP_URL/..\\..\\..\\windows\\system32"
sleep 1

# Test 10: Path Traversal - URL Encoded
echo ""
echo "🔴 Test 10: Path Traversal - URL Encoded (Should Block)"
curl -s -o /dev/null -w "Status: %{http_code}\n" "$APP_URL/%2e%2e%2f%2e%2e%2f"
sleep 1

# Test 11: Rate Limiting
echo ""
echo "🔴 Test 11: Rate Limiting (Sending 110 requests - Last 10 should block)"
for i in {1..110}; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "$APP_URL")
    if [ $i -eq 1 ]; then
        echo -n "Sending requests: "
    fi
    if [ $(($i % 10)) -eq 0 ]; then
        echo -n "$i "
    fi
    if [ $i -eq 101 ]; then
        echo ""
        echo "Status at request $i: $status (Should be 429)"
    fi
done
echo ""
echo "Rate limit test complete!"

# Test 12: Multiple Attack Vectors
echo ""
echo "🔴 Test 12: Combined Attack (Should Block)"
curl -s -o /dev/null -w "Status: %{http_code}\n" "$APP_URL?id=1' OR 1=1--&search=<script>alert(1)</script>&path=../../etc"
sleep 1

echo ""
echo "================================================"
echo "✅ Testing Complete!"
echo ""
echo "📊 Check the dashboard at http://localhost:3000 to view:"
echo "   - All blocked requests"
echo "   - Threat type distribution"
echo "   - Attack patterns"
echo "   - Rate limit violations"
echo ""
echo "🗄️  Check the SQLite database for detailed logs:"
echo "   sqlite3 firewall/firewall.db 'SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 20;'"
echo ""
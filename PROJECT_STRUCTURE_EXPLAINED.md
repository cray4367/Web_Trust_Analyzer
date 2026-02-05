# Project Structure & File Responsibilities

This document explains the architecture of the **Web Trust Analyzer** after the "Interactive Firewall" enhancements.

## 📂 Web_Trust_Analyzer (Go Backend)
 The core security engine that acts as a Reverse Proxy, protecting the target application.

### Core Configuration
- **`main.go`**: The entry point. It sets up the HTTP server, initializes the Database, compiles the Firewall rules, and registers all API routes (including the new Attack Simulation routes).
- **`config.go`** (Proposed/Implicit): Holds the `FirewallConfig` struct and default settings (previously in `middleware.go` or `main.go`, cleaning this up makes it modular).
- **`.env`**: Stores sensitive environment variables (not committed to git).

### Firewall Logic
- **`middleware.go`**: The heart of the protection.
  - **`ThreatDetector`**: Intercepts requests, scans them against Regex patterns (XSS, SQLi), and now returns *exact match details*.
  - **`RateLimiter`**: Tracks request counts per IP.
  - **`BotDetector`** (New): Blocks suspicious User-Agents and non-browser clients.
- **`firewall.go` / `models.go`**: Defines the data structures for `SecurityEvent`, `RequestLog`, and `AttackResult`.

### Data Persistence
- **`database.go`**: Manages the SQLite connection. It logs every request and security violation. Updated to store `rule_id` and `match_pattern` for better debugging.
- **`firewall.db`**: The SQLite database file.

### Attack Simulation (New Module)
- **`attacker.go`**: A "Red Team" module running inside the backend.
  - **Why?** Browsers cannot send certain malicious requests (like modified `Host` headers or high-speed floods). This Go module sends them effectively “from the inside” or via loopback to test the proxy.
  - **Functions**: `LaunchSQLiAttack`, `LaunchXSSAttack`, `LaunchFloodAttack`.

### API Handlers
- **`handlers.go`**: The controller layer. It handles requests from the Dashboard (e.g., "Give me the latest logs", "Update config").
- **`attack_handlers.go`** (or merged into `handlers.go`): Handles the `POST /api/attack/simulate` command from the Dashboard.

---

## 📂 React_resume (Dashboard Frontend)
The "Blue Team" control center for monitoring and controlling the firewall.

### UI Components
- **`Dashboard.jsx`**: The main view.
  - **`ThreatTable`**: Shows live logs. Now includes specific "Match Pattern" columns.
  - **`AttackConsole`**: A terminal-like UI that triggers the new Backend Attacks and displays their results.
  - **`StatCards`**: Visual metrics (Events/sec, top attackers).
- **`main.jsx`**: React entry point.

### Infrastructure
- **`vite.config.js`**: Build configuration.
- **`tailwind.config.js`**: Styling configuration.

---

## 🎯 Target Application
- **`../React_resume`** (The Resume Template): The actual application being protected. The Firewall proxies traffic to this app (typically running on port 3000).

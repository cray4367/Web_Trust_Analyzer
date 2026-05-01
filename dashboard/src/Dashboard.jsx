import React, { useState, useEffect, useRef } from 'react';
import { Shield, Activity, AlertTriangle, Lock, Cpu, Eye, Settings, Database, TrendingUp, Users, Filter, RefreshCw, Download, Search, Play, Zap, ShieldOff, ShieldCheck, Terminal } from 'lucide-react';
import { TrustScoreGauge, TrustDistributionChart, TrustProfileCard, TrustStatsCards } from './TrustComponents';

const API_BASE = import.meta.env.VITE_API_URL || '/api';
const ATTACK_TARGET = import.meta.env.VITE_TARGET_URL || '/app';
const WAF_API_KEY = import.meta.env.VITE_WAF_API_KEY || '';

// Shared fetch headers — automatically includes X-API-Key when set
const apiHeaders = (extra = {}) => ({
  'Content-Type': 'application/json',
  ...(WAF_API_KEY ? { 'X-API-Key': WAF_API_KEY } : {}),
  ...extra,
});

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [threats, setThreats] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [isSecure, setIsSecure] = useState(true);
  const [rateLimitConfig, setRateLimitConfig] = useState({ window_seconds: 60, max_requests: 30 });

  // New state for Attack Console
  const [attackLogs, setAttackLogs] = useState([]);
  const consoleEndRef = useRef(null);

  // New state for Trust System
  const [trustStats, setTrustStats] = useState(null);
  const [trustProfiles, setTrustProfiles] = useState([]);
  const [trustDistribution, setTrustDistribution] = useState({});
  const [profileFilter, setProfileFilter] = useState('all');

  const fetchData = async () => {
    try {
      const [statsRes, eventsRes, threatsRes, configRes, trustStatsRes, trustDistRes] = await Promise.all([
        fetch(`${API_BASE}/events/stats`, { headers: apiHeaders() }),  // 1 → statsRes
        fetch(`${API_BASE}/events?limit=20`, { headers: apiHeaders() }),  // 2 → eventsRes
        fetch(`${API_BASE}/monitor/threats`, { headers: apiHeaders() }),  // 3 → threatsRes
        fetch(`${API_BASE}/config`, { headers: apiHeaders() }),  // 4 → configRes
        fetch(`${API_BASE}/trust/stats`, { headers: apiHeaders() }),  // 5 → trustStatsRes
        fetch(`${API_BASE}/trust/distribution`, { headers: apiHeaders() }),  // 6 → trustDistRes
        // ratelimit/status is fetched separately below — keep it out to avoid the off-by-one
      ]);

      if (statsRes.ok) setStats(await statsRes.json());
      if (eventsRes.ok) {
        const eventsData = await eventsRes.json();
        setEvents(eventsData.events || []);
      }
      if (threatsRes.ok) setThreats(await threatsRes.json());
      if (configRes.ok) {
        const config = await configRes.json();
        setIsSecure(config.enable_sqli || config.enable_xss);
      }

      const rateLimitRes = await fetch(`${API_BASE}/ratelimit/status`, { headers: apiHeaders() });
      if (rateLimitRes.ok) {
        const data = await rateLimitRes.json();
        if (data.config) setRateLimitConfig(data.config);
      }

      // Fetch trust data
      if (trustStatsRes.ok) setTrustStats(await trustStatsRes.json());
      if (trustDistRes.ok) {
        const distData = await trustDistRes.json();
        setTrustDistribution(distData.distribution || {});
      }

      setLoading(false);
    } catch (error) {
      console.error('Error fetching data:', error);
      setLoading(false);
    }
  };

  const fetchTrustProfiles = async () => {
    try {
      let endpoint = '/trust/profiles?limit=20';
      if (profileFilter === 'trusted') endpoint = '/trust/top-trusted?limit=20';
      if (profileFilter === 'suspicious') endpoint = '/trust/suspicious?limit=20';

      const res = await fetch(`${API_BASE}${endpoint}`, { headers: apiHeaders() });
      if (res.ok) {
        const data = await res.json();
        setTrustProfiles(data.profiles || []);
      }
    } catch (error) {
      console.error('Error fetching trust profiles:', error);
    }
  };

  useEffect(() => {
    fetchData();
    if (autoRefresh) {
      const interval = setInterval(fetchData, 2000);
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  useEffect(() => {
    if (activeTab === 'trust') {
      fetchTrustProfiles();
    }
  }, [activeTab, profileFilter]);

  // Scroll console to bottom
  useEffect(() => {
    consoleEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [attackLogs]);

  const addLog = (msg, type = 'info') => {
    const time = new Date().toLocaleTimeString();
    setAttackLogs(prev => [...prev, { time, msg, type }]);
  };

  const toggleSecurity = async () => {
    const newState = !isSecure;
    // Optimistic UI update
    setIsSecure(newState);
    addLog(`System security switched to: ${newState ? 'SECURE' : 'UNSECURE'}`, 'system');

    try {
      await fetch(`${API_BASE}/config`, {
        method: 'POST',
        headers: apiHeaders(),
        body: JSON.stringify({
          rate_limit_window: 60,
          rate_limit_max: 100,
          enable_csrf: newState,
          enable_xss: newState,
          enable_sqli: newState,
          enable_path_traversal: newState,
          enable_cmd_injection: newState,
          enable_nosqli: newState,
          enable_lfi: newState,
          enable_ssrf: newState,
          block_suspicious: newState
        })
      });
      setTimeout(fetchData, 500);
    } catch (err) {
      addLog(`Failed to toggle security: ${err.message}`, 'error');
    }
  };

  const launchAttack = async (type) => {
    addLog(`🚀 Launching ${type} simulation...`, 'info');

    try {
      const res = await fetch(`${API_BASE}/attack/simulate`, {
        method: 'POST',
        headers: apiHeaders(),
        body: JSON.stringify({
          type: type,
          intensity: type === 'FLOOD' ? 200 : 1
        })
      });

      const result = await res.json();

      if (result.success) {
        // Log the summary - Red if threats passed, Green if all blocked
        const summaryType = (result.passed_count > 0) ? 'danger' : 'success';
        addLog(result.message, summaryType);

        // Log details line by line
        result.details.forEach(detail => {
          if (detail.includes("BLOCKED")) addLog(detail, 'success');
          else if (detail.includes("PASSED")) addLog(detail, 'danger');
          else if (detail.includes("Allowed")) addLog(detail, 'danger'); // Handle older backend response
          else addLog(detail, 'info');
        });

      } else {
        addLog(`❌ Simulation Failed: ${result.error}`, 'error');
      }

      // Refresh logs
      setTimeout(fetchData, 1000);
    } catch (err) {
      addLog(`❌ Request Failed: ${err.message}`, 'error');
    }
  };

  const updateRateLimit = async (e) => {
    e.preventDefault();
    const windowSeconds = parseInt(e.target.window_seconds.value);
    const maxRequests = parseInt(e.target.max_requests.value);

    try {
      const res = await fetch(`${API_BASE}/ratelimit/config`, {
        method: 'POST',
        headers: apiHeaders(),
        body: JSON.stringify({ window_seconds: windowSeconds, max_requests: maxRequests })
      });

      if (res.ok) {
        addLog(`✅ Rate limit updated: ${maxRequests} reqs / ${windowSeconds}s`, 'success');
        fetchData();
      } else {
        addLog('❌ Failed to update rate limit', 'error');
      }
    } catch (err) {
      addLog(`❌ Error: ${err.message}`, 'error');
    }
  };

  const getSeverityColor = (severity) => {
    const colors = { CRITICAL: '#ff1744', HIGH: '#ff6b35', MEDIUM: '#ffa726', LOW: '#66bb6a' };
    return colors[severity] || '#757575';
  };

  const StatCard = ({ icon: Icon, title, value, trend, color }) => (
    <div className="stat-card" style={{ '--accent-color': color }}>
      <div className="stat-header">
        <Icon size={24} color={color} />
        <span className="stat-trend">{trend}</span>
      </div>
      <div className="stat-body">
        <h3 className="stat-title">{title}</h3>
        <div className="stat-value">{value?.toLocaleString() || 0}</div>
      </div>
      <div className="stat-glow" style={{ background: `radial-gradient(circle at 50% 50%, ${color}20, transparent 70%)` }}></div>
    </div>
  );

  const ThreatTable = () => (
    <div className="threat-table-container">
      <div className="table-header">
        <h3><AlertTriangle size={20} /> Live Security Logs</h3>
        <div className="table-actions">
          <button className="icon-btn" onClick={fetchData}><RefreshCw size={18} /></button>
        </div>
      </div>
      <div className="threat-table">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Type</th>
              <th>Severity</th>
              <th>IP Address</th>
              <th>Payload / Path</th>
              <th>Match Rule</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event, idx) => (
              <tr key={idx} className="table-row">
                <td className="time-cell">{new Date(event.timestamp).toLocaleTimeString()}</td>
                <td><span className="type-badge">{event.type?.replace(/_/g, ' ')}</span></td>
                <td>
                  <span className="severity-badge" style={{
                    background: `${getSeverityColor(event.severity)}20`,
                    color: getSeverityColor(event.severity),
                    border: `1px solid ${getSeverityColor(event.severity)}40`
                  }}>
                    {event.severity}
                  </span>
                </td>
                <td className="ip-cell">{event.ip}</td>
                <td className="path-cell" title={event.payload || event.path}>
                  {event.payload ? event.payload.substring(0, 40) : event.path}
                </td>
                <td className="rule-cell">
                  {event.match_pattern ? (
                    <span className="code-badge">{event.match_pattern.substring(0, 30)}</span>
                  ) : <span className="text-muted">-</span>}
                </td>
                <td>
                  <span className={`block-status ${event.status === 'PASSED' ? 'status-passed' : 'status-blocked'}`}>
                    {event.status || 'BLOCKED'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  const AttackConsole = () => (
    <div className="console-container">
      <div className="console-header">
        <Terminal size={16} /> <span>ATTACK CONSOLE</span>
      </div>
      <div className="console-body">
        {attackLogs.length === 0 && <div className="console-placeholder">Ready to launch attacks...</div>}
        {attackLogs.map((log, i) => (
          <div key={i} className={`console-line ${log.type}`}>
            <span className="console-time">[{log.time}]</span>
            <span className="console-msg">{log.msg}</span>
          </div>
        ))}
        <div ref={consoleEndRef} />
      </div>
    </div>
  );

  const OWASPChecks = () => {
    const attacks = [
      { id: 1, name: "SQL Injection", type: "SQL_INJECTION", desc: "Injects malicious SQL query" },
      { id: 2, name: "Cross-Site Scripting", type: "XSS", desc: "Injects malicious scripts" },
      { id: 3, name: "Path Traversal", type: "PATH_TRAVERSAL", desc: "Access unauthorized files" },
      { id: 4, name: "Command Injection", type: "CMD_INJECTION", desc: "Executes system commands" },
      { id: 5, name: "NoSQL Injection", type: "NOSQL_INJECTION", desc: "NoSQL DB operator bypass" },
      { id: 6, name: "Local File Inclusion", type: "LFI", desc: "Access local server files" },
      { id: 7, name: "Server-Side Request Forgery", type: "SSRF", desc: "Internal port scanning" },
      { id: 8, name: "Botnet Attack", type: "BOT", desc: "Simulates suspicious User-Agents" },
      { id: 9, name: "DDoS Simulation", type: "FLOOD", desc: "High concurrency request flood" },
    ];

    return (
      <div className="attack-layout">
        <div className="owasp-container">
          <div className="owasp-header">
            <h3><Zap size={20} /> Attack Simulation Lab</h3>
            <p style={{ color: '#94a3b8', fontSize: '0.9rem' }}>Launch live attacks against your own system.</p>
          </div>
          <div className="owasp-grid">
            {attacks.map((attack) => (
              <div key={attack.id} className="owasp-card">
                <div className="owasp-top">
                  <div className="owasp-number">0{attack.id}</div>
                  <div className="owasp-status active"><div className="status-dot"></div> Ready</div>
                </div>
                <div className="owasp-name">{attack.name}</div>
                <div className="owasp-desc">{attack.desc}</div>
                <button className="attack-btn" onClick={() => launchAttack(attack.type)}>
                  <Play size={14} fill="currentColor" /> LAUNCH ATTACK
                </button>
              </div>
            ))}
          </div>
        </div>

        <AttackConsole />
      </div>
    );
  };


  const SettingsPanel = () => (
    <div className="settings-panel">
      <div className="settings-header">
        <h3><Settings size={20} /> Firewall Configuration</h3>
        <p>Adjust the security sensitivity and thresholds.</p>
      </div>

      <div className="settings-card">
        <h4>Rate Limiting Strategy</h4>
        <p className="settings-desc">Define the threshold for the DDoS protection system.</p>

        <form onSubmit={updateRateLimit} className="settings-form">
          <div className="form-group">
            <label>Window Duration (Seconds)</label>
            <input type="number" name="window_seconds" defaultValue={rateLimitConfig.window_seconds} min="1" required />
            <span className="form-hint">Time window to track requests</span>
          </div>
          <div className="form-group">
            <label>Max Requests per Window</label>
            <input type="number" name="max_requests" defaultValue={rateLimitConfig.max_requests} min="1" required />
            <span className="form-hint">Requests allowed before blocking IP</span>
          </div>
          <button type="submit" className="save-btn">SAVE PARAMETERS</button>
        </form>
      </div>
    </div>
  );

  const ThreatAnalysis = () => {
    if (!threats) return null;
    const typeData = Object.entries(threats.events_by_type || {});
    const maxCount = Math.max(...typeData.map(([_, count]) => count), 1);

    return (
      <div className="threat-analysis">
        <h3><TrendingUp size={20} /> Threat Distribution</h3>
        <div className="threat-bars">
          {typeData.map(([type, count]) => (
            <div key={type} className="threat-bar-item">
              <div className="threat-bar-label">
                <span>{type.replace(/_/g, ' ')}</span>
                <span className="threat-count">{count}</span>
              </div>
              <div className="threat-bar-track">
                <div className="threat-bar-fill" style={{ width: `${(count / maxCount) * 100}%`, background: `linear-gradient(90deg, #00f5ff, #0080ff)` }}></div>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  if (loading) return <div className="loading-container"><div className="loader"></div><p>Initializing Security Systems...</p></div>;

  return (
    <div className="dashboard">
      <div className="bg-grid"></div>
      <div className="bg-gradient"></div>

      <header className="header">
        <div className="header-left">
          <Shield className="logo-icon" size={32} />
          <div className="header-title"><h1>WEB TRUST ANALYZER</h1><p>Advanced Firewall Protection System</p></div>
        </div>
        <div className="header-right">
          <button className={`secure-toggle ${isSecure ? 'secure' : 'unsecure'}`} onClick={toggleSecurity}>
            {isSecure ? <ShieldCheck size={20} /> : <ShieldOff size={20} />}
            <span>{isSecure ? 'SYSTEM SECURE' : 'PROTECTION OFF'}</span>
          </button>
          <button className={`refresh-btn ${autoRefresh ? 'active' : ''}`} onClick={() => setAutoRefresh(!autoRefresh)}>
            <RefreshCw size={18} className={autoRefresh ? 'spinning' : ''} /> Live Logs
          </button>
        </div>
      </header>

      <nav className="nav-tabs">
        {['overview', 'logs', 'trust', 'attack lab', 'settings'].map(tab => (
          <button key={tab} className={`nav-tab ${activeTab === tab ? 'active' : ''}`} onClick={() => setActiveTab(tab)}>
            {tab.toUpperCase()}
          </button>
        ))}
      </nav>

      <main className="main-content">
        {activeTab === 'overview' && (
          <>
            <div className="stats-grid">
              <StatCard icon={AlertTriangle} title="Total Events" value={stats?.total_events} trend="All time" color="#ff1744" />
              <StatCard icon={Activity} title="Events (24h)" value={stats?.events_last_24h} trend="Last 24 hours" color="#00f5ff" />
              <StatCard icon={Lock} title="Blocked Requests" value={stats?.blocked_requests} trend="Rate limited" color="#ffa726" />
              <StatCard icon={Users} title="Unique Attackers" value={stats?.top_attackers?.length} trend="Tracked IPs" color="#66bb6a" />
            </div>
            <div className="charts-grid">
              <div className="chart-card">
                <h3><Cpu size={20} /> System Status</h3>
                <div className="system-status-indicator">
                  <div className={`status-big-icon ${isSecure ? 'safe' : 'danger'}`}>
                    {isSecure ? <ShieldCheck size={64} /> : <ShieldOff size={64} />}
                  </div>
                  <h2>{isSecure ? "Firewall Active" : "Firewall Disabled"}</h2>
                  <p>{isSecure ? "All systems operational. Threats are being blocked." : "WARNING: Protection is disabled. Application is vulnerable."}</p>
                </div>
              </div>
              <ThreatAnalysis />
            </div>
            <ThreatTable />
          </>
        )}

        {activeTab === 'logs' && <ThreatTable />}

        {activeTab === 'trust' && (
          <>
            <TrustStatsCards trustStats={trustStats} />

            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem', marginTop: '2rem' }}>
              <div className="trust-profiles-container">
                <div className="trust-header">
                  <h3><Users size={20} /> User Trust Profiles</h3>
                  <div className="trust-filters">
                    <button
                      className={profileFilter === 'all' ? 'filter-active' : ''}
                      onClick={() => setProfileFilter('all')}
                    >
                      All
                    </button>
                    <button
                      className={profileFilter === 'trusted' ? 'filter-active' : ''}
                      onClick={() => setProfileFilter('trusted')}
                    >
                      Trusted
                    </button>
                    <button
                      className={profileFilter === 'suspicious' ? 'filter-active' : ''}
                      onClick={() => setProfileFilter('suspicious')}
                    >
                      Suspicious
                    </button>
                  </div>
                </div>

                <div className="trust-profiles-grid">
                  {trustProfiles.length === 0 ? (
                    <div style={{ textAlign: 'center', padding: '3rem', color: '#64748b' }}>
                      No trust profiles found. Profiles will appear as requests are processed.
                    </div>
                  ) : (
                    trustProfiles.map(profile => (
                      <TrustProfileCard key={profile.ip} profile={profile} />
                    ))
                  )}
                </div>
              </div>

              <div>
                <TrustDistributionChart distribution={trustDistribution} />
              </div>
            </div>
          </>
        )}

        {activeTab === 'attack lab' && <OWASPChecks />}
        {activeTab === 'settings' && <SettingsPanel />}
      </main>

      <style jsx>{`
        /* CONSOLE STYLES */
        .attack-layout { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; height: 500px; }
        .console-container { background: #0f172a; border-radius: 12px; border: 1px solid #334155; display: flex; flex-direction: column; overflow: hidden; font-family: 'Fira Code', monospace; font-size: 0.85rem; }
        .console-header { background: #1e293b; padding: 0.75rem 1rem; border-bottom: 1px solid #334155; display: flex; align-items: center; gap: 0.5rem; font-weight: bold; color: #94a3b8; letter-spacing: 1px; }
        .console-body { padding: 1rem; overflow-y: auto; flex: 1; display: flex; flex-direction: column; gap: 0.5rem; }
        .console-line { display: flex; gap: 0.75rem; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.25rem; }
        .console-time { color: #64748b; min-width: 85px; }
        .console-msg { word-break: break-all; }
        .console-line.info .console-msg { color: #e2e8f0; }
        .console-line.code .console-msg { color: #00f5ff; }
        .console-line.success .console-msg { color: #4ade80; font-weight: bold; }
        .console-line.danger .console-msg { color: #f87171; font-weight: bold; }
        .console-line.error .console-msg { color: #fca5a5; }
        .console-line.system .console-msg { color: #fbbf24; }
        .console-placeholder { color: #475569; font-style: italic; text-align: center; margin-top: 2rem; }

        /* SETTINGS STYLES */
        .settings-panel { padding: 2rem; background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(10px); border: 1px solid rgba(0, 245, 255, 0.2); border-radius: 16px; max-width: 800px; margin: 0 auto; }
        .settings-header { margin-bottom: 2rem; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 1rem; }
        .settings-header h3 { display: flex; align-items: center; gap: 0.75rem; color: #00f5ff; margin-bottom: 0.5rem; }
        .settings-header p { color: #94a3b8; font-size: 0.9rem; }
        .settings-card { background: rgba(0,0,0,0.2); padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.05); }
        .settings-card h4 { color: #e0e7ff; margin-bottom: 0.5rem; }
        .settings-desc { color: #64748b; font-size: 0.85rem; margin-bottom: 1.5rem; }
        .settings-form { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; align-items: end; }
        .form-group { display: flex; flex-direction: column; gap: 0.5rem; }
        .form-group label { font-size: 0.8rem; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; }
        .form-group input { background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(0, 245, 255, 0.2); padding: 0.75rem; border-radius: 6px; color: #fff; font-family: inherit; transition: all 0.3s ease; }
        .form-group input:focus { outline: none; border-color: #00f5ff; box-shadow: 0 0 10px rgba(0, 245, 255, 0.2); }
        .form-hint { font-size: 0.75rem; color: #64748b; }
        .save-btn { grid-column: 1 / -1; padding: 0.75rem; background: #00f5ff; color: #000; border: none; border-radius: 6px; font-weight: 700; cursor: pointer; transition: all 0.3s ease; margin-top: 1rem; }
        .save-btn:hover { background: #fff; box-shadow: 0 0 20px rgba(0, 245, 255, 0.5); }

        /* Existing Styles */
        .secure-toggle { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 700; cursor: pointer; transition: all 0.3s ease; border: none; }
        .secure-toggle.secure { background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; box-shadow: 0 0 15px rgba(16, 185, 129, 0.3); }
        .secure-toggle.unsecure { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; box-shadow: 0 0 15px rgba(239, 68, 68, 0.3); animation: pulse-red 2s infinite; }
        @keyframes pulse-red { 0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); } 70% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); } 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); } }
        .attack-btn { width: 100%; padding: 0.75rem; background: #ef4444; color: white; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 0.5rem; transition: all 0.2s; }
        .attack-btn:hover { background: #dc2626; transform: translateY(-2px); box-shadow: 0 4px 12px rgba(239, 68, 68, 0.4); }
        .block-status { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: bold; text-transform: uppercase; }
        .block-status.status-blocked { background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); } 
        .block-status.status-passed { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); animation: pulse-red 2s infinite; }
        .system-status-indicator { display: flex; flex-direction: column; align-items: center; text-align: center; padding: 2rem; gap: 1rem; }
        .status-big-icon.safe { color: #10b981; filter: drop-shadow(0 0 10px rgba(16,185,129,0.5)); }
        .status-big-icon.danger { color: #ef4444; filter: drop-shadow(0 0 10px rgba(239,68,68,0.5)); }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        .dashboard { min-height: 100vh; background: #0a0e27; color: #e0e7ff; font-family: 'JetBrains Mono', monospace; position: relative; overflow-x: hidden; }
        .bg-grid { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-image: linear-gradient(rgba(0, 245, 255, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 245, 255, 0.03) 1px, transparent 1px); background-size: 50px 50px; animation: gridMove 20s linear infinite; z-index: 0; }
        .bg-gradient { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: radial-gradient(circle at 20% 50%, rgba(0, 128, 255, 0.1) 0%, transparent 50%), radial-gradient(circle at 80% 80%, rgba(255, 23, 68, 0.1) 0%, transparent 50%); z-index: 0; animation: gradientShift 15s ease infinite; }
        @keyframes gridMove { 0% { transform: translateY(0); } 100% { transform: translateY(50px); } }
        @keyframes gradientShift { 0%, 100% { opacity: 0.5; } 50% { opacity: 0.8; } }
        .header { position: relative; z-index: 10; display: flex; justify-content: space-between; align-items: center; padding: 2rem 3rem; background: rgba(10, 14, 39, 0.8); backdrop-filter: blur(20px); border-bottom: 1px solid rgba(0, 245, 255, 0.2); }
        .header-left { display: flex; align-items: center; gap: 1.5rem; }
        .logo-icon { color: #00f5ff; filter: drop-shadow(0 0 10px rgba(0, 245, 255, 0.5)); animation: pulse 2s ease-in-out infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
        .header-title h1 { font-size: 1.5rem; font-weight: 700; letter-spacing: 2px; background: linear-gradient(135deg, #00f5ff, #0080ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; text-shadow: 0 0 20px rgba(0, 245, 255, 0.3); }
        .header-title p { font-size: 0.75rem; color: #64748b; margin-top: 0.25rem; letter-spacing: 1px; }
        .header-right { display: flex; gap: 1rem; }
        .refresh-btn { display: flex; align-items: center; gap: 0.5rem; padding: 0.75rem 1.5rem; background: rgba(0, 245, 255, 0.1); border: 1px solid rgba(0, 245, 255, 0.3); color: #00f5ff; border-radius: 8px; cursor: pointer; transition: all 0.3s ease; font-family: inherit; font-size: 0.875rem; }
        .refresh-btn.active { background: rgba(0, 245, 255, 0.2); box-shadow: 0 0 20px rgba(0, 245, 255, 0.3); }
        .refresh-btn:hover { background: rgba(0, 245, 255, 0.2); transform: translateY(-2px); }
        .spinning { animation: spin 1s linear infinite; }
        @keyframes spin { 100% { transform: rotate(360deg); } }
        .nav-tabs { position: relative; z-index: 10; display: flex; gap: 1rem; padding: 0 3rem; background: rgba(10, 14, 39, 0.6); backdrop-filter: blur(10px); border-bottom: 1px solid rgba(0, 245, 255, 0.1); }
        .nav-tab { padding: 1rem 2rem; background: transparent; border: none; color: #64748b; cursor: pointer; font-family: inherit; font-size: 0.875rem; font-weight: 500; letter-spacing: 1px; text-transform: uppercase; transition: all 0.3s ease; position: relative; }
        .nav-tab::after { content: ''; position: absolute; bottom: 0; left: 0; width: 100%; height: 2px; background: linear-gradient(90deg, #00f5ff, #0080ff); transform: scaleX(0); transition: transform 0.3s ease; }
        .nav-tab.active { color: #00f5ff; }
        .nav-tab.active::after { transform: scaleX(1); }
        .nav-tab:hover { color: #00f5ff; }
        .main-content { position: relative; z-index: 10; padding: 3rem; max-width: 1800px; margin: 0 auto; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; margin-bottom: 3rem; }
        .stat-card { position: relative; padding: 2rem; background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(10px); border: 1px solid rgba(0, 245, 255, 0.2); border-radius: 16px; overflow: hidden; transition: all 0.3s ease; }
        .stat-card:hover { transform: translateY(-4px); border-color: var(--accent-color); box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); }
        .stat-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
        .stat-trend { font-size: 0.75rem; color: #64748b; }
        .stat-title { font-size: 0.875rem; color: #94a3b8; margin-bottom: 0.75rem; letter-spacing: 0.5px; }
        .stat-value { font-size: 2.5rem; font-weight: 700; background: linear-gradient(135deg, var(--accent-color), #fff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .stat-glow { position: absolute; top: 50%; left: 50%; width: 200%; height: 200%; transform: translate(-50%, -50%); pointer-events: none; opacity: 0.5; }
        .charts-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 1.5rem; margin-bottom: 3rem; }
        .chart-card { padding: 2rem; background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(10px); border: 1px solid rgba(0, 245, 255, 0.2); border-radius: 16px; }
        .chart-card h3 { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1.5rem; font-size: 1rem; color: #e0e7ff; }
        .threat-analysis { padding: 2rem; background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(10px); border: 1px solid rgba(0, 245, 255, 0.2); border-radius: 16px; }
        .threat-analysis h3 { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1.5rem; }
        .threat-bars { display: flex; flex-direction: column; gap: 1.25rem; }
        .threat-bar-item { display: flex; flex-direction: column; gap: 0.5rem; }
        .threat-bar-label { display: flex; justify-content: space-between; font-size: 0.875rem; color: #94a3b8; }
        .threat-count { color: #00f5ff; font-weight: 600; }
        .threat-bar-track { height: 8px; background: rgba(0, 0, 0, 0.5); border-radius: 4px; overflow: hidden; }
        .threat-bar-fill { height: 100%; border-radius: 4px; transition: width 1s ease; box-shadow: 0 0 10px rgba(0, 245, 255, 0.5); }
        .threat-table-container { background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(10px); border: 1px solid rgba(0, 245, 255, 0.2); border-radius: 16px; overflow: hidden; }
        .table-header { display: flex; justify-content: space-between; align-items: center; padding: 1.5rem 2rem; border-bottom: 1px solid rgba(0, 245, 255, 0.1); }
        .table-header h3 { display: flex; align-items: center; gap: 0.75rem; font-size: 1rem; }
        .table-actions { display: flex; gap: 0.5rem; }
        .icon-btn { padding: 0.5rem; background: rgba(0, 245, 255, 0.1); border: 1px solid rgba(0, 245, 255, 0.3); border-radius: 8px; color: #00f5ff; cursor: pointer; transition: all 0.3s ease; }
        .icon-btn:hover { background: rgba(0, 245, 255, 0.2); }
        .threat-table { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        thead { background: rgba(0, 0, 0, 0.3); }
        th { padding: 1rem 1.5rem; text-align: left; font-size: 0.75rem; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 1px; }
        .table-row { border-bottom: 1px solid rgba(255, 255, 255, 0.05); transition: all 0.3s ease; }
        .table-row:hover { background: rgba(0, 245, 255, 0.05); }
        td { padding: 1rem 1.5rem; font-size: 0.875rem; }
        .time-cell { color: #64748b; font-size: 0.8125rem; }
        .type-badge { display: inline-block; padding: 0.25rem 0.75rem; background: rgba(0, 128, 255, 0.2); color: #0080ff; border-radius: 6px; font-size: 0.75rem; font-weight: 500; text-transform: capitalize; }
        .severity-badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 6px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .ip-cell { font-family: 'Courier New', monospace; color: #00f5ff; }
        .rule-cell { font-family: 'Courier New', monospace; color: #f59e0b; font-size: 0.75rem; }
        .code-badge { background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.1); }
        .text-muted { color: #64748b; }
        .path-cell { color: #94a3b8; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .owasp-container { background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(10px); border: 1px solid rgba(0, 245, 255, 0.2); border-radius: 16px; padding: 2rem; }
        .owasp-header h3 { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }
        .owasp-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 1rem; margin-top: 1.5rem; }
        .owasp-card { padding: 1.5rem; background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; transition: all 0.3s ease; }
        .owasp-card:hover { transform: translateY(-2px); border-color: #00f5ff; }
        .owasp-number { font-size: 2rem; font-weight: 700; background: linear-gradient(135deg, #00f5ff, #0080ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .owasp-name { font-size: 1rem; color: #e0e7ff; margin-bottom: 0.5rem; font-weight: bold; }
        .owasp-desc { font-size: 0.8rem; color: #64748b; margin-bottom: 1rem; }
        .owasp-status { display: flex; align-items: center; gap: 0.5rem; font-size: 0.75rem; color: #64748b; text-transform: uppercase; }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; background: #66bb6a; box-shadow: 0 0 8px #66bb6a; animation: blink 2s ease-in-out infinite; }
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .loading-container { display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; gap: 2rem; }
        .loader { width: 64px; height: 64px; border: 4px solid rgba(0, 245, 255, 0.2); border-top-color: #00f5ff; border-radius: 50%; animation: spin 1s linear infinite; }
        
        /* TRUST COMPONENT STYLES */
        .trust-stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
        .trust-stat-card { padding: 1.5rem; background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(10px); border: 1px solid rgba(0, 245, 255, 0.2); border-radius: 12px; display: flex; flex-direction: column; align-items: center; gap: 0.75rem; transition: all 0.3s ease; }
        .trust-stat-card:hover { transform: translateY(-4px); border-color: var(--accent-color); box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); }
        .trust-stat-card .stat-value { font-size: 2rem; font-weight: 700; background: linear-gradient(135deg, var(--accent-color), #fff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .trust-stat-card .stat-label { font-size: 0.875rem; color: #94a3b8; text-align: center; }
        
        .trust-profiles-container { background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(10px); border: 1px solid rgba(0, 245, 255, 0.2); border-radius: 16px; padding: 2rem; }
        .trust-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
        .trust-header h3 { display: flex; align-items: center; gap: 0.75rem; color: #e0e7ff; margin: 0; }
        .trust-filters { display: flex; gap: 0.5rem; }
        .trust-filters button { padding: 0.5rem 1rem; background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 6px; color: #94a3b8; cursor: pointer; transition: all 0.3s ease; font-family: inherit; font-size: 0.875rem; }
        .trust-filters button:hover { background: rgba(0, 245, 255, 0.1); border-color: rgba(0, 245, 255, 0.3); color: #00f5ff; }
        .trust-filters button.filter-active { background: rgba(0, 245, 255, 0.2); border-color: #00f5ff; color: #00f5ff; }
        
        .trust-profiles-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1.5rem; }
        .trust-profile-card { padding: 1.5rem; background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; transition: all 0.3s ease; }
        .trust-profile-card:hover { transform: translateY(-2px); border-color: #00f5ff; box-shadow: 0 4px 16px rgba(0, 245, 255, 0.2); }
        .profile-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
        .profile-ip { font-family: 'Courier New', monospace; color: #00f5ff; font-weight: 600; }
        .trust-badge { padding: 0.25rem 0.75rem; border-radius: 6px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
        .profile-stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-top: 1rem; padding-top: 1rem; border-top: 1px solid rgba(255, 255, 255, 0.1); }
        .profile-stats .stat { display: flex; flex-direction: column; align-items: center; gap: 0.25rem; }
        .profile-stats .stat-label { font-size: 0.75rem; color: #64748b; }
        .profile-stats .stat-value { font-size: 1.25rem; font-weight: 700; color: #e0e7ff; }
        .profile-timeline { margin-top: 1rem; padding-top: 1rem; border-top: 1px solid rgba(255, 255, 255, 0.1); }
        
        .trust-distribution { padding: 2rem; background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(10px); border: 1px solid rgba(0, 245, 255, 0.2); border-radius: 16px; }
        .distribution-bars { display: flex; flex-direction: column; gap: 1.25rem; }
        .distribution-item { display: flex; flex-direction: column; gap: 0.5rem; }
        .distribution-label { display: flex; justify-content: space-between; font-size: 0.875rem; color: #94a3b8; }
        .distribution-count { color: #00f5ff; font-weight: 600; }
        .distribution-bar-track { height: 8px; background: rgba(0, 0, 0, 0.5); border-radius: 4px; overflow: hidden; }
        .distribution-bar-fill { height: 100%; border-radius: 4px; box-shadow: 0 0 10px rgba(0, 245, 255, 0.5); }
        .distribution-percentage { font-size: 0.75rem; color: #64748b; text-align: right; }
        
        .trust-gauge { width: 100%; max-width: 200px; margin: 0 auto; }
      `}</style>
    </div>
  );
};

export default Dashboard;
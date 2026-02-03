import React, { useState, useEffect, useRef } from 'react';
import { Shield, Activity, AlertTriangle, Lock, Cpu, Eye, Settings, Database, TrendingUp, Users, Filter, RefreshCw, Download, Search, Play, Zap, ShieldOff, ShieldCheck, Terminal } from 'lucide-react';

const API_BASE = 'http://localhost:8080/api';
const ATTACK_TARGET = 'http://localhost:8080/app';


const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [threats, setThreats] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [isSecure, setIsSecure] = useState(true);
  
  // New state for Attack Console
  const [attackLogs, setAttackLogs] = useState([]);
  const consoleEndRef = useRef(null);

  const fetchData = async () => {
    try {
      const [statsRes, eventsRes, threatsRes, configRes] = await Promise.all([
        fetch(`${API_BASE}/events/stats`),
        fetch(`${API_BASE}/events?limit=20`),
        fetch(`${API_BASE}/monitor/threats`),
        fetch(`${API_BASE}/config`)
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
      
      setLoading(false);
    } catch (error) {
      console.error('Error fetching data:', error);
      // Don't stop loading on error, just log it, helps prevent UI freezing
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    if (autoRefresh) {
      const interval = setInterval(fetchData, 2000);
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

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
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rate_limit_window: 60,
          rate_limit_max: 100,
          enable_csrf: newState,
          enable_xss: newState,
          enable_sqli: newState,
          enable_path_traversal: newState,
          block_suspicious: newState
        })
      });
      setTimeout(fetchData, 500); 
    } catch (err) {
      addLog(`Failed to toggle security: ${err.message}`, 'error');
    }
  };

  const launchAttack = async (type) => {
    let url = ATTACK_TARGET;
    let payload = "";

    switch(type) {
      case 'SQL_INJECTION':
        payload = "?id=1' OR '1'='1";
        url += payload;
        break;
      case 'XSS':
        payload = "?search=<script>alert('XSS')</script>";
        url += payload;
        break;
      case 'PATH_TRAVERSAL':
        payload = "?file=../../etc/passwd";
        url += payload;
        break;
      default:
        payload = "/normal";
        url += payload;
    }

    addLog(`🚀 Launching ${type} attack...`, 'info');
    addLog(`📡 Sending payload: ${payload}`, 'code');

    try {
      const res = await fetch(url);
      
      if (res.status === 403 || res.status === 400) {
        addLog(`🛡️ BLOCKED! Server responded with ${res.status} Forbidden`, 'success');
      } else if (res.status === 200) {
        addLog(`⚠️ PASSED! Server responded with 200 OK (Vulnerability Exposed)`, 'danger');
      } else {
        addLog(`ℹ️ Server responded with ${res.status}`, 'info');
      }
      
      // Refresh logs immediately to show the block in the table
      setTimeout(fetchData, 500);
    } catch (err) {
      addLog(`❌ Request Failed: ${err.message}`, 'error');
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
                <td><span className="block-status">BLOCKED</span></td>
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
    ];

    return (
      <div className="attack-layout">
          <div className="owasp-container">
            <div className="owasp-header">
              <h3><Zap size={20} /> Attack Simulation Lab</h3>
              <p style={{color: '#94a3b8', fontSize: '0.9rem'}}>Launch live attacks against your own system.</p>
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
        {['overview', 'logs', 'attack lab'].map(tab => (
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
        {activeTab === 'attack lab' && <OWASPChecks />}
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

        /* Existing Styles */
        .secure-toggle { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 700; cursor: pointer; transition: all 0.3s ease; border: none; }
        .secure-toggle.secure { background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; box-shadow: 0 0 15px rgba(16, 185, 129, 0.3); }
        .secure-toggle.unsecure { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; box-shadow: 0 0 15px rgba(239, 68, 68, 0.3); animation: pulse-red 2s infinite; }
        @keyframes pulse-red { 0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); } 70% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); } 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); } }
        .attack-btn { width: 100%; padding: 0.75rem; background: #ef4444; color: white; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 0.5rem; transition: all 0.2s; }
        .attack-btn:hover { background: #dc2626; transform: translateY(-2px); box-shadow: 0 4px 12px rgba(239, 68, 68, 0.4); }
        .block-status { background: rgba(239, 68, 68, 0.2); color: #ef4444; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: bold; }
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
        .path-cell { color: #94a3b8; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .owasp-container { background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(10px); border: 1px solid rgba(0, 245, 255, 0.2); border-radius: 16px; padding: 2rem; }
        .owasp-header h3 { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }
        .owasp-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 1rem; margin-top: 1.5rem; }
        .owasp-card { padding: 1.5rem; background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; transition: all 0.3s ease; }
        .owasp-card:hover { transform: translateY(-2px); border-color: #00f5ff; }
        .owasp-number { font-size: 2rem; font-weight: 700; background: linear-gradient(135deg, #00f5ff, #0080ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .owasp-name { font-size: 1rem; color: #e0e7ff; margin-bottom: 0.5rem; font-weight: bold; }
        .owasp-status { display: flex; align-items: center; gap: 0.5rem; font-size: 0.75rem; color: #64748b; text-transform: uppercase; }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; background: #66bb6a; box-shadow: 0 0 8px #66bb6a; animation: blink 2s ease-in-out infinite; }
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .loading-container { display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; gap: 2rem; }
        .loader { width: 64px; height: 64px; border: 4px solid rgba(0, 245, 255, 0.2); border-top-color: #00f5ff; border-radius: 50%; animation: spin 1s linear infinite; }
      `}</style>
    </div>
  );
};

export default Dashboard;
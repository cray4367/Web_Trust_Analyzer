import React, { useState, useEffect } from 'react';
import { Shield, Activity, AlertTriangle, Lock, Cpu, Eye, Settings, Database, TrendingUp, Users, Filter, RefreshCw, Download, Search } from 'lucide-react';

const API_BASE = 'http://localhost:8080/api';

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [threats, setThreats] = useState(null);
  const [owaspStatus, setOwaspStatus] = useState([]);
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchData = async () => {
    try {
      const [statsRes, eventsRes, threatsRes, owaspRes] = await Promise.all([
        fetch(`${API_BASE}/events/stats`),
        fetch(`${API_BASE}/events?limit=20`),
        fetch(`${API_BASE}/monitor/threats`),
        fetch(`${API_BASE}/owasp/status`)
      ]);

      setStats(await statsRes.json());
      const eventsData = await eventsRes.json();
      setEvents(eventsData.events || []);
      setThreats(await threatsRes.json());
      const owaspData = await owaspRes.json();
      setOwaspStatus(owaspData.checks || []);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching data:', error);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    if (autoRefresh) {
      const interval = setInterval(fetchData, 5000);
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  const getSeverityColor = (severity) => {
    const colors = {
      CRITICAL: '#ff1744',
      HIGH: '#ff6b35',
      MEDIUM: '#ffa726',
      LOW: '#66bb6a'
    };
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
        <h3><AlertTriangle size={20} /> Recent Security Events</h3>
        <div className="table-actions">
          <button className="icon-btn"><Search size={18} /></button>
          <button className="icon-btn"><Filter size={18} /></button>
          <button className="icon-btn"><Download size={18} /></button>
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
              <th>Path</th>
              <th>Details</th>
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
                <td className="path-cell">{event.path}</td>
                <td className="details-cell">{event.details?.substring(0, 50)}...</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  const OWASPChecks = () => (
    <div className="owasp-container">
      <div className="owasp-header">
        <h3><Shield size={20} /> OWASP Top 10 Protection Status</h3>
      </div>
      <div className="owasp-grid">
        {owaspStatus.map((check) => (
          <div key={check.id} className={`owasp-card ${check.enabled ? 'enabled' : 'disabled'}`}>
            <div className="owasp-number">#{check.id}</div>
            <div className="owasp-name">{check.name}</div>
            <div className={`owasp-status ${check.status}`}>
              <div className="status-dot"></div>
              {check.status.replace(/_/g, ' ')}
            </div>
          </div>
        ))}
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
                <div 
                  className="threat-bar-fill" 
                  style={{ 
                    width: `${(count / maxCount) * 100}%`,
                    background: `linear-gradient(90deg, #00f5ff, #0080ff)`
                  }}
                ></div>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  if (loading) {
    return (
      <div className="loading-container">
        <div className="loader"></div>
        <p>Initializing Security Systems...</p>
      </div>
    );
  }

  return (
    <div className="dashboard">
      {/* Animated background */}
      <div className="bg-grid"></div>
      <div className="bg-gradient"></div>
      
      {/* Header */}
      <header className="header">
        <div className="header-left">
          <Shield className="logo-icon" size={32} />
          <div className="header-title">
            <h1>WEB TRUST ANALYZER</h1>
            <p>Advanced Firewall Protection System</p>
          </div>
        </div>
        <div className="header-right">
          <button 
            className={`refresh-btn ${autoRefresh ? 'active' : ''}`}
            onClick={() => setAutoRefresh(!autoRefresh)}
          >
            <RefreshCw size={18} className={autoRefresh ? 'spinning' : ''} />
            Auto-Refresh
          </button>
          <button className="settings-btn">
            <Settings size={20} />
          </button>
        </div>
      </header>

      {/* Navigation */}
      <nav className="nav-tabs">
        {['overview', 'threats', 'owasp', 'settings'].map(tab => (
          <button
            key={tab}
            className={`nav-tab ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setActiveTab(tab)}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </nav>

      {/* Main Content */}
      <main className="main-content">
        {activeTab === 'overview' && (
          <>
            {/* Stats Grid */}
            <div className="stats-grid">
              <StatCard
                icon={AlertTriangle}
                title="Total Events"
                value={stats?.total_events}
                trend="+12% from last hour"
                color="#ff1744"
              />
              <StatCard
                icon={Activity}
                title="Events (24h)"
                value={stats?.events_last_24h}
                trend="Last 24 hours"
                color="#00f5ff"
              />
              <StatCard
                icon={Lock}
                title="Blocked Requests"
                value={stats?.blocked_requests}
                trend="Rate limited"
                color="#ffa726"
              />
              <StatCard
                icon={Users}
                title="Unique Attackers"
                value={stats?.top_attackers?.length}
                trend="Tracked IPs"
                color="#66bb6a"
              />
            </div>

            {/* Charts Section */}
            <div className="charts-grid">
              <div className="chart-card">
                <h3><Cpu size={20} /> Severity Distribution</h3>
                <div className="severity-chart">
                  {[
                    { label: 'Critical', value: stats?.critical_events, color: '#ff1744' },
                    { label: 'High', value: stats?.high_events, color: '#ff6b35' },
                    { label: 'Medium', value: stats?.medium_events, color: '#ffa726' },
                    { label: 'Low', value: stats?.low_events, color: '#66bb6a' }
                  ].map(item => (
                    <div key={item.label} className="severity-item">
                      <div className="severity-info">
                        <div className="severity-dot" style={{ background: item.color }}></div>
                        <span>{item.label}</span>
                      </div>
                      <div className="severity-value">{item.value || 0}</div>
                    </div>
                  ))}
                </div>
              </div>

              <ThreatAnalysis />
            </div>

            {/* Events Table */}
            <ThreatTable />
          </>
        )}

        {activeTab === 'threats' && <ThreatTable />}
        
        {activeTab === 'owasp' && <OWASPChecks />}

        {activeTab === 'settings' && (
          <div className="settings-container">
            <div className="settings-card">
              <h3><Settings size={20} /> Firewall Configuration</h3>
              <div className="settings-grid">
                <div className="setting-item">
                  <label>Rate Limit Window (seconds)</label>
                  <input type="number" defaultValue="60" />
                </div>
                <div className="setting-item">
                  <label>Max Requests per Window</label>
                  <input type="number" defaultValue="100" />
                </div>
                <div className="setting-item">
                  <label>Enable SQL Injection Protection</label>
                  <input type="checkbox" defaultChecked />
                </div>
                <div className="setting-item">
                  <label>Enable XSS Protection</label>
                  <input type="checkbox" defaultChecked />
                </div>
              </div>
              <button className="save-btn">Save Configuration</button>
            </div>
          </div>
        )}
      </main>

      <style jsx>{`
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
        }

        .dashboard {
          min-height: 100vh;
          background: #0a0e27;
          color: #e0e7ff;
          font-family: 'JetBrains Mono', 'Fira Code', monospace;
          position: relative;
          overflow-x: hidden;
        }

        /* Animated Background */
        .bg-grid {
          position: fixed;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          background-image: 
            linear-gradient(rgba(0, 245, 255, 0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 245, 255, 0.03) 1px, transparent 1px);
          background-size: 50px 50px;
          animation: gridMove 20s linear infinite;
          z-index: 0;
        }

        .bg-gradient {
          position: fixed;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          background: radial-gradient(circle at 20% 50%, rgba(0, 128, 255, 0.1) 0%, transparent 50%),
                      radial-gradient(circle at 80% 80%, rgba(255, 23, 68, 0.1) 0%, transparent 50%);
          z-index: 0;
          animation: gradientShift 15s ease infinite;
        }

        @keyframes gridMove {
          0% { transform: translateY(0); }
          100% { transform: translateY(50px); }
        }

        @keyframes gradientShift {
          0%, 100% { opacity: 0.5; }
          50% { opacity: 0.8; }
        }

        /* Header */
        .header {
          position: relative;
          z-index: 10;
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 2rem 3rem;
          background: rgba(10, 14, 39, 0.8);
          backdrop-filter: blur(20px);
          border-bottom: 1px solid rgba(0, 245, 255, 0.2);
        }

        .header-left {
          display: flex;
          align-items: center;
          gap: 1.5rem;
        }

        .logo-icon {
          color: #00f5ff;
          filter: drop-shadow(0 0 10px rgba(0, 245, 255, 0.5));
          animation: pulse 2s ease-in-out infinite;
        }

        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.7; }
        }

        .header-title h1 {
          font-size: 1.5rem;
          font-weight: 700;
          letter-spacing: 2px;
          background: linear-gradient(135deg, #00f5ff, #0080ff);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          text-shadow: 0 0 20px rgba(0, 245, 255, 0.3);
        }

        .header-title p {
          font-size: 0.75rem;
          color: #64748b;
          margin-top: 0.25rem;
          letter-spacing: 1px;
        }

        .header-right {
          display: flex;
          gap: 1rem;
        }

        .refresh-btn, .settings-btn {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          padding: 0.75rem 1.5rem;
          background: rgba(0, 245, 255, 0.1);
          border: 1px solid rgba(0, 245, 255, 0.3);
          color: #00f5ff;
          border-radius: 8px;
          cursor: pointer;
          transition: all 0.3s ease;
          font-family: inherit;
          font-size: 0.875rem;
        }

        .refresh-btn.active {
          background: rgba(0, 245, 255, 0.2);
          box-shadow: 0 0 20px rgba(0, 245, 255, 0.3);
        }

        .refresh-btn:hover, .settings-btn:hover {
          background: rgba(0, 245, 255, 0.2);
          transform: translateY(-2px);
        }

        .spinning {
          animation: spin 1s linear infinite;
        }

        @keyframes spin {
          100% { transform: rotate(360deg); }
        }

        /* Navigation */
        .nav-tabs {
          position: relative;
          z-index: 10;
          display: flex;
          gap: 1rem;
          padding: 0 3rem;
          background: rgba(10, 14, 39, 0.6);
          backdrop-filter: blur(10px);
          border-bottom: 1px solid rgba(0, 245, 255, 0.1);
        }

        .nav-tab {
          padding: 1rem 2rem;
          background: transparent;
          border: none;
          color: #64748b;
          cursor: pointer;
          font-family: inherit;
          font-size: 0.875rem;
          font-weight: 500;
          letter-spacing: 1px;
          text-transform: uppercase;
          transition: all 0.3s ease;
          position: relative;
        }

        .nav-tab::after {
          content: '';
          position: absolute;
          bottom: 0;
          left: 0;
          width: 100%;
          height: 2px;
          background: linear-gradient(90deg, #00f5ff, #0080ff);
          transform: scaleX(0);
          transition: transform 0.3s ease;
        }

        .nav-tab.active {
          color: #00f5ff;
        }

        .nav-tab.active::after {
          transform: scaleX(1);
        }

        .nav-tab:hover {
          color: #00f5ff;
        }

        /* Main Content */
        .main-content {
          position: relative;
          z-index: 10;
          padding: 3rem;
          max-width: 1800px;
          margin: 0 auto;
        }

        /* Stats Grid */
        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
          gap: 1.5rem;
          margin-bottom: 3rem;
        }

        .stat-card {
          position: relative;
          padding: 2rem;
          background: rgba(15, 23, 42, 0.6);
          backdrop-filter: blur(10px);
          border: 1px solid rgba(0, 245, 255, 0.2);
          border-radius: 16px;
          overflow: hidden;
          transition: all 0.3s ease;
        }

        .stat-card:hover {
          transform: translateY(-4px);
          border-color: var(--accent-color);
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
        }

        .stat-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 1.5rem;
        }

        .stat-trend {
          font-size: 0.75rem;
          color: #64748b;
        }

        .stat-title {
          font-size: 0.875rem;
          color: #94a3b8;
          margin-bottom: 0.75rem;
          letter-spacing: 0.5px;
        }

        .stat-value {
          font-size: 2.5rem;
          font-weight: 700;
          background: linear-gradient(135deg, var(--accent-color), #fff);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
        }

        .stat-glow {
          position: absolute;
          top: 50%;
          left: 50%;
          width: 200%;
          height: 200%;
          transform: translate(-50%, -50%);
          pointer-events: none;
          opacity: 0.5;
        }

        /* Charts */
        .charts-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
          gap: 1.5rem;
          margin-bottom: 3rem;
        }

        .chart-card {
          padding: 2rem;
          background: rgba(15, 23, 42, 0.6);
          backdrop-filter: blur(10px);
          border: 1px solid rgba(0, 245, 255, 0.2);
          border-radius: 16px;
        }

        .chart-card h3 {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          margin-bottom: 1.5rem;
          font-size: 1rem;
          color: #e0e7ff;
        }

        .severity-chart {
          display: flex;
          flex-direction: column;
          gap: 1rem;
        }

        .severity-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 1rem;
          background: rgba(0, 0, 0, 0.3);
          border-radius: 8px;
          border: 1px solid rgba(255, 255, 255, 0.05);
        }

        .severity-info {
          display: flex;
          align-items: center;
          gap: 0.75rem;
        }

        .severity-dot {
          width: 12px;
          height: 12px;
          border-radius: 50%;
          box-shadow: 0 0 10px currentColor;
        }

        .severity-value {
          font-size: 1.5rem;
          font-weight: 700;
        }

        /* Threat Analysis */
        .threat-analysis {
          padding: 2rem;
          background: rgba(15, 23, 42, 0.6);
          backdrop-filter: blur(10px);
          border: 1px solid rgba(0, 245, 255, 0.2);
          border-radius: 16px;
        }

        .threat-analysis h3 {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          margin-bottom: 1.5rem;
        }

        .threat-bars {
          display: flex;
          flex-direction: column;
          gap: 1.25rem;
        }

        .threat-bar-item {
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }

        .threat-bar-label {
          display: flex;
          justify-content: space-between;
          font-size: 0.875rem;
          color: #94a3b8;
        }

        .threat-count {
          color: #00f5ff;
          font-weight: 600;
        }

        .threat-bar-track {
          height: 8px;
          background: rgba(0, 0, 0, 0.5);
          border-radius: 4px;
          overflow: hidden;
        }

        .threat-bar-fill {
          height: 100%;
          border-radius: 4px;
          transition: width 1s ease;
          box-shadow: 0 0 10px rgba(0, 245, 255, 0.5);
        }

        /* Threat Table */
        .threat-table-container {
          background: rgba(15, 23, 42, 0.6);
          backdrop-filter: blur(10px);
          border: 1px solid rgba(0, 245, 255, 0.2);
          border-radius: 16px;
          overflow: hidden;
        }

        .table-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 1.5rem 2rem;
          border-bottom: 1px solid rgba(0, 245, 255, 0.1);
        }

        .table-header h3 {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          font-size: 1rem;
        }

        .table-actions {
          display: flex;
          gap: 0.5rem;
        }

        .icon-btn {
          padding: 0.5rem;
          background: rgba(0, 245, 255, 0.1);
          border: 1px solid rgba(0, 245, 255, 0.3);
          border-radius: 8px;
          color: #00f5ff;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        .icon-btn:hover {
          background: rgba(0, 245, 255, 0.2);
        }

        .threat-table {
          overflow-x: auto;
        }

        table {
          width: 100%;
          border-collapse: collapse;
        }

        thead {
          background: rgba(0, 0, 0, 0.3);
        }

        th {
          padding: 1rem 1.5rem;
          text-align: left;
          font-size: 0.75rem;
          font-weight: 600;
          color: #64748b;
          text-transform: uppercase;
          letter-spacing: 1px;
        }

        .table-row {
          border-bottom: 1px solid rgba(255, 255, 255, 0.05);
          transition: all 0.3s ease;
        }

        .table-row:hover {
          background: rgba(0, 245, 255, 0.05);
        }

        td {
          padding: 1rem 1.5rem;
          font-size: 0.875rem;
        }

        .time-cell {
          color: #64748b;
          font-size: 0.8125rem;
        }

        .type-badge {
          display: inline-block;
          padding: 0.25rem 0.75rem;
          background: rgba(0, 128, 255, 0.2);
          color: #0080ff;
          border-radius: 6px;
          font-size: 0.75rem;
          font-weight: 500;
          text-transform: capitalize;
        }

        .severity-badge {
          display: inline-block;
          padding: 0.25rem 0.75rem;
          border-radius: 6px;
          font-size: 0.75rem;
          font-weight: 600;
          text-transform: uppercase;
        }

        .ip-cell {
          font-family: 'Courier New', monospace;
          color: #00f5ff;
        }

        .path-cell {
          color: #94a3b8;
          max-width: 200px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }

        .details-cell {
          color: #64748b;
          font-size: 0.8125rem;
        }

        /* OWASP Checks */
        .owasp-container {
          background: rgba(15, 23, 42, 0.6);
          backdrop-filter: blur(10px);
          border: 1px solid rgba(0, 245, 255, 0.2);
          border-radius: 16px;
          padding: 2rem;
        }

        .owasp-header h3 {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          margin-bottom: 2rem;
        }

        .owasp-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
          gap: 1rem;
        }

        .owasp-card {
          padding: 1.5rem;
          background: rgba(0, 0, 0, 0.3);
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 12px;
          transition: all 0.3s ease;
        }

        .owasp-card.enabled {
          border-color: rgba(102, 187, 106, 0.5);
        }

        .owasp-card:hover {
          transform: translateY(-2px);
          border-color: #00f5ff;
        }

        .owasp-number {
          font-size: 2rem;
          font-weight: 700;
          background: linear-gradient(135deg, #00f5ff, #0080ff);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          margin-bottom: 0.5rem;
        }

        .owasp-name {
          font-size: 0.875rem;
          color: #e0e7ff;
          margin-bottom: 1rem;
          min-height: 2.5rem;
        }

        .owasp-status {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          font-size: 0.75rem;
          color: #64748b;
          text-transform: uppercase;
        }

        .status-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: #66bb6a;
          box-shadow: 0 0 8px #66bb6a;
          animation: blink 2s ease-in-out infinite;
        }

        @keyframes blink {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }

        /* Settings */
        .settings-container {
          max-width: 800px;
        }

        .settings-card {
          background: rgba(15, 23, 42, 0.6);
          backdrop-filter: blur(10px);
          border: 1px solid rgba(0, 245, 255, 0.2);
          border-radius: 16px;
          padding: 2rem;
        }

        .settings-card h3 {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          margin-bottom: 2rem;
        }

        .settings-grid {
          display: grid;
          gap: 1.5rem;
          margin-bottom: 2rem;
        }

        .setting-item {
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }

        .setting-item label {
          font-size: 0.875rem;
          color: #94a3b8;
        }

        .setting-item input[type="number"],
        .setting-item input[type="text"] {
          padding: 0.75rem;
          background: rgba(0, 0, 0, 0.3);
          border: 1px solid rgba(0, 245, 255, 0.3);
          border-radius: 8px;
          color: #e0e7ff;
          font-family: inherit;
        }

        .setting-item input[type="checkbox"] {
          width: 20px;
          height: 20px;
        }

        .save-btn {
          padding: 1rem 2rem;
          background: linear-gradient(135deg, #00f5ff, #0080ff);
          border: none;
          color: #0a0e27;
          border-radius: 8px;
          font-weight: 700;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        .save-btn:hover {
          transform: translateY(-2px);
          box-shadow: 0 4px 20px rgba(0, 245, 255, 0.4);
        }

        /* Loading */
        .loading-container {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
          gap: 2rem;
        }

        .loader {
          width: 64px;
          height: 64px;
          border: 4px solid rgba(0, 245, 255, 0.2);
          border-top-color: #00f5ff;
          border-radius: 50%;
          animation: spin 1s linear infinite;
        }

        .loading-container p {
          color: #64748b;
          font-size: 1rem;
          letter-spacing: 1px;
        }
      `}</style>
    </div>
  );
};

export default Dashboard;
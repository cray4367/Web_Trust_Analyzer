import React from 'react';
import { Shield, TrendingUp, Users, AlertTriangle } from 'lucide-react';

// Trust Score Gauge Component
export const TrustScoreGauge = ({ score, label }) => {
    // Defensive check: Default score to 0 if undefined/null or not a number
    const safeScore = (typeof score === 'number' && !isNaN(score)) ? score : 0;

    const getColor = (s) => {
        if (s >= 80) return '#10b981';
        if (s >= 60) return '#3b82f6';
        if (s >= 40) return '#f59e0b';
        if (s >= 20) return '#f97316';
        return '#ef4444';
    };

    const percentage = (safeScore / 100) * 180; // 180 degrees for semicircle

    return (
        <div className="trust-gauge">
            <svg viewBox="0 0 200 120" style={{ width: '100%', height: 'auto' }}>
                {/* Background arc */}
                <path
                    d="M 20 100 A 80 80 0 0 1 180 100"
                    stroke="#1e293b"
                    strokeWidth="20"
                    fill="none"
                />
                {/* Colored arc */}
                <path
                    d="M 20 100 A 80 80 0 0 1 180 100"
                    stroke={getColor(safeScore)}
                    strokeWidth="20"
                    fill="none"
                    strokeDasharray={`${percentage * 1.396} 251`}
                    style={{ transition: 'stroke-dasharray 1s ease' }}
                />
                {/* Score text */}
                <text
                    x="100"
                    y="85"
                    textAnchor="middle"
                    fontSize="36"
                    fontWeight="bold"
                    fill={getColor(safeScore)}
                >
                    {safeScore.toFixed(0)}
                </text>
                {/* Label */}
                <text
                    x="100"
                    y="110"
                    textAnchor="middle"
                    fontSize="12"
                    fill="#94a3b8"
                >
                    {label}
                </text>
            </svg>
        </div>
    );
};

// Trust Distribution Chart Component
export const TrustDistributionChart = ({ distribution }) => {
    const levels = [
        { key: 'HIGHLY_TRUSTED', label: 'Highly Trusted', color: '#10b981' },
        { key: 'TRUSTED', label: 'Trusted', color: '#3b82f6' },
        { key: 'NEUTRAL', label: 'Neutral', color: '#f59e0b' },
        { key: 'SUSPICIOUS', label: 'Suspicious', color: '#f97316' },
        { key: 'MALICIOUS', label: 'Malicious', color: '#ef4444' },
    ];

    // Defensive check: Ensure distribution is an object
    const safeDist = distribution || {};
    const total = Object.values(safeDist).reduce((a, b) => a + b, 0) || 1;

    return (
        <div className="trust-distribution">
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
                <TrendingUp size={20} /> Trust Distribution
            </h3>
            <div className="distribution-bars">
                {levels.map(level => {
                    const count = safeDist[level.key] || 0;
                    const percentage = (count / total) * 100;

                    return (
                        <div key={level.key} className="distribution-item">
                            <div className="distribution-label">
                                <span>{level.label}</span>
                                <span className="distribution-count">{count}</span>
                            </div>
                            <div className="distribution-bar-track">
                                <div
                                    className="distribution-bar-fill"
                                    style={{
                                        width: `${percentage}%`,
                                        background: level.color,
                                        transition: 'width 1s ease'
                                    }}
                                />
                            </div>
                            <span className="distribution-percentage">{percentage.toFixed(1)}%</span>
                        </div>
                    );
                })}
            </div>
        </div>
    );
};

// Trust Profile Card Component
export const TrustProfileCard = ({ profile }) => {
    // Defensive check
    if (!profile) return null;

    // Default values
    const safeReputation = profile.reputation || 'UNKNOWN';
    const safeScore = profile.trust_score ?? 0;
    const safeIP = profile.ip || 'Unknown IP';

    const getReputationColor = (rep) => {
        switch (rep) {
            case 'HIGHLY_TRUSTED': return '#10b981';
            case 'TRUSTED': return '#3b82f6';
            case 'NEUTRAL': return '#f59e0b';
            case 'SUSPICIOUS': return '#f97316';
            case 'MALICIOUS': return '#ef4444';
            default: return '#64748b';
        }
    };

    const formatDate = (dateStr) => {
        if (!dateStr) return 'N/A';
        try {
            return new Date(dateStr).toLocaleDateString('en-US', {
                month: 'short',
                day: 'numeric',
                year: 'numeric'
            });
        } catch (e) { return 'Invalid Date'; }
    };

    const formatTime = (dateStr) => {
        if (!dateStr) return 'N/A';
        try {
            return new Date(dateStr).toLocaleTimeString('en-US', {
                hour: '2-digit',
                minute: '2-digit'
            });
        } catch (e) { return 'Invalid Time'; }
    };

    return (
        <div className="trust-profile-card">
            <div className="profile-header">
                <span className="profile-ip">{safeIP}</span>
                <span
                    className="trust-badge"
                    style={{
                        background: `${getReputationColor(safeReputation)}20`,
                        color: getReputationColor(safeReputation),
                        border: `1px solid ${getReputationColor(safeReputation)}40`
                    }}
                >
                    {safeReputation.replace(/_/g, ' ')}
                </span>
            </div>

            <div style={{ margin: '1rem 0' }}>
                <TrustScoreGauge score={safeScore} label="Trust Score" />
            </div>

            <div className="profile-stats">
                <div className="stat">
                    <span className="stat-label">Requests</span>
                    <span className="stat-value">{profile.request_count || 0}</span>
                </div>
                <div className="stat">
                    <span className="stat-label">Threats</span>
                    <span className="stat-value" style={{ color: '#ef4444' }}>{profile.threat_count || 0}</span>
                </div>
                <div className="stat">
                    <span className="stat-label">Clean</span>
                    <span className="stat-value" style={{ color: '#10b981' }}>{profile.clean_count || 0}</span>
                </div>
            </div>

            <div className="profile-timeline">
                <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
                    <div>First seen: {formatDate(profile.first_seen)}</div>
                    <div>Last seen: {formatTime(profile.last_seen)}</div>
                </div>
            </div>
        </div>
    );
};

// Trust Stats Cards Component
// Trust Stats Cards Component
export const TrustStatsCards = ({ trustStats }) => {
    if (!trustStats) return null;

    // Defensive helper
    const safeNum = (val) => (typeof val === 'number' && !isNaN(val)) ? val : 0;

    return (
        <div className="trust-stats-grid">
            <div className="trust-stat-card" style={{ '--accent-color': '#00f5ff' }}>
                <Users size={24} color="#00f5ff" />
                <div className="stat-value">{safeNum(trustStats.total_profiles)}</div>
                <div className="stat-label">Total Profiles</div>
            </div>

            <div className="trust-stat-card" style={{ '--accent-color': '#10b981' }}>
                <Shield size={24} color="#10b981" />
                <div className="stat-value">{safeNum(trustStats.highly_trusted) + safeNum(trustStats.trusted)}</div>
                <div className="stat-label">Trusted Users</div>
            </div>

            <div className="trust-stat-card" style={{ '--accent-color': '#f97316' }}>
                <AlertTriangle size={24} color="#f97316" />
                <div className="stat-value">{safeNum(trustStats.suspicious) + safeNum(trustStats.malicious)}</div>
                <div className="stat-label">Suspicious Users</div>
            </div>

            <div className="trust-stat-card" style={{ '--accent-color': '#3b82f6' }}>
                <TrendingUp size={24} color="#3b82f6" />
                <div className="stat-value">{safeNum(trustStats.average_score).toFixed(1)}</div>
                <div className="stat-label">Avg Trust Score</div>
            </div>
        </div>
    );
};

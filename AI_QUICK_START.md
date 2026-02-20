# AI-Powered Threat Scoring - Quick Start Guide

## 🎯 What This Does

This system assigns a **threat score (0-100)** to every incoming request by analyzing:
- **Payload patterns** (SQL injection, XSS, malicious code)
- **IP reputation** (known attackers, geographic risk)
- **Request behavior** (frequency, headers, timing)
- **Machine learning predictions** (novel attack detection)

## 🏗️ Architecture Overview

![Architecture Diagram](/home/akshat/.gemini/antigravity/brain/c7d1b39a-94d3-4cc5-9e37-17e75bc6b815/threat_scoring_architecture_1770310648954.png)

## 📊 Scoring Components

![Scoring Components](/home/akshat/.gemini/antigravity/brain/c7d1b39a-94d3-4cc5-9e37-17e75bc6b815/scoring_components_breakdown_1770310689271.png)

### Weighted Breakdown (Total: 100 points)

| Component | Weight | Max Points | What It Measures |
|-----------|--------|------------|------------------|
| **Payload Analysis** | 35% | 35 | Special characters, entropy, known attack patterns |
| **IP Reputation** | 25% | 25 | External threat databases, historical attacks |
| **Request Patterns** | 20% | 20 | HTTP method, path depth, header anomalies |
| **Behavioral Signals** | 15% | 15 | User-Agent legitimacy, session consistency |
| **Timing Patterns** | 5% | 5 | Request frequency, timing anomalies |

## 🚀 Implementation Approach

### Phase 1: Rule-Based Foundation (Week 1)
**Goal:** Get basic scoring working without ML

```go
// Pseudo-code for scoring logic
score := 0.0

// 1. Payload Analysis (35 points max)
score += CalculateEntropyScore(payload) * 0.15      // 0-15 pts
score += SpecialCharDensity(payload) * 0.20         // 0-20 pts

// 2. IP Reputation (25 points max)
score += GetIPReputationScore(ip) * 0.25            // 0-25 pts

// 3. Request Patterns (20 points max)
score += AnalyzeRequestPattern(request) * 0.20      // 0-20 pts

// 4. Behavioral (15 points max)
score += AnalyzeBehavior(userAgent, session) * 0.15 // 0-15 pts

// 5. Timing (5 points max)
score += AnalyzeTiming(requestTime) * 0.05          // 0-5 pts

// Normalize to 0-100
finalScore := min(score, 100)
```

**Action Thresholds:**
- **0-39**: ✅ Allow (Low risk)
- **40-59**: 🟡 Monitor (Medium risk)
- **60-79**: ⚠️ Flag for review (High risk)
- **80-100**: 🚫 Block (Critical risk)

### Phase 2: ML Enhancement (Week 2-3)
**Goal:** Add machine learning to improve accuracy

```python
# Train model on historical data
features = [
    'payload_entropy',
    'special_char_density',
    'ip_reputation',
    'request_frequency',
    'user_agent_score'
]

model = RandomForestClassifier()
model.fit(X_train, y_train)  # y = is_threat (0 or 1)

# Use model to adjust scores
ml_adjustment = model.predict_proba(features)[1] * 20  # 0-20 pts
final_score = rule_based_score + ml_adjustment
```

## 📁 File Structure

```
Web_Trust_Analyzer/
├── firewall/
│   ├── scoring/
│   │   ├── features.go          # Feature extraction
│   │   ├── engine.go            # Scoring engine
│   │   ├── ip_reputation.go     # IP lookup & caching
│   │   └── ml_client.go         # ML service client
│   ├── middleware.go            # Add scoring middleware
│   └── database.go              # New tables for scores
│
├── ml-service/                  # Python ML microservice
│   ├── app.py                   # FastAPI server
│   ├── models/
│   │   └── threat_classifier.pkl
│   ├── train.py                 # Model training script
│   └── requirements.txt
│
└── dashboard/
    └── src/
        └── components/
            ├── ThreatScoreGauge.jsx
            ├── ScoreDistribution.jsx
            └── FeatureImportance.jsx
```

## 🔧 Key Implementation Details

### 1. Feature Extraction Example

```go
func CalculateEntropy(data string) float64 {
    if len(data) == 0 {
        return 0
    }
    
    freq := make(map[rune]int)
    for _, char := range data {
        freq[char]++
    }
    
    entropy := 0.0
    length := float64(len(data))
    
    for _, count := range freq {
        p := float64(count) / length
        entropy -= p * math.Log2(p)
    }
    
    // Normalize to 0-1 scale (max entropy ~8 for ASCII)
    return math.Min(entropy / 8.0, 1.0)
}
```

### 2. IP Reputation Integration

```go
type IPReputationCache struct {
    cache map[string]*CachedReputation
    mutex sync.RWMutex
}

func (irc *IPReputationCache) GetScore(ip string) float64 {
    // Check cache first
    if cached, ok := irc.cache[ip]; ok {
        if time.Since(cached.Timestamp) < 24*time.Hour {
            return cached.Score
        }
    }
    
    // Call external API
    score := callAbuseIPDB(ip)
    
    // Cache result
    irc.cache[ip] = &CachedReputation{
        Score: score,
        Timestamp: time.Now(),
    }
    
    return score
}
```

### 3. ML Service Communication

```go
type MLClient struct {
    baseURL string
    client  *http.Client
}

func (ml *MLClient) GetPrediction(features RequestFeatures) (float64, error) {
    jsonData, _ := json.Marshal(features)
    
    resp, err := ml.client.Post(
        ml.baseURL + "/predict",
        "application/json",
        bytes.NewBuffer(jsonData),
    )
    
    if err != nil {
        return 0, err // Fallback to rule-based only
    }
    
    var result struct {
        ThreatProbability float64 `json:"threat_probability"`
    }
    json.NewDecoder(resp.Body).Decode(&result)
    
    return result.ThreatProbability, nil
}
```

## 📊 Database Schema

```sql
CREATE TABLE threat_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER,
    total_score REAL,
    payload_score REAL,
    ip_score REAL,
    pattern_score REAL,
    behavioral_score REAL,
    timing_score REAL,
    ml_score REAL,
    risk_level TEXT,
    action_taken TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_threat_scores_total ON threat_scores(total_score);
CREATE INDEX idx_threat_scores_timestamp ON threat_scores(timestamp);
```

## 🎨 Dashboard Additions

### Real-time Threat Score Display

```jsx
function ThreatScoreGauge({ score }) {
    const getRiskLevel = (score) => {
        if (score >= 80) return { level: 'CRITICAL', color: '#ff1744' };
        if (score >= 60) return { level: 'HIGH', color: '#ff9100' };
        if (score >= 40) return { level: 'MEDIUM', color: '#ffd600' };
        return { level: 'LOW', color: '#00e676' };
    };
    
    const risk = getRiskLevel(score);
    
    return (
        <div className="threat-gauge">
            <CircularProgress 
                value={score} 
                color={risk.color}
            />
            <div className="score-value">{score.toFixed(1)}</div>
            <div className="risk-level">{risk.level}</div>
        </div>
    );
}
```

## 🧪 Testing Strategy

### 1. Test with Known Attacks

```bash
# SQL Injection (should score 80+)
curl "http://localhost:8080/app?id=1' OR '1'='1"

# XSS Attack (should score 80+)
curl "http://localhost:8080/app?q=<script>alert('xss')</script>"

# Legitimate request (should score <40)
curl "http://localhost:8080/app/dashboard"
```

### 2. Validate Scoring Components

```go
func TestScoringComponents(t *testing.T) {
    engine := NewScoringEngine()
    
    // Test malicious payload
    features := RequestFeatures{
        PayloadLength: 100,
        SpecialCharDensity: 0.8,  // 80% special chars
        EntropyScore: 0.9,         // High randomness
    }
    
    score := engine.CalculateScore(features)
    assert.True(t, score.TotalScore >= 60, "Malicious payload should score high")
}
```

## 📈 Success Metrics

| Metric | Target | How to Measure |
|--------|--------|----------------|
| Detection Rate | 95%+ | True positives / Total attacks |
| False Positive Rate | <5% | False positives / Total legitimate |
| Scoring Latency | <10ms | Time to calculate score |
| ML Service Uptime | 99%+ | Service availability |

## 🔄 Continuous Improvement

### Weekly Tasks
1. **Review high-scoring legitimate requests** → Adjust weights
2. **Analyze missed attacks** → Add new patterns
3. **Retrain ML model** with new data
4. **Update IP reputation cache**

### Monthly Tasks
1. **Evaluate model performance** (precision, recall, F1)
2. **A/B test new scoring algorithms**
3. **Update threat intelligence sources**
4. **Optimize performance bottlenecks**

## 🚨 Common Pitfalls & Solutions

| Problem | Solution |
|---------|----------|
| High false positives | Lower thresholds, whitelist trusted IPs |
| ML service slow | Add caching, async predictions |
| Scoring too slow | Profile code, optimize hot paths |
| Model drift | Regular retraining, monitoring |

## 🎯 Next Steps

1. **Review the detailed [implementation_plan.md](file:///home/akshat/.gemini/antigravity/brain/c7d1b39a-94d3-4cc5-9e37-17e75bc6b815/implementation_plan.md)**
2. **Decide on approach**: Start with rule-based or full ML?
3. **Set up development environment** for ML service
4. **Begin Phase 1 implementation** (feature extraction)

---

**Ready to implement?** The detailed plan covers everything from code structure to deployment strategy!

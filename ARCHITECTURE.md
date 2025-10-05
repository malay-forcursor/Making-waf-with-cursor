# 🏗️ AI-NGFW Architecture Documentation

## System Architecture

### High-Level Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                      Internet Traffic                             │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│                    WAF Entry Point                                │
│                   (FastAPI Middleware)                            │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Request Inspector                              │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ • Extract headers, body, params                            │  │
│  │ • Parse HTTP/HTTPS traffic                                 │  │
│  │ • Deep Packet Inspection                                   │  │
│  └────────────────────────────────────────────────────────────┘  │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│              Parallel Detection Engines                           │
│                                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐            │
│  │Rule-Based   │  │ML Anomaly   │  │Behavioral    │            │
│  │Detection    │  │Detection    │  │Analysis      │            │
│  │(Signatures) │  │(IF/DBSCAN)  │  │(LSTM)        │            │
│  └──────┬──────┘  └──────┬──────┘  └──────┬───────┘            │
│         │                │                │                      │
│  ┌──────┴────────────────┴────────────────┴───────┐             │
│  │         ┌─────────────┐  ┌──────────────┐      │             │
│  │         │Traffic      │  │Threat Intel  │      │             │
│  │         │Classifier   │  │Lookup        │      │             │
│  │         │(CNN)        │  │(STIX/TAXII)  │      │             │
│  │         └──────┬──────┘  └──────┬───────┘      │             │
│  └────────────────┴─────────────────┴──────────────┘             │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│                   Risk Aggregation Engine                         │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ • Combine detection results                                │  │
│  │ • Calculate risk score                                     │  │
│  │ • Apply Zero Trust policies                                │  │
│  │ • Make decision (Allow/Block/Monitor)                      │  │
│  └────────────────────────────────────────────────────────────┘  │
└────────────────────────┬─────────────────────────────────────────┘
                         │
           ┌─────────────┼─────────────┐
           │             │             │
           ▼             ▼             ▼
     ┌─────────┐   ┌─────────┐   ┌──────────┐
     │ Allow   │   │ Block   │   │ Monitor  │
     │ Request │   │ Request │   │ & Log    │
     └─────────┘   └────┬────┘   └──────────┘
                        │
                        ▼
              ┌─────────────────┐
              │ SOAR Workflows  │
              │ Auto-Response   │
              └─────────────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
    ┌──────────┐  ┌─────────┐  ┌──────────┐
    │Block IP  │  │Sandbox  │  │Alert     │
    │Temp/Perm │  │Traffic  │  │Security  │
    └──────────┘  └─────────┘  └──────────┘
```

## Core Components

### 1. WAF Engine (`src/core/engine.py`)

**Purpose**: Orchestrates all detection and response components

**Key Functions**:
- `inspect_request()`: Main entry point for request inspection
- `_make_decision()`: Aggregates results and makes final decision
- `_extract_features()`: Prepares data for ML models

**Flow**:
1. Receive request from FastAPI middleware
2. Extract request features
3. Dispatch to all detection engines in parallel
4. Aggregate results
5. Calculate risk score
6. Make decision (allow/block/monitor)
7. Trigger automated response if needed

### 2. Rule-Based Detection (`src/detection/rule_engine.py`)

**Purpose**: Signature-based detection for known attack patterns

**Attack Types Detected**:
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- LDAP Injection
- XML Injection

**Implementation**:
- Pre-compiled regex patterns for performance
- Pattern matching against request components
- Configurable severity levels
- Custom rule support

**Example Rules**:
```python
sql_injection_patterns = [
    r"(?i)(union|select|insert|update|delete).*?(from|into|table)",
    r"(?i)(or|and)\s+['\"]\d+['\"]?\s*=\s*['\"]\d+['\"]?",
    r"(?i)(exec|execute|sp_|xp_)"
]
```

### 3. ML-Based Anomaly Detection (`src/ml/anomaly_detector.py`)

**Purpose**: Detect zero-day attacks and anomalous behavior

**Models Used**:
1. **Isolation Forest**: Identifies outliers in high-dimensional space
2. **DBSCAN**: Density-based clustering for anomaly detection
3. **Local Outlier Factor (LOF)**: Detects local anomalies

**Features**:
- Path length
- Header count
- Body size
- Query parameters
- User agent characteristics
- Time-based features

**Process**:
```python
1. Extract numerical features from request
2. Normalize using StandardScaler
3. Run through ensemble of models
4. Aggregate anomaly scores
5. Return final anomaly score (0-1)
```

**Continuous Learning**:
- Buffers recent requests
- Periodically retrains models
- Adapts to normal traffic patterns

### 4. Traffic Classifier (`src/ml/traffic_classifier.py`)

**Purpose**: Classify traffic into threat categories using deep learning

**Architecture**:
- Lightweight CNN for encrypted traffic analysis
- Pattern-based classification (fallback)
- Multi-class classification

**Threat Categories**:
- SQL Injection
- XSS
- Command Injection
- Path Traversal
- Zero-day
- Normal

**Process**:
1. Convert request to feature vector
2. Pass through CNN
3. Output probability distribution
4. Select highest confidence class

### 5. Behavioral Analysis (`src/ml/behavioral_analyzer.py`)

**Purpose**: Analyze user/IP behavior patterns over time

**Metrics Tracked**:
- Request rate per IP
- Unique paths accessed
- Method distribution
- Burst patterns
- Time-based patterns

**Risk Factors**:
1. **High Request Rate**: Exceeds threshold
2. **Path Scanning**: Accessing many unique paths
3. **Method Anomalies**: Unusual method distribution
4. **Burst Activity**: Too many requests too quickly

**LSTM Analysis** (Future Enhancement):
- Sequence modeling of user actions
- Predict next action
- Detect deviation from normal patterns

### 6. Zero Trust Components

#### Authenticator (`src/zero_trust/authenticator.py`)

**Purpose**: Continuous authentication and verification

**Features**:
- JWT-based authentication
- Multi-factor authentication support
- Session management
- Device fingerprinting
- Behavioral biometrics (planned)

**Zero Trust Principles**:
- Never trust, always verify
- Least privilege access
- Assume breach mindset

#### Risk Scorer (`src/zero_trust/risk_scorer.py`)

**Purpose**: Calculate real-time risk scores

**Risk Factors**:
1. **IP Reputation**: Known malicious IPs
2. **Failed Attempts**: Login/access failures
3. **User Agent**: Missing or suspicious user agents
4. **Time-based**: Access during unusual hours
5. **Geographic**: Unusual locations
6. **Path-based**: Accessing sensitive resources

**Risk Score Calculation**:
```python
risk_score = max([
    ip_risk,
    failed_attempt_risk,
    user_agent_risk,
    time_risk,
    path_risk
])
```

### 7. SOAR - Automated Incident Response (`src/soar/incident_responder.py`)

**Purpose**: Automated threat response and mitigation

**Severity-Based Response**:

| Severity | Actions |
|----------|---------|
| Critical | Block IP (24h), Deep inspection, High-priority alert, Update ML |
| High | Block IP (1h), Send alert, Log for analysis |
| Medium | Rate limit, Add to watchlist |
| Low | Log only |

**SOAR Workflows**:
1. **IP Blocking**: Temporary or permanent
2. **Quarantine**: Isolate suspicious traffic
3. **Sandboxing**: Execute in isolated environment
4. **Alerting**: Notify security team
5. **ML Update**: Feed new patterns to models

**Integration Points**:
- Email notifications
- Slack/Teams webhooks
- SIEM systems (Splunk, ELK)
- Ticketing systems (Jira, ServiceNow)

### 8. Threat Intelligence (`src/threat_intel/feed_manager.py`)

**Purpose**: Integrate external threat intelligence

**Feed Sources**:
1. **Abuse.ch**: Malware URLs and IPs
2. **AlienVault OTX**: Open threat exchange
3. **MITRE ATT&CK**: Tactics, techniques, procedures
4. **Custom Feeds**: Organization-specific IOCs

**IOC Types**:
- IP addresses
- Domain names
- URLs
- File hashes (MD5, SHA1, SHA256)

**STIX/TAXII Support**:
- Standard format for threat intel
- Automated feed updates
- Indicator sharing

**Process**:
```python
1. Fetch feeds periodically
2. Parse and extract IOCs
3. Store in memory database
4. Check incoming requests against IOCs
5. Return match if found
```

### 9. Database Manager (`src/utils/db_manager.py`)

**Purpose**: Manage persistence and caching

**Databases**:
1. **MongoDB**: Persistent storage
   - Inspection logs
   - Incidents
   - Statistics
   - Audit trail

2. **Redis**: High-speed cache
   - Session data
   - Rate limiting counters
   - Temporary blocks
   - ML model cache

**Operations**:
- Log inspection results
- Query statistics
- Cache frequent lookups
- Store threat intelligence

### 10. Monitoring & Dashboard

#### Metrics Collector (`src/monitoring/metrics.py`)

**Purpose**: Collect and expose metrics

**Metrics**:
- Total requests
- Blocked/allowed/monitored counts
- Threats by type and severity
- Performance metrics (latency, throughput)
- System resource usage

**Prometheus Compatibility**:
- Text format exposition
- Standard metric types (counter, gauge, histogram)
- Labeled metrics for dimensional analysis

#### Dashboard (`src/monitoring/dashboard.py`)

**Purpose**: Real-time visualization

**Technologies**:
- Dash (Plotly)
- Bootstrap for styling
- WebSocket for real-time updates

**Visualizations**:
1. **KPI Cards**: Key metrics at a glance
2. **Threat Charts**: Bar charts, pie charts
3. **Time Series**: Traffic over time
4. **Heatmaps**: Attack sources/targets
5. **Incident List**: Recent security events

**Features**:
- Auto-refresh every 5 seconds
- Responsive design
- Dark theme for SOC environments

## Data Flow

### Request Processing Pipeline

```
1. HTTP Request arrives at FastAPI
   ↓
2. WAF Middleware intercepts
   ↓
3. Extract features:
   - Source IP, headers, path, method, body
   ↓
4. Parallel detection (all run simultaneously):
   a. Rule Engine checks signatures
   b. Anomaly Detector analyzes features
   c. Traffic Classifier predicts category
   d. Behavioral Analyzer checks patterns
   e. Threat Intel looks up IOCs
   f. Zero Trust calculates risk
   ↓
5. Aggregate all results:
   - Collect threat types
   - Calculate max risk score
   - Determine confidence level
   ↓
6. Make decision:
   - Allow: Risk < low threshold
   - Monitor: Risk = medium threshold
   - Block: Risk > high threshold
   ↓
7. Execute action:
   - If blocked → trigger SOAR workflow
   - Log to database
   - Update metrics
   - Send response
   ↓
8. Response sent to client
```

### ML Model Training Pipeline

```
1. Collect traffic data
   ↓
2. Buffer in memory (10,000 samples)
   ↓
3. Periodically trigger retraining:
   - Extract features
   - Normalize data
   - Split train/validation
   ↓
4. Train models:
   - Isolation Forest
   - LOF
   - CNN classifier
   - LSTM behavioral
   ↓
5. Evaluate performance:
   - Accuracy, precision, recall
   - False positive rate
   - F1 score
   ↓
6. If improved:
   - Save models to disk
   - Update production models
   - Log performance metrics
   ↓
7. Continue monitoring
```

## Scalability Considerations

### Horizontal Scaling

- **Stateless Design**: Each WAF instance is independent
- **Load Balancing**: Distribute traffic across instances
- **Shared State**: Use Redis for distributed caching
- **Database**: MongoDB with replica sets

### Performance Optimization

1. **Pre-compiled Patterns**: Regex patterns compiled at startup
2. **Connection Pooling**: Reuse database connections
3. **Async I/O**: Non-blocking operations
4. **Model Caching**: Keep models in memory
5. **Batch Processing**: Batch database writes

### High Availability

- **Health Checks**: `/health` endpoint for load balancers
- **Graceful Shutdown**: Clean up resources
- **Failover**: Multiple WAF instances
- **Circuit Breakers**: Fail-open on errors
- **Redundant Storage**: Database replication

## Security Considerations

### Secure by Design

1. **Defense in Depth**: Multiple detection layers
2. **Fail-Open**: Allow traffic on errors (configurable)
3. **Rate Limiting**: Prevent resource exhaustion
4. **Input Validation**: Sanitize all inputs
5. **Secure Defaults**: Strict default policies

### Data Protection

- **Encryption at Rest**: Database encryption
- **Encryption in Transit**: HTTPS/TLS
- **Data Minimization**: Only store necessary data
- **Privacy**: No PII logging (configurable)
- **Audit Logging**: Complete audit trail

### Threat Model

**Threats Addressed**:
- SQL Injection
- XSS
- Command Injection
- Path Traversal
- Zero-day exploits
- DDoS
- Credential stuffing
- API abuse

**Residual Risks**:
- Advanced persistent threats (APT)
- Insider threats (requires additional controls)
- Zero-day in WAF itself (keep updated)

## Compliance & Standards

### NIST SP 800-207 (Zero Trust)

- ✅ Continuous verification
- ✅ Least privilege access
- ✅ Assume breach
- ✅ Micro-segmentation
- ✅ Dynamic policies

### MITRE ATT&CK

- ✅ Threat intelligence integration
- ✅ TTP mapping
- ✅ Detection coverage
- ✅ Incident response

### OWASP Top 10

- ✅ Injection protection
- ✅ Broken authentication prevention
- ✅ XSS protection
- ✅ Security misconfiguration detection
- ✅ Sensitive data exposure prevention

## Future Enhancements

1. **Deep SSL/TLS Inspection**: Decrypt and inspect encrypted traffic
2. **GraphQL Support**: Parse and validate GraphQL queries
3. **gRPC Support**: Inspect binary protocols
4. **Container Integration**: Kubernetes sidecar deployment
5. **Edge Deployment**: Run at CDN edge locations
6. **Advanced ML**: Transformer models for better detection
7. **Federated Learning**: Privacy-preserving model training
8. **Auto-Tuning**: Self-optimizing thresholds

---

**Document Version**: 1.0  
**Last Updated**: 2025-10-05

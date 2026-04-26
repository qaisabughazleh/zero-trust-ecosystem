# Zero-Trust Microservice Ecosystem

A production-grade, fully functional zero-trust security architecture for a university platform.

## Architecture

```
 Clients (Student / Professor / Visitor)
        │ HTTPS + JWT
        ▼
 ┌─────────────────────────────────────┐
 │         API GATEWAY (Node.js)       │
 │  • JWT validation (every request)   │
 │  • OPA policy evaluation            │
 │  • AI risk scoring                  │
 │  • Rate limiting (Redis)            │
 │  • Session management               │
 │  • Audit logging                    │
 └──────────┬──────────────────────────┘
            │ mTLS (Istio)
     ┌──────┼────────────────────┐
     ▼      ▼                    ▼
 Student  Professor  Visitor   Admin
   Svc      Svc       Svc      Svc
     └──────┴────┬───────┴────────┘
                 │ mTLS
         ┌───────┼────────┐
         ▼       ▼        ▼
       OPA   AI Engine  Log Svc
      (RBAC) (IsoForest) (ELK)
         └───────┼────────┘
                 ▼
           Postgres + Redis
           Prometheus + Grafana
```

## Technology Stack

| Component        | Technology                          | Purpose                              |
|-----------------|-------------------------------------|--------------------------------------|
| API Gateway      | Node.js 20 · Fastify                | Request routing, auth, RBAC          |
| Microservices    | Node.js 20 · Fastify · PostgreSQL   | Business logic (student/prof/visitor)|
| Policy Engine    | Open Policy Agent (OPA) · Rego      | Fine-grained RBAC + contextual rules |
| AI Engine        | Python 3.12 · FastAPI · scikit-learn| Anomaly detection, risk scoring      |
| ML Model         | Isolation Forest                    | Unsupervised anomaly detection       |
| Session Store    | Redis 7                             | Sessions, rate limiting, pub/sub     |
| Database         | PostgreSQL 16                       | Persistent data                      |
| Log Storage      | Elasticsearch 8                     | Structured audit log indexing        |
| Metrics          | Prometheus + Grafana                | System health monitoring             |
| Service Mesh     | Istio                               | mTLS, traffic management             |
| Container Orch.  | Kubernetes + Helm                   | Deployment, scaling, secrets         |
| Auth Protocol    | JWT (RS256 in prod) + Redis sessions| Stateful session management          |

## Zero-Trust Principles Implemented

### 1. Never Trust, Always Verify
- Every request is validated at the gateway (JWT + OPA)
- Every microservice independently re-validates with OPA (defence-in-depth)
- No service trusts another based on network position alone

### 2. Mutual TLS (mTLS)
- Istio enforces STRICT mTLS for all service-to-service traffic
- Certificates automatically rotated by Istio's CA
- Plaintext connections rejected by PeerAuthentication policy

### 3. Least Privilege (RBAC via OPA)
```
Role        → Permitted Services
─────────────────────────────────
student     → visitor, student (own data only)
professor   → visitor, student (course-scoped), professor
visitor     → visitor (GET only, 06:00–22:00 UTC)
admin       → all services, all methods
```

### 4. Continuous Validation
- JWT verified on every request (not just first)
- Redis session TTL of 30 minutes (sliding window)
- AI engine tracks behavioral baseline per user
- OPA re-evaluates on every service call

### 5. Assume Breach
- AI engine continuously monitors for anomalies
- Automatic IP blocking at risk_score > 0.95
- User anomaly flagging injected back into OPA
- Rate limiting per role per IP

## Quick Start

### Prerequisites
- Docker 24+ and Docker Compose 2.20+
- 8 GB RAM minimum (Elasticsearch is hungry)

### Launch
```bash
# Clone and start
git clone <repo>
cd zero-trust-ecosystem

# Generate JWT secret
echo "JWT_SECRET=$(openssl rand -hex 32)" > .env

# Start all services
docker compose up -d

# Watch logs
docker compose logs -f gateway ai-engine opa

# Check health
curl http://localhost:8080/health
```

### Test Credentials
| Role      | Email                  | Password      |
|-----------|------------------------|---------------|
| Student   | student@uni.edu        | student123    |
| Professor | professor@uni.edu      | professor123  |
| Visitor   | visitor@uni.edu        | visitor123    |

### Run Simulation
```bash
pip install httpx
python3 scripts/simulate.py --gateway http://localhost:8080 --scenario all
```

### Example Requests
```bash
# 1. Login
TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"student@uni.edu","password":"student123"}' \
  | jq -r .token)

# 2. Allowed: student → student service
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/student/grades

# 3. Denied: student → professor service (403 Forbidden)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/professor/courses

# 4. AI insights (admin only)
curl http://localhost:5000/insights   # Direct access for dev
```

## Monitoring URLs (after docker compose up)

| Service       | URL                                      |
|---------------|------------------------------------------|
| API Gateway   | http://localhost:8080                    |
| Grafana       | http://localhost:3000 (admin/admin)      |
| Prometheus    | http://localhost:9090                    |
| OPA           | http://localhost:8181                    |
| AI Engine     | http://localhost:5000/docs               |
| Elasticsearch | http://localhost:9201                    |

## Kubernetes Deployment

```bash
# Install Istio
istioctl install --set profile=default

# Apply all manifests
kubectl apply -f k8s/base/
kubectl apply -f k8s/gateway/
kubectl apply -f k8s/services/
kubectl apply -f k8s/monitoring/

# Check pods
kubectl get pods -n zero-trust

# Port-forward gateway
kubectl port-forward svc/zt-gateway-svc 8080:8080 -n zero-trust
```

## AI Model Details

**Algorithm**: Isolation Forest (unsupervised anomaly detection)
**Features**:
- Role encoding (student=0, professor=1, visitor=2, admin=3)
- Target service encoding
- HTTP method encoding
- Hour of day (UTC)
- Request rate — last 1 minute
- Request rate — last 5 minutes
- Unique services accessed in session
- IP address octet sum (rough geolocation proxy)

**Retraining**: Every 5 minutes from Elasticsearch logs (configurable via `MODEL_UPDATE_INTERVAL`)
**Contamination rate**: 5% (assumes 5% of traffic is anomalous during training)
**Enforcement**:
- risk_score > 0.85 → user flagged in OPA, future requests scrutinised
- risk_score > 0.95 → IP blocked automatically, OPA updated via Data API

## Policy Updates

OPA policies can be updated live without restart:

```bash
# Update policy via OPA Data API
curl -X PUT http://localhost:8181/v1/data/zerotrust/blocklist/ips \
  -d '["192.168.1.100", "10.0.0.50"]'

# Query current policy data
curl http://localhost:8181/v1/data/zerotrust

# Test a policy decision
curl -X POST http://localhost:8181/v1/data/zerotrust/authz/allow \
  -d '{"input":{"user":{"id":"u-001","role":"student"},"resource":{"service":"professor","method":"GET","path":"/api/professor/courses"},"context":{"ip":"1.2.3.4","timestamp":"2025-01-01T10:00:00Z","request_id":"test"}}}'
```

## Project Structure

```
zero-trust-ecosystem/
├── docker-compose.yml          # Full stack orchestration
├── gateway/                    # API Gateway (Node.js/Fastify)
│   ├── src/index.js            # Main gateway + routing + auth
│   └── src/metrics.js          # Prometheus metrics
├── services/
│   ├── student/src/index.js    # Student microservice
│   ├── professor/src/index.js  # Professor microservice
│   ├── visitor/src/index.js    # Public/visitor microservice
│   └── admin/                  # Admin microservice
├── policy-engine/
│   └── policies/
│       ├── authz.rego          # OPA RBAC + contextual policies (Rego)
│       └── data.json           # Initial policy data (blocklists, config)
├── ai-engine/
│   ├── main.py                 # FastAPI + IsolationForest AI engine
│   └── requirements.txt
├── logging/src/index.js        # Centralized log service (ES bridge)
├── monitoring/
│   ├── prometheus/
│   │   ├── prometheus.yml      # Scrape configuration
│   │   └── alerts.yml          # Alerting rules
│   └── grafana/                # Dashboard provisioning
├── k8s/
│   ├── base/
│   │   ├── namespace-rbac.yaml # Namespace, secrets, RBAC
│   │   └── istio-mtls.yaml     # Istio mTLS + AuthorizationPolicies
│   └── gateway/
│       └── deployment.yaml     # Gateway Deployment + HPA
└── scripts/
    ├── init.sql                # PostgreSQL schema + seed data
    └── simulate.py             # Load & penetration test simulator
```

"""
Zero-Trust AI Engine
====================
Stack: Python 3.12 · FastAPI · scikit-learn · Redis · asyncio

Responsibilities
----------------
1. Real-time risk scoring for every gateway request
2. Anomaly detection using Isolation Forest (trained on access logs)
3. Behavioral baseline tracking per user/role
4. Automated policy enforcement via OPA Data API
5. Insights aggregation for monitoring dashboards
6. Periodic model retraining from Elasticsearch logs
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

import numpy as np
import redis.asyncio as aioredis
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import httpx

# ── Configuration ──────────────────────────────────────────────────────────────
OPA_URL = os.getenv("OPA_URL", "http://opa:8181")
ES_URL  = os.getenv("ES_URL",  "http://elasticsearch:9200")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
MODEL_UPDATE_INTERVAL = int(os.getenv("MODEL_UPDATE_INTERVAL", 300))  # seconds
ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "-0.2"))     # IsolationForest score cutoff

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ai-engine")

app = FastAPI(title="Zero-Trust AI Engine", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Shared state ───────────────────────────────────────────────────────────────
redis_client: aioredis.Redis | None = None
model: IsolationForest | None = None
le_role    = LabelEncoder().fit(["student", "professor", "visitor", "admin", "unknown"])
le_service = LabelEncoder().fit(["student", "professor", "visitor", "admin", "unknown"])
le_method  = LabelEncoder().fit(["GET", "POST", "PUT", "DELETE", "PATCH", "unknown"])

# In-memory sliding windows for behavioral baselines (per user)
# Stores last 500 request timestamps per user
user_request_windows: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
user_service_counts: dict[str, dict] = defaultdict(lambda: defaultdict(int))

# Anomaly tracking
detected_anomalies: list[dict] = []
policy_adjustments: list[dict] = []
insights_cache: dict = {}

# ── Pydantic models ────────────────────────────────────────────────────────────
class ScoreRequest(BaseModel):
    userId: str
    role: str = "unknown"
    targetService: str = "unknown"
    ip: str = "0.0.0.0"
    method: str = "GET"

class EnforceRequest(BaseModel):
    userId: str
    role: str
    ip: str
    risk_score: float
    anomaly_flags: list[str]

# ── Feature extraction ─────────────────────────────────────────────────────────
def extract_features(req: ScoreRequest) -> np.ndarray:
    """
    Build a feature vector for anomaly scoring:
    [role_enc, service_enc, method_enc, hour_of_day,
     req_rate_1min, req_rate_5min, unique_services_1hr,
     ip_octets_sum]
    """
    now = time.time()
    window = user_request_windows[req.userId]
    window.append(now)

    # Request rate features
    one_min_ago = now - 60
    five_min_ago = now - 300
    rate_1m = sum(1 for t in window if t > one_min_ago)
    rate_5m = sum(1 for t in window if t > five_min_ago)

    # Service diversity
    user_service_counts[req.userId][req.targetService] += 1
    unique_svcs = len(user_service_counts[req.userId])

    # IP features
    try:
        ip_sum = sum(int(o) for o in req.ip.split("."))
    except Exception:
        ip_sum = 0

    hour = datetime.now(timezone.utc).hour

    role_enc    = le_role.transform([req.role if req.role in le_role.classes_ else "unknown"])[0]
    service_enc = le_service.transform([req.targetService if req.targetService in le_service.classes_ else "unknown"])[0]
    method_enc  = le_method.transform([req.method if req.method in le_method.classes_ else "unknown"])[0]

    return np.array([[
        role_enc, service_enc, method_enc,
        hour, rate_1m, rate_5m, unique_svcs, ip_sum
    ]], dtype=float)

# ── Anomaly detection ──────────────────────────────────────────────────────────
def detect_anomalies(features: np.ndarray, req: ScoreRequest) -> tuple[float, list[str]]:
    """Score a request and return (risk_score 0-1, anomaly_flags)."""
    flags: list[str] = []
    base_score = 0.0

    # IsolationForest scoring (trained model)
    if model is not None:
        iso_score = model.score_samples(features)[0]  # more negative = more anomalous
        iso_risk = max(0.0, min(1.0, (ANOMALY_THRESHOLD - iso_score) / abs(ANOMALY_THRESHOLD) + 0.3))
        base_score = max(base_score, iso_risk)
        if iso_score < ANOMALY_THRESHOLD:
            flags.append("isolation_forest_anomaly")

    # Heuristic rules (always active, complement the model)
    rate_1m = int(features[0][4])
    rate_5m = int(features[0][5])
    unique_svcs = int(features[0][6])

    if rate_1m > 50:
        flags.append("high_request_rate_1m")
        base_score = max(base_score, 0.7)

    if rate_5m > 150:
        flags.append("high_request_rate_5m")
        base_score = max(base_score, 0.6)

    if unique_svcs > 4:
        flags.append("excessive_service_enumeration")
        base_score = max(base_score, 0.75)

    # Role-specific heuristics
    if req.role == "visitor" and rate_1m > 10:
        flags.append("visitor_rate_exceeded")
        base_score = max(base_score, 0.65)

    if req.role == "student" and req.targetService in ("professor", "admin"):
        flags.append("unauthorized_service_attempt")
        base_score = max(base_score, 0.5)

    return round(min(1.0, base_score), 4), flags

# ── OPA data API integration ───────────────────────────────────────────────────
async def push_to_opa(path: str, data: Any) -> None:
    """Push live data (blocklists, anomaly scores) into OPA's data API."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.put(
                f"{OPA_URL}/v1/data/{path}",
                content=json.dumps(data),
                headers={"Content-Type": "application/json"},
            )
            log.info(f"OPA data updated: {path}")
    except Exception as e:
        log.warning(f"OPA push failed for {path}: {e}")

async def block_ip(ip: str, reason: str) -> None:
    """Add IP to OPA blocklist and record action."""
    await push_to_opa("zerotrust/blocklist/ips", [ip])
    policy_adjustments.append({
        "action": "block_ip",
        "ip": ip,
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    log.warning(f"IP blocked by AI engine: {ip} ({reason})")

async def flag_user_anomaly(user_id: str, score: float) -> None:
    """Inject anomaly score into OPA so it can gate future requests."""
    await push_to_opa(f"zerotrust/anomalies/users/{user_id}", {
        "anomaly_score": score,
        "flagged_at": datetime.now(timezone.utc).isoformat(),
    })

# ── Model training ─────────────────────────────────────────────────────────────
async def retrain_model() -> None:
    """Fetch recent logs from Elasticsearch and retrain IsolationForest."""
    global model
    log.info("Starting model retraining...")
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{ES_URL}/zt-logs-*/_search",
                json={
                    "size": 5000,
                    "query": {"range": {"timestamp": {"gte": "now-24h"}}},
                    "_source": ["role", "target_service", "method", "risk_score"],
                }
            )
            if resp.status_code != 200:
                log.warning("ES unavailable, skipping retrain")
                return

            hits = resp.json().get("hits", {}).get("hits", [])
            if len(hits) < 50:
                log.info(f"Not enough data for retraining ({len(hits)} samples)")
                return

            X = []
            for hit in hits:
                src = hit["_source"]
                role = src.get("role", "unknown")
                svc  = src.get("target_service", "unknown")
                meth = src.get("method", "unknown")
                role_enc = le_role.transform([role if role in le_role.classes_ else "unknown"])[0]
                svc_enc  = le_service.transform([svc if svc in le_service.classes_ else "unknown"])[0]
                meth_enc = le_method.transform([meth if meth in le_method.classes_ else "unknown"])[0]
                X.append([role_enc, svc_enc, meth_enc, 0, 0, 0, 0, 0])

            model = IsolationForest(n_estimators=150, contamination=0.05, random_state=42)
            model.fit(np.array(X))
            log.info(f"Model retrained on {len(X)} samples")

    except Exception as e:
        log.error(f"Retraining failed: {e}")

async def periodic_retrain() -> None:
    """Run model retraining on a schedule."""
    await asyncio.sleep(30)  # initial warm-up delay
    while True:
        await retrain_model()
        await asyncio.sleep(MODEL_UPDATE_INTERVAL)

# ── Startup ────────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global redis_client, model
    redis_client = aioredis.from_url(REDIS_URL, password="redispass", decode_responses=True)

    # Seed a basic model with synthetic normal traffic
    seed_data = np.array([
        [0, 0, 0, h, r, r*4, 1, 100]  # student, student svc, GET, various hours
        for h in range(24) for r in range(1, 20)
    ] + [
        [1, 1, 0, h, r, r*4, 2, 100]  # professor, professor svc, GET
        for h in range(24) for r in range(1, 20)
    ] + [
        [2, 2, 0, h, r, r*3, 1, 50]   # visitor, visitor svc, GET
        for h in range(7, 22) for r in range(1, 8)
    ])

    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(seed_data)
    log.info("AI engine started with seeded model")

    asyncio.create_task(periodic_retrain())

# ── API Endpoints ─────────────────────────────────────────────────────────────
@app.post("/score")
async def score_request(req: ScoreRequest, background_tasks: BackgroundTasks):
    """Real-time risk scoring for a single request."""
    features = extract_features(req)
    risk_score, anomaly_flags = detect_anomalies(features, req)

    if risk_score > 0.85:
        detected_anomalies.append({
            "user_id": req.userId,
            "role": req.role,
            "service": req.targetService,
            "risk_score": risk_score,
            "flags": anomaly_flags,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        # Push anomaly score into OPA asynchronously
        background_tasks.add_task(flag_user_anomaly, req.userId, risk_score)

    return {"risk_score": risk_score, "anomaly_flags": anomaly_flags}

@app.post("/enforce")
async def enforce_policy(req: EnforceRequest, background_tasks: BackgroundTasks):
    """
    Called by gateway when AI risk score is critical.
    Automatically tightens policy via OPA.
    """
    actions = []

    if req.risk_score > 0.95:
        background_tasks.add_task(block_ip, req.ip, f"critical_risk_score_{req.risk_score}")
        actions.append(f"ip_blocked:{req.ip}")

    if req.risk_score > 0.85:
        background_tasks.add_task(flag_user_anomaly, req.userId, req.risk_score)
        actions.append(f"user_anomaly_flagged:{req.userId}")

    log.warning(f"Enforcement triggered for user {req.userId}: {actions}")
    return {"actions": actions, "enforced": True}

@app.get("/insights")
async def get_insights():
    """Aggregated AI insights for the monitoring dashboard."""
    now = datetime.now(timezone.utc)

    # Compute role distribution from recent anomalies
    role_counts: dict[str, int] = defaultdict(int)
    service_counts: dict[str, int] = defaultdict(int)
    recent_anomalies = [a for a in detected_anomalies[-200:]]

    for a in recent_anomalies:
        role_counts[a["role"]] += 1
        service_counts[a["service"]] += 1

    return {
        "model_status": "active" if model is not None else "seeding",
        "total_anomalies_detected": len(detected_anomalies),
        "recent_anomalies": recent_anomalies[-20:],
        "policy_adjustments": policy_adjustments[-20:],
        "anomalies_by_role": dict(role_counts),
        "anomalies_by_service": dict(service_counts),
        "users_tracked": len(user_request_windows),
        "model_type": "IsolationForest",
        "features": ["role", "service", "method", "hour", "rate_1m", "rate_5m", "unique_svcs", "ip_sum"],
        "contamination_rate": 0.05,
        "timestamp": now.isoformat(),
    }

@app.get("/health")
async def health():
    return {"status": "ok", "model_ready": model is not None}

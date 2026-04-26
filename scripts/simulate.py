#!/usr/bin/env python3
"""
Zero-Trust Load & Penetration Simulation Script
================================================
Simulates realistic traffic patterns including:
  - Normal multi-role concurrent requests
  - Unauthorized access attempts
  - Brute-force simulation
  - Rate-limit testing
  - Session replay attacks

Usage:
  python3 simulate.py --gateway http://localhost:8080 --scenario all
"""

import argparse
import asyncio
import json
import sys
import time
from dataclasses import dataclass
from typing import Optional

import httpx

# ── Config ─────────────────────────────────────────────────────────────────────
USERS = {
    "student":   {"username": "student@uni.edu",   "password": "student123"},
    "professor": {"username": "professor@uni.edu",  "password": "professor123"},
    "visitor":   {"username": "visitor@uni.edu",    "password": "visitor123"},
}

ENDPOINTS = {
    "student":   ["/api/student/grades", "/api/student/schedule", "/api/student/profile"],
    "professor": ["/api/professor/courses", "/api/professor/profile"],
    "visitor":   ["/api/visitor/catalog", "/api/visitor/events", "/api/visitor/announcements"],
    "admin":     ["/api/admin/users"],          # Should be forbidden for all non-admin
    "cross":     ["/api/professor/courses"],    # Student trying to reach professor svc
}

COLORS = {
    "green":  "\033[92m",
    "red":    "\033[91m",
    "yellow": "\033[93m",
    "blue":   "\033[94m",
    "reset":  "\033[0m",
    "bold":   "\033[1m",
}

def c(color, text): return f"{COLORS[color]}{text}{COLORS['reset']}"

@dataclass
class Result:
    role: str
    endpoint: str
    status: int
    latency_ms: float
    decision: str
    risk_score: Optional[float] = None

results: list[Result] = []

# ── Auth ───────────────────────────────────────────────────────────────────────
async def login(client: httpx.AsyncClient, gateway: str, role: str) -> Optional[str]:
    creds = USERS[role]
    try:
        resp = await client.post(f"{gateway}/auth/login", json=creds, timeout=10)
        if resp.status_code == 200:
            return resp.json()["token"]
    except Exception as e:
        print(c("red", f"  Login failed for {role}: {e}"))
    return None

# ── Request ────────────────────────────────────────────────────────────────────
async def make_request(client: httpx.AsyncClient, gateway: str, token: str, role: str, endpoint: str) -> Result:
    headers = {"Authorization": f"Bearer {token}"}
    t0 = time.perf_counter()
    try:
        resp = await client.get(f"{gateway}{endpoint}", headers=headers, timeout=10)
        latency = (time.perf_counter() - t0) * 1000
        risk = float(resp.headers.get("x-risk-score", 0))
        decision = "ALLOW" if resp.status_code < 400 else "DENY"
        return Result(role=role, endpoint=endpoint, status=resp.status_code,
                     latency_ms=round(latency, 1), decision=decision, risk_score=risk)
    except Exception as e:
        latency = (time.perf_counter() - t0) * 1000
        return Result(role=role, endpoint=endpoint, status=0,
                     latency_ms=round(latency, 1), decision="ERROR")

def print_result(r: Result):
    icon = "✓" if r.decision == "ALLOW" else "✗"
    color = "green" if r.decision == "ALLOW" else "red"
    risk_str = f"  risk={r.risk_score:.2f}" if r.risk_score else ""
    print(f"  {c(color, icon)} [{r.role:>10}] {r.endpoint:<40} {r.status}  {r.latency_ms:>7.1f}ms{risk_str}")

# ── Scenarios ─────────────────────────────────────────────────────────────────

async def scenario_normal_traffic(gateway: str, iterations: int = 5):
    """Normal traffic — each role accesses its permitted services."""
    print(c("bold", f"\n{'='*60}"))
    print(c("bold", "SCENARIO 1: Normal multi-role traffic"))
    print(c("bold", f"{'='*60}"))

    async with httpx.AsyncClient() as client:
        tokens = {}
        for role in USERS:
            tok = await login(client, gateway, role)
            if tok:
                tokens[role] = tok
                print(c("blue", f"  ✓ Logged in as {role}"))

        for i in range(iterations):
            print(f"\n  Round {i+1}/{iterations}")
            tasks = []
            for role, token in tokens.items():
                for ep in ENDPOINTS.get(role, []):
                    tasks.append(make_request(client, gateway, token, role, ep))

            batch = await asyncio.gather(*tasks)
            for r in batch:
                print_result(r)
                results.append(r)

async def scenario_unauthorized_access(gateway: str):
    """Roles attempting to access services they're not permitted to."""
    print(c("bold", f"\n{'='*60}"))
    print(c("bold", "SCENARIO 2: Unauthorized access attempts"))
    print(c("bold", f"{'='*60}"))

    CROSS_ATTEMPTS = [
        ("student",   "/api/professor/courses"),
        ("student",   "/api/admin/users"),
        ("visitor",   "/api/student/grades"),
        ("visitor",   "/api/professor/courses"),
        ("professor", "/api/admin/users"),
    ]

    async with httpx.AsyncClient() as client:
        tokens = {role: await login(client, gateway, role) for role in USERS}

        for role, endpoint in CROSS_ATTEMPTS:
            token = tokens.get(role)
            if not token:
                continue
            r = await make_request(client, gateway, token, role, endpoint)
            print_result(r)
            expected = "DENY"
            status = c("green", "CORRECT") if r.decision == expected else c("red", "POLICY BREACH!")
            print(f"    → Expected: {expected}  Got: {r.decision}  {status}")
            results.append(r)

async def scenario_brute_force(gateway: str):
    """Simulate a brute-force login attempt — should trigger rate limiting."""
    print(c("bold", f"\n{'='*60}"))
    print(c("bold", "SCENARIO 3: Brute-force login simulation"))
    print(c("bold", f"{'='*60}"))

    async with httpx.AsyncClient() as client:
        tasks = [
            client.post(f"{gateway}/auth/login",
                       json={"username": "student@uni.edu", "password": f"wrong{i}"},
                       timeout=5)
            for i in range(30)
        ]
        t0 = time.perf_counter()
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.perf_counter() - t0

        status_counts: dict[int, int] = {}
        for r in responses:
            if isinstance(r, Exception):
                status_counts[0] = status_counts.get(0, 0) + 1
            else:
                status_counts[r.status_code] = status_counts.get(r.status_code, 0) + 1

        print(f"  Sent 30 bad-credential requests in {elapsed:.1f}s")
        for code, count in sorted(status_counts.items()):
            label = "Unauthorized" if code == 401 else "Rate Limited" if code == 429 else str(code)
            color = "green" if code == 429 else "yellow"
            print(f"  {c(color, f'HTTP {code} ({label})')}: {count} responses")

        rate_limited = status_counts.get(429, 0)
        if rate_limited > 0:
            print(c("green", f"\n  ✓ Rate limiter triggered correctly ({rate_limited} requests blocked)"))
        else:
            print(c("yellow", f"\n  ⚠ Rate limiter not triggered — check Redis config"))

async def scenario_concurrent_load(gateway: str, workers: int = 20):
    """High-concurrency load test."""
    print(c("bold", f"\n{'='*60}"))
    print(c("bold", f"SCENARIO 4: Concurrent load ({workers} workers)"))
    print(c("bold", f"{'='*60}"))

    async with httpx.AsyncClient() as client:
        token = await login(client, gateway, "student")
        if not token:
            print(c("red", "  Failed to get token"))
            return

        tasks = [
            make_request(client, gateway, token, "student", "/api/student/grades")
            for _ in range(workers)
        ]
        t0 = time.perf_counter()
        batch = await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - t0

        latencies = [r.latency_ms for r in batch]
        allow_count = sum(1 for r in batch if r.decision == "ALLOW")
        deny_count  = sum(1 for r in batch if r.decision == "DENY")

        print(f"  Completed {workers} concurrent requests in {elapsed*1000:.0f}ms")
        print(f"  {c('green', f'Allowed: {allow_count}')}  {c('red', f'Denied: {deny_count}')}")
        print(f"  Latency — min: {min(latencies):.0f}ms  avg: {sum(latencies)/len(latencies):.0f}ms  max: {max(latencies):.0f}ms")

def print_summary():
    print(c("bold", f"\n{'='*60}"))
    print(c("bold", "SUMMARY"))
    print(c("bold", f"{'='*60}"))

    total  = len(results)
    allow  = sum(1 for r in results if r.decision == "ALLOW")
    deny   = sum(1 for r in results if r.decision == "DENY")
    errors = sum(1 for r in results if r.decision == "ERROR")

    print(f"  Total requests : {total}")
    print(f"  {c('green', f'Allowed        : {allow}')}")
    print(f"  {c('red',   f'Denied         : {deny}')}")
    print(f"  Errors         : {errors}")

    if results:
        lats = [r.latency_ms for r in results if r.latency_ms > 0]
        if lats:
            print(f"  Avg latency    : {sum(lats)/len(lats):.1f}ms")
            print(f"  P95 latency    : {sorted(lats)[int(len(lats)*0.95)]:.1f}ms")

async def main():
    parser = argparse.ArgumentParser(description="Zero-Trust simulation")
    parser.add_argument("--gateway", default="http://localhost:8080")
    parser.add_argument("--scenario", choices=["normal","unauth","brute","load","all"], default="all")
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--iterations", type=int, default=3)
    args = parser.parse_args()

    print(c("bold", f"Zero-Trust Ecosystem Simulation"))
    print(f"Gateway: {args.gateway}\n")

    if args.scenario in ("normal", "all"):
        await scenario_normal_traffic(args.gateway, args.iterations)
    if args.scenario in ("unauth", "all"):
        await scenario_unauthorized_access(args.gateway)
    if args.scenario in ("brute", "all"):
        await scenario_brute_force(args.gateway)
    if args.scenario in ("load", "all"):
        await scenario_concurrent_load(args.gateway, args.workers)

    print_summary()

if __name__ == "__main__":
    asyncio.run(main())

/**
 * Centralized Log Service
 * Stack: Node.js · Fastify · Elasticsearch · Redis Pub/Sub
 *
 * Receives structured audit events from the gateway and services,
 * indexes them into Elasticsearch, and forwards anomalies to the AI engine.
 */

import Fastify from "fastify";
import { createClient } from "redis";
import fetch from "node-fetch";
import { randomUUID } from "crypto";

const {
  PORT = 9200,
  ES_URL = "http://elasticsearch:9201",
  REDIS_URL,
  AI_ENGINE_URL,
} = process.env;

const app = Fastify({ logger: true });

const redis = createClient({ url: REDIS_URL, password: "redispass" });
await redis.connect();

// ── Elasticsearch helpers ──────────────────────────────────────────────────────
function indexName() {
  const d = new Date();
  return `zt-logs-${d.getFullYear()}.${String(d.getMonth() + 1).padStart(2, "0")}`;
}

async function indexDocument(doc) {
  await fetch(`${ES_URL}/${indexName()}/_doc`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...doc, "@timestamp": doc.timestamp ?? new Date().toISOString() }),
  });
}

// Alert thresholds
const ALERT_RULES = [
  { field: "decision", value: "DENY",    threshold: 5,  window: 60,  alert: "excessive_denials" },
  { field: "event",    value: "ATTACK",  threshold: 1,  window: 30,  alert: "attack_detected" },
];

// Sliding window counters (in-memory, production would use Redis)
const counters: Record<string, { count: number; resetAt: number }> = {};

function checkAlertRules(log) {
  for (const rule of ALERT_RULES) {
    if (log[rule.field] !== rule.value) continue;

    const key = rule.alert;
    const now = Date.now();
    if (!counters[key] || counters[key].resetAt < now) {
      counters[key] = { count: 0, resetAt: now + rule.window * 1000 };
    }

    counters[key].count++;
    if (counters[key].count >= rule.threshold) {
      triggerAlert(rule.alert, log);
      counters[key].count = 0; // reset to prevent alert storm
    }
  }
}

async function triggerAlert(type, context) {
  const alert = {
    type,
    severity: type === "attack_detected" ? "critical" : "high",
    context,
    timestamp: new Date().toISOString(),
    alert_id: randomUUID(),
  };

  // Push alert to Redis for real-time dashboard
  await redis.publish("alerts", JSON.stringify(alert));
  // Index the alert separately
  await indexDocument({ ...alert, _type: "alert" });
  app.log.warn(`ALERT [${type}]: ${JSON.stringify(context)}`);
}

// ── Routes ─────────────────────────────────────────────────────────────────────
app.post("/log", async (req, reply) => {
  const doc = req.body;

  // Fire-and-forget indexing
  indexDocument(doc).catch(() => {});
  checkAlertRules(doc);

  // Forward high-risk events to AI engine
  if (doc.risk_score > 0.6 || doc.anomaly_flags?.length > 0) {
    fetch(`${AI_ENGINE_URL}/score`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        userId: doc.user_id,
        role: doc.role,
        targetService: doc.target_service,
        ip: doc.ip,
        method: doc.method,
      }),
    }).catch(() => {});
  }

  return reply.code(202).send({ status: "accepted" });
});

app.get("/logs/recent", async (req, reply) => {
  const { limit = 50 } = req.query ?? {};
  const res = await fetch(`${ES_URL}/${indexName()}/_search`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      size: Number(limit),
      sort: [{ "@timestamp": { order: "desc" } }],
      query: { match_all: {} },
    }),
  });

  if (!res.ok) return reply.send({ data: [], error: "ES unavailable" });
  const { hits } = await res.json();
  return reply.send({ data: hits.hits.map((h) => h._source) });
});

app.get("/logs/stats", async (req, reply) => {
  const res = await fetch(`${ES_URL}/${indexName()}/_search`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      size: 0,
      aggs: {
        decisions: { terms: { field: "decision.keyword", size: 5 } },
        roles:     { terms: { field: "role.keyword",     size: 10 } },
        services:  { terms: { field: "target_service.keyword", size: 10 } },
        avg_risk:  { avg: { field: "risk_score" } },
      },
    }),
  });

  if (!res.ok) return reply.send({ error: "ES unavailable" });
  const body = await res.json();
  return reply.send({ aggregations: body.aggregations });
});

app.get("/health", async () => ({ status: "ok" }));

await app.listen({ port: Number(PORT), host: "0.0.0.0" });

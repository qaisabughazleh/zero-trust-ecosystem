/**
 * Zero-Trust API Gateway
 * Stack: Node.js 20 · Fastify · JWT · OPA · Redis
 *
 * Responsibilities:
 *  - Mutual-TLS termination (handled by sidecar/ingress in prod)
 *  - JWT validation on every request
 *  - OPA policy evaluation (RBAC + fine-grained rules)
 *  - Rate limiting via Redis
 *  - Request routing to microservices
 *  - Structured audit logging → Log Service
 *  - AI Engine consultation for risk scoring
 *  - Periodic re-authentication enforcement
 */

import Fastify from "fastify";
import fastifyJwt from "@fastify/jwt";
import fastifyRateLimit from "@fastify/rate-limit";
import fastifyHttpProxy from "@fastify/http-proxy";
import { createClient } from "redis";
import fetch from "node-fetch";
import { randomUUID } from "crypto";
import { metrics } from "./metrics.js";

const {
  PORT = 8080,
  OPA_URL,
  AUTH_SECRET,
  REDIS_URL,
  LOG_SERVICE_URL,
  AI_ENGINE_URL,
  STUDENT_SVC_URL,
  PROFESSOR_SVC_URL,
  VISITOR_SVC_URL,
  ADMIN_SVC_URL,
} = process.env;

// ── Fastify instance ──────────────────────────────────────────────────────────
const app = Fastify({
  logger: { level: "info", serializers: { req: (r) => ({ method: r.method, url: r.url }) } },
  trustProxy: true,
  requestIdHeader: "x-request-id",
  genReqId: () => randomUUID(),
});

// ── Redis client ──────────────────────────────────────────────────────────────
const redis = createClient({ url: REDIS_URL });
await redis.connect();

// ── Plugins ───────────────────────────────────────────────────────────────────
await app.register(fastifyJwt, { secret: AUTH_SECRET });
await app.register(fastifyRateLimit, {
  global: true,
  max: 200,
  timeWindow: "1 minute",
  redis,
  keyGenerator: (req) => req.ip + ":" + (req.headers["x-role"] ?? "unknown"),
  errorResponseBuilder: (req, context) => ({
    code: 429,
    error: "Too Many Requests",
    message: `Rate limit exceeded. Try again in ${context.after}`,
    requestId: req.id,
  }),
});

// ── Helpers ───────────────────────────────────────────────────────────────────
async function evaluatePolicy(input) {
  const res = await fetch(`${OPA_URL}/v1/data/zerotrust/authz/allow`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input }),
  });
  const { result } = await res.json();
  return !!result;
}

async function getRiskScore(requestData) {
  try {
    const res = await fetch(`${AI_ENGINE_URL}/score`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestData),
      signal: AbortSignal.timeout(500), // non-blocking – fail open
    });
    const { risk_score, anomaly_flags } = await res.json();
    return { risk_score, anomaly_flags };
  } catch {
    return { risk_score: 0, anomaly_flags: [] };
  }
}

async function auditLog(entry) {
  const payload = {
    timestamp: new Date().toISOString(),
    ...entry,
  };
  // Fire-and-forget – don't block the request path
  fetch(`${LOG_SERVICE_URL}/log`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  }).catch(() => {});
  // Also push to Redis pub/sub for real-time dashboard
  redis.publish("audit-log", JSON.stringify(payload)).catch(() => {});
}

function sessionKey(userId) {
  return `session:${userId}`;
}

const REAUTH_TTL = 30 * 60; // 30 minutes of inactivity forces re-auth

// ── Auth decorator ─────────────────────────────────────────────────────────────
app.decorate("authenticate", async (req, reply) => {
  try {
    await req.jwtVerify();
  } catch {
    metrics.authFailures.inc();
    reply.code(401).send({ error: "Unauthorized", message: "Invalid or missing JWT" });
    return;
  }

  const { sub: userId, role } = req.user;

  // Zero-trust: verify session is still alive in Redis (continuous validation)
  const sessionTTL = await redis.ttl(sessionKey(userId));
  if (sessionTTL === -2) {
    metrics.reauthRequired.inc();
    reply.code(401).send({
      error: "Session Expired",
      message: "Re-authentication required",
      reauth_required: true,
    });
    return;
  }

  // Slide the session window on activity
  await redis.expire(sessionKey(userId), REAUTH_TTL);
});

// ── Core RBAC + OPA middleware ────────────────────────────────────────────────
async function authorize(req, reply, targetService) {
  const { sub: userId, role, email } = req.user;
  const ip = req.ip;
  const requestId = req.id;

  // 1. OPA policy evaluation
  const opaInput = {
    user: { id: userId, role, email },
    resource: { service: targetService, method: req.method, path: req.url },
    context: { ip, timestamp: new Date().toISOString(), request_id: requestId },
  };

  const [allowed, { risk_score, anomaly_flags }] = await Promise.all([
    evaluatePolicy(opaInput),
    getRiskScore({ userId, role, targetService, ip, method: req.method }),
  ]);

  // 2. AI risk gate – block even if OPA allows, if risk is critical
  const blocked = !allowed || risk_score > 0.9;

  // 3. Audit every decision
  await auditLog({
    request_id: requestId,
    user_id: userId,
    role,
    target_service: targetService,
    method: req.method,
    path: req.url,
    ip,
    decision: blocked ? "DENY" : "ALLOW",
    opa_result: allowed,
    risk_score,
    anomaly_flags,
  });

  if (blocked) {
    const reason = !allowed ? "policy_violation" : "ai_risk_threshold";
    metrics.requestsDenied.labels({ service: targetService, reason }).inc();

    if (risk_score > 0.9) {
      // Trigger automated policy tightening via AI engine
      fetch(`${AI_ENGINE_URL}/enforce`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, role, ip, risk_score, anomaly_flags }),
      }).catch(() => {});
    }

    reply.code(403).send({
      error: "Forbidden",
      message: "Access denied by policy",
      request_id: requestId,
      reason,
    });
    return false;
  }

  metrics.requestsAllowed.labels({ service: targetService }).inc();
  req.headers["x-user-id"] = userId;
  req.headers["x-user-role"] = role;
  req.headers["x-request-id"] = requestId;
  req.headers["x-risk-score"] = String(risk_score);
  return true;
}

// ── Auth endpoint ──────────────────────────────────────────────────────────────
app.post("/auth/login", async (req, reply) => {
  const { username, password, role } = req.body ?? {};

  // In production: validate against IdP (Keycloak / LDAP)
  const MOCK_USERS = {
    "student@uni.edu":   { password: "student123",   role: "student",   id: "u-001" },
    "professor@uni.edu": { password: "professor123",  role: "professor", id: "u-002" },
    "visitor@uni.edu":   { password: "visitor123",    role: "visitor",   id: "u-003" },
    "admin@uni.edu":     { password: "admin123",      role: "admin",     id: "u-004" },
  };

  const user = MOCK_USERS[username];
  if (!user || user.password !== password) {
    metrics.authFailures.inc();
    return reply.code(401).send({ error: "Invalid credentials" });
  }

  const token = app.jwt.sign(
    { sub: user.id, email: username, role: user.role },
    { expiresIn: "1h" }
  );

  // Register session in Redis
  await redis.setEx(sessionKey(user.id), REAUTH_TTL, JSON.stringify({ role: user.role, loginAt: Date.now() }));

  await auditLog({ event: "LOGIN", user_id: user.id, role: user.role, ip: req.ip });
  metrics.logins.labels({ role: user.role }).inc();

  return reply.send({ token, role: user.role, expires_in: 3600 });
});

app.post("/auth/logout", { onRequest: [app.authenticate] }, async (req, reply) => {
  await redis.del(sessionKey(req.user.sub));
  await auditLog({ event: "LOGOUT", user_id: req.user.sub, role: req.user.role });
  return reply.send({ message: "Logged out" });
});

// ── Service routes ─────────────────────────────────────────────────────────────
const SERVICE_MAP = {
  "student":   STUDENT_SVC_URL,
  "professor": PROFESSOR_SVC_URL,
  "visitor":   VISITOR_SVC_URL,
  "admin":     ADMIN_SVC_URL,
};

for (const [svcName, upstream] of Object.entries(SERVICE_MAP)) {
  app.register(async (instance) => {
    instance.addHook("onRequest", instance.authenticate);
    instance.addHook("preHandler", async (req, reply) => {
      const ok = await authorize(req, reply, svcName);
      if (!ok) return; // reply already sent
    });

    // Proxy all matching traffic upstream
    instance.register(fastifyHttpProxy, {
      upstream,
      prefix: `/api/${svcName}`,
      rewritePrefix: `/api/${svcName}`,
      http2: false,
    });
  });
}

// ── Policy management endpoints (admin only) ──────────────────────────────────
app.get("/admin/policies", { onRequest: [app.authenticate] }, async (req, reply) => {
  if (req.user.role !== "admin") return reply.code(403).send({ error: "Forbidden" });
  const res = await fetch(`${OPA_URL}/v1/data/zerotrust`);
  return reply.send(await res.json());
});

app.put("/admin/policies", { onRequest: [app.authenticate] }, async (req, reply) => {
  if (req.user.role !== "admin") return reply.code(403).send({ error: "Forbidden" });
  const res = await fetch(`${OPA_URL}/v1/policies/zerotrust`, {
    method: "PUT",
    headers: { "Content-Type": "text/plain" },
    body: req.body,
  });
  await auditLog({ event: "POLICY_UPDATE", admin_id: req.user.sub });
  return reply.send({ status: res.ok ? "updated" : "error" });
});

// ── AI insights endpoint ───────────────────────────────────────────────────────
app.get("/admin/ai/insights", { onRequest: [app.authenticate] }, async (req, reply) => {
  if (req.user.role !== "admin") return reply.code(403).send({ error: "Forbidden" });
  const res = await fetch(`${AI_ENGINE_URL}/insights`);
  return reply.send(await res.json());
});

// ── Health / metrics ──────────────────────────────────────────────────────────
app.get("/health", async () => ({ status: "ok", timestamp: new Date().toISOString() }));
app.get("/metrics", async (req, reply) => {
  reply.header("Content-Type", metrics.register.contentType);
  return metrics.register.metrics();
});

// ── Start ─────────────────────────────────────────────────────────────────────
await app.listen({ port: Number(PORT), host: "0.0.0.0" });
app.log.info(`Gateway listening on :${PORT}`);

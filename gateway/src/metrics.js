import { Registry, Counter, Histogram, Gauge } from "prom-client";

export const register = new Registry();

export const metrics = {
  register,

  requestsAllowed: new Counter({
    name: "zt_gateway_requests_allowed_total",
    help: "Total allowed requests by service",
    labelNames: ["service"],
    registers: [register],
  }),

  requestsDenied: new Counter({
    name: "zt_gateway_requests_denied_total",
    help: "Total denied requests by service and reason",
    labelNames: ["service", "reason"],
    registers: [register],
  }),

  authFailures: new Counter({
    name: "zt_gateway_auth_failures_total",
    help: "Total authentication failures",
    registers: [register],
  }),

  reauthRequired: new Counter({
    name: "zt_gateway_reauth_required_total",
    help: "Sessions requiring re-authentication",
    registers: [register],
  }),

  logins: new Counter({
    name: "zt_gateway_logins_total",
    help: "Total logins by role",
    labelNames: ["role"],
    registers: [register],
  }),

  requestDuration: new Histogram({
    name: "zt_gateway_request_duration_ms",
    help: "Request duration in milliseconds",
    labelNames: ["service", "method", "status"],
    buckets: [5, 10, 25, 50, 100, 250, 500, 1000],
    registers: [register],
  }),

  activeConnections: new Gauge({
    name: "zt_gateway_active_connections",
    help: "Currently active connections",
    registers: [register],
  }),

  riskScore: new Histogram({
    name: "zt_ai_risk_score",
    help: "AI risk scores distribution",
    labelNames: ["role", "service"],
    buckets: [0.1, 0.2, 0.3, 0.5, 0.7, 0.9, 1.0],
    registers: [register],
  }),
};

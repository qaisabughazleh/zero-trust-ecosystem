/**
 * Student Microservice
 * Stack: Node.js · Fastify · PostgreSQL
 *
 * Zero-trust: validates every inbound request independently,
 * even after the gateway has already authorised it.
 * (Defence-in-depth — never trust the gateway alone.)
 */

import Fastify from "fastify";
import postgres from "postgres";
import fetch from "node-fetch";
import { randomUUID } from "crypto";

const { PORT = 3001, DB_URL, OPA_URL, SERVICE_NAME = "student-svc" } = process.env;

const app = Fastify({ logger: true, genReqId: () => randomUUID() });
const sql = postgres(DB_URL);

// ── Internal OPA check (defence-in-depth) ─────────────────────────────────────
async function verifyInternalPolicy(req, reply) {
  const userId  = req.headers["x-user-id"];
  const role    = req.headers["x-user-role"];
  const reqId   = req.headers["x-request-id"] ?? req.id;

  if (!userId || !role) {
    return reply.code(401).send({ error: "Missing internal auth headers" });
  }

  const opaRes = await fetch(`${OPA_URL}/v1/data/zerotrust/authz/allow`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      input: {
        user: { id: userId, role },
        resource: { service: "student", method: req.method, path: req.url },
        context: { ip: req.ip, timestamp: new Date().toISOString(), request_id: reqId },
      },
    }),
  });

  const { result } = await opaRes.json();
  if (!result) {
    return reply.code(403).send({ error: "Service-level policy denied" });
  }

  req.userId = userId;
  req.userRole = role;
}

app.addHook("preHandler", verifyInternalPolicy);

// ── Routes ────────────────────────────────────────────────────────────────────

// GET /api/student/grades — students see only their own; professors see course-scoped
app.get("/api/student/grades", async (req, reply) => {
  const { userId, userRole } = req;

  let rows;
  if (userRole === "student") {
    // Data filter: own records only (enforced by OPA data_filter rule)
    rows = await sql`
      SELECT g.course_id, c.name, g.grade, g.semester
      FROM grades g
      JOIN courses c ON c.id = g.course_id
      WHERE g.student_id = ${userId}
      ORDER BY g.semester DESC
    `;
  } else if (userRole === "professor") {
    // Professors see grades for courses they teach
    rows = await sql`
      SELECT g.student_id, g.course_id, c.name, g.grade, g.semester
      FROM grades g
      JOIN courses c ON c.id = g.course_id
      WHERE c.professor_id = ${userId}
      ORDER BY g.semester DESC, c.name
    `;
  } else {
    return reply.code(403).send({ error: "Forbidden" });
  }

  return reply.send({ data: rows, count: rows.length });
});

// GET /api/student/schedule
app.get("/api/student/schedule", async (req, reply) => {
  const { userId, userRole } = req;
  if (userRole !== "student") return reply.code(403).send({ error: "Forbidden" });

  const rows = await sql`
    SELECT e.course_id, c.name, c.credits, c.room, c.schedule_time
    FROM enrollments e
    JOIN courses c ON c.id = e.course_id
    WHERE e.student_id = ${userId}
    ORDER BY c.schedule_time
  `;

  return reply.send({ data: rows });
});

// GET /api/student/profile
app.get("/api/student/profile", async (req, reply) => {
  const { userId, userRole } = req;
  if (userRole !== "student") return reply.code(403).send({ error: "Forbidden" });

  const [profile] = await sql`
    SELECT id, name, email, department, enrolled_year
    FROM students
    WHERE id = ${userId}
  `;

  return reply.send({ data: profile ?? null });
});

// GET /api/student/list — professors/admin only
app.get("/api/student/list", async (req, reply) => {
  const { userRole } = req;
  if (!["professor", "admin"].includes(userRole)) {
    return reply.code(403).send({ error: "Forbidden" });
  }

  const rows = await sql`
    SELECT id, name, department, enrolled_year
    FROM students
    ORDER BY name
    LIMIT 100
  `;

  return reply.send({ data: rows, count: rows.length });
});

app.get("/health", async () => ({
  status: "ok",
  service: SERVICE_NAME,
  timestamp: new Date().toISOString(),
}));

await app.listen({ port: Number(PORT), host: "0.0.0.0" });

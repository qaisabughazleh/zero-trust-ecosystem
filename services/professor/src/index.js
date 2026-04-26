/**
 * Professor Microservice
 * Stack: Node.js · Fastify · PostgreSQL
 */

import Fastify from "fastify";
import postgres from "postgres";
import fetch from "node-fetch";
import { randomUUID } from "crypto";

const { PORT = 3002, DB_URL, OPA_URL, SERVICE_NAME = "professor-svc" } = process.env;

const app = Fastify({ logger: true, genReqId: () => randomUUID() });
const sql = postgres(DB_URL);

// ── Defence-in-depth OPA check (same pattern as student-svc) ─────────────────
async function verifyInternalPolicy(req, reply) {
  const userId = req.headers["x-user-id"];
  const role   = req.headers["x-user-role"];
  if (!userId || !role) return reply.code(401).send({ error: "Missing internal auth headers" });

  const opaRes = await fetch(`${OPA_URL}/v1/data/zerotrust/authz/allow`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      input: {
        user: { id: userId, role },
        resource: { service: "professor", method: req.method, path: req.url },
        context: { ip: req.ip, timestamp: new Date().toISOString(), request_id: req.id },
      },
    }),
  });

  const { result } = await opaRes.json();
  if (!result) return reply.code(403).send({ error: "Service-level policy denied" });

  req.userId = userId;
  req.userRole = role;
}

app.addHook("preHandler", verifyInternalPolicy);

// ── Routes ─────────────────────────────────────────────────────────────────────

// GET /api/professor/courses — list courses taught by this professor
app.get("/api/professor/courses", async (req, reply) => {
  const { userId, userRole } = req;

  if (userRole !== "professor" && userRole !== "admin") {
    return reply.code(403).send({ error: "Forbidden" });
  }

  const filter = userRole === "professor"
    ? sql`WHERE professor_id = ${userId}`
    : sql``;

  const rows = await sql`
    SELECT c.id, c.name, c.credits, c.room, c.schedule_time,
           COUNT(e.student_id) AS enrolled_count
    FROM courses c
    LEFT JOIN enrollments e ON e.course_id = c.id
    ${filter}
    GROUP BY c.id
    ORDER BY c.name
  `;

  return reply.send({ data: rows });
});

// POST /api/professor/grades — submit / update a grade
app.post("/api/professor/grades", async (req, reply) => {
  const { userId, userRole } = req;
  if (userRole !== "professor") return reply.code(403).send({ error: "Forbidden" });

  const { student_id, course_id, grade, semester } = req.body ?? {};

  // Verify professor teaches this course
  const [course] = await sql`
    SELECT id FROM courses WHERE id = ${course_id} AND professor_id = ${userId}
  `;
  if (!course) return reply.code(403).send({ error: "Not your course" });

  await sql`
    INSERT INTO grades (student_id, course_id, grade, semester, submitted_by, submitted_at)
    VALUES (${student_id}, ${course_id}, ${grade}, ${semester}, ${userId}, NOW())
    ON CONFLICT (student_id, course_id, semester)
    DO UPDATE SET grade = EXCLUDED.grade, submitted_at = NOW()
  `;

  return reply.send({ status: "ok" });
});

// GET /api/professor/profile
app.get("/api/professor/profile", async (req, reply) => {
  const { userId, userRole } = req;
  if (userRole !== "professor") return reply.code(403).send({ error: "Forbidden" });

  const [profile] = await sql`
    SELECT id, name, email, department, title FROM professors WHERE id = ${userId}
  `;
  return reply.send({ data: profile ?? null });
});

app.get("/health", async () => ({
  status: "ok",
  service: SERVICE_NAME,
  timestamp: new Date().toISOString(),
}));

await app.listen({ port: Number(PORT), host: "0.0.0.0" });

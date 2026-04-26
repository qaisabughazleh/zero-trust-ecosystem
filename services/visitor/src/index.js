/**
 * Visitor (Public) Microservice
 * Read-only public endpoints — catalog, events, announcements
 * Accessible to all roles; no auth required for data (but gateway still validates)
 */

import Fastify from "fastify";
import postgres from "postgres";
import { randomUUID } from "crypto";

const { PORT = 3003, DB_URL, SERVICE_NAME = "visitor-svc" } = process.env;

const app = Fastify({ logger: true, genReqId: () => randomUUID() });
const sql = postgres(DB_URL);

// GET /api/visitor/catalog — public course catalog
app.get("/api/visitor/catalog", async (req, reply) => {
  const { department, search } = req.query ?? {};

  let rows = await sql`
    SELECT c.id, c.name, c.description, c.credits, c.department,
           p.name AS professor_name, c.schedule_time
    FROM courses c
    JOIN professors p ON p.id = c.professor_id
    WHERE c.is_public = true
    ${department ? sql`AND c.department = ${department}` : sql``}
    ${search ? sql`AND (c.name ILIKE ${"%" + search + "%"} OR c.description ILIKE ${"%" + search + "%"})` : sql``}
    ORDER BY c.department, c.name
    LIMIT 50
  `;

  return reply.send({ data: rows, count: rows.length });
});

// GET /api/visitor/events — public events
app.get("/api/visitor/events", async (req, reply) => {
  const rows = await sql`
    SELECT id, title, description, event_date, location, organizer
    FROM events
    WHERE event_date >= NOW()
    ORDER BY event_date
    LIMIT 20
  `;
  return reply.send({ data: rows });
});

// GET /api/visitor/announcements
app.get("/api/visitor/announcements", async (req, reply) => {
  const rows = await sql`
    SELECT id, title, body, published_at, category
    FROM announcements
    WHERE is_public = true
    ORDER BY published_at DESC
    LIMIT 10
  `;
  return reply.send({ data: rows });
});

app.get("/health", async () => ({
  status: "ok",
  service: SERVICE_NAME,
  timestamp: new Date().toISOString(),
}));

await app.listen({ port: Number(PORT), host: "0.0.0.0" });

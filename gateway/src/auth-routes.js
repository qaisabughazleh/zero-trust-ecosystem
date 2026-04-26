/**
 * Public Auth API — /api/auth/*
 * ==============================
 * Fully public endpoints that issue role-based JWT tokens.
 * These are the ONLY unauthenticated routes in the system.
 *
 * POST /api/auth/token       — issue token (username + password)
 * POST /api/auth/token/guest — issue visitor token (no credentials)
 * POST /api/auth/refresh     — refresh an existing valid token
 * POST /api/auth/revoke      — revoke / logout
 * GET  /api/auth/validate    — validate a token and return its claims
 * GET  /api/auth/roles       — list available roles and their permissions
 */

export default async function authRoutes(app, { redis, jwtSign, auditLog, metrics }) {
  const REAUTH_TTL = 30 * 60; // 30-minute sliding session

  // ── User directory (replace with Keycloak/LDAP in production) ──────────────
  const USERS = {
    // Students
    "student@uni.edu":    { id: "u-001", password: "student123",   role: "student",   name: "Alex Rivera" },
    "s2@uni.edu":         { id: "u-005", password: "student456",   role: "student",   name: "Maya Johnson" },
    // Professors
    "professor@uni.edu":  { id: "u-002", password: "professor123", role: "professor", name: "Dr. Sarah Chen" },
    "prof2@uni.edu":      { id: "u-006", password: "prof456",      role: "professor", name: "Dr. James Okoye" },
    // Visitors — any email with visitor role
    "visitor@uni.edu":    { id: "u-003", password: "visitor123",   role: "visitor",   name: "Guest User" },
    // Admin
    "admin@uni.edu":      { id: "u-004", password: "admin123",     role: "admin",     name: "System Admin" },
  };

  // Role → permitted services + allowed methods
  const ROLE_PERMISSIONS = {
    student: {
      services: ["visitor", "student"],
      description: "Access own grades, schedule, enrollment, and public catalog",
      endpoints: [
        "GET /api/student/grades",
        "GET /api/student/schedule",
        "GET /api/student/profile",
        "GET /api/visitor/catalog",
        "GET /api/visitor/events",
        "GET /api/visitor/announcements",
      ],
    },
    professor: {
      services: ["visitor", "student", "professor"],
      description: "Manage courses, view/grade student records, access public catalog",
      endpoints: [
        "GET /api/professor/courses",
        "POST /api/professor/grades",
        "GET /api/professor/profile",
        "GET /api/student/grades",
        "GET /api/student/list",
        "GET /api/visitor/catalog",
        "GET /api/visitor/events",
      ],
    },
    visitor: {
      services: ["visitor"],
      description: "Read-only access to public catalog and events (06:00–22:00 UTC)",
      endpoints: [
        "GET /api/visitor/catalog",
        "GET /api/visitor/events",
        "GET /api/visitor/announcements",
      ],
    },
    admin: {
      services: ["visitor", "student", "professor", "admin"],
      description: "Full system access",
      endpoints: ["ALL /*"],
    },
  };

  function sessionKey(userId) { return `session:${userId}`; }

  function buildToken(user) {
    return jwtSign(
      {
        sub:   user.id,
        email: user.email,
        role:  user.role,
        name:  user.name,
        iat:   Math.floor(Date.now() / 1000),
      },
      { expiresIn: "1h" }
    );
  }

  // ── POST /api/auth/token ────────────────────────────────────────────────────
  app.post("/api/auth/token", {
    schema: {
      body: {
        type: "object",
        required: ["username", "password"],
        properties: {
          username: { type: "string", format: "email" },
          password: { type: "string", minLength: 1 },
        },
      },
      response: {
        200: {
          type: "object",
          properties: {
            access_token:  { type: "string" },
            token_type:    { type: "string" },
            expires_in:    { type: "number" },
            role:          { type: "string" },
            name:          { type: "string" },
            permissions:   { type: "object" },
            issued_at:     { type: "string" },
          },
        },
      },
    },
  }, async (req, reply) => {
    const { username, password } = req.body;
    const user = USERS[username.toLowerCase()];

    if (!user || user.password !== password) {
      metrics?.authFailures?.inc?.();
      await auditLog({
        event: "LOGIN_FAILED",
        username,
        ip: req.ip,
        reason: !user ? "unknown_user" : "bad_password",
      });
      return reply.code(401).send({
        error: "Unauthorized",
        message: "Invalid credentials",
        hint: "Check the /api/auth/roles endpoint for test credentials",
      });
    }

    const token = buildToken({ ...user, email: username });

    // Register session
    await redis.setEx(
      sessionKey(user.id),
      REAUTH_TTL,
      JSON.stringify({ role: user.role, loginAt: Date.now(), ip: req.ip })
    );

    await auditLog({ event: "LOGIN_SUCCESS", user_id: user.id, role: user.role, ip: req.ip });
    metrics?.logins?.labels?.({ role: user.role })?.inc?.();

    return reply.send({
      access_token: token,
      token_type:   "Bearer",
      expires_in:   3600,
      role:         user.role,
      name:         user.name,
      permissions:  ROLE_PERMISSIONS[user.role],
      issued_at:    new Date().toISOString(),
    });
  });

  // ── POST /api/auth/token/guest — visitor token, no credentials needed ───────
  app.post("/api/auth/token/guest", async (req, reply) => {
    const guestId = "guest-" + Math.random().toString(36).slice(2, 10);
    const token = jwtSign(
      { sub: guestId, email: "guest@public", role: "visitor", name: "Guest" },
      { expiresIn: "2h" }
    );

    await redis.setEx(sessionKey(guestId), 7200, JSON.stringify({ role: "visitor", guest: true }));
    await auditLog({ event: "GUEST_TOKEN_ISSUED", guest_id: guestId, ip: req.ip });

    return reply.send({
      access_token: token,
      token_type:   "Bearer",
      expires_in:   7200,
      role:         "visitor",
      name:         "Guest",
      permissions:  ROLE_PERMISSIONS.visitor,
      note:         "Guest tokens expire in 2 hours and are limited to public endpoints",
    });
  });

  // ── POST /api/auth/refresh ─────────────────────────────────────────────────
  app.post("/api/auth/refresh", {
    onRequest: [app.authenticate],
  }, async (req, reply) => {
    const { sub: userId, role, email, name } = req.user;

    // Check session still exists
    const sessionData = await redis.get(sessionKey(userId));
    if (!sessionData) {
      return reply.code(401).send({ error: "Session expired", reauth_required: true });
    }

    const newToken = buildToken({ id: userId, role, name, email });
    await redis.expire(sessionKey(userId), REAUTH_TTL); // reset TTL

    await auditLog({ event: "TOKEN_REFRESHED", user_id: userId, role });
    return reply.send({
      access_token: newToken,
      token_type:   "Bearer",
      expires_in:   3600,
      role,
    });
  });

  // ── POST /api/auth/revoke ──────────────────────────────────────────────────
  app.post("/api/auth/revoke", {
    onRequest: [app.authenticate],
  }, async (req, reply) => {
    const { sub: userId, role } = req.user;
    await redis.del(sessionKey(userId));
    await auditLog({ event: "LOGOUT", user_id: userId, role });
    return reply.send({ message: "Token revoked. Session ended." });
  });

  // ── GET /api/auth/validate ─────────────────────────────────────────────────
  app.get("/api/auth/validate", {
    onRequest: [app.authenticate],
  }, async (req, reply) => {
    const { sub: userId, role, email, name, iat, exp } = req.user;
    const sessionTTL = await redis.ttl(sessionKey(userId));

    return reply.send({
      valid:          true,
      user_id:        userId,
      email,
      role,
      name,
      permissions:    ROLE_PERMISSIONS[role] ?? {},
      token_issued:   new Date(iat * 1000).toISOString(),
      token_expires:  new Date(exp * 1000).toISOString(),
      session_ttl_s:  sessionTTL,
    });
  });

  // ── GET /api/auth/roles — public, no auth needed ────────────────────────────
  app.get("/api/auth/roles", async (req, reply) => {
    return reply.send({
      roles: ROLE_PERMISSIONS,
      test_credentials: {
        student:   { username: "student@uni.edu",   password: "student123" },
        professor: { username: "professor@uni.edu",  password: "professor123" },
        visitor:   { username: "visitor@uni.edu",   password: "visitor123" },
        guest:     { note: "POST /api/auth/token/guest — no credentials needed" },
      },
      how_to_use: {
        step1: "POST /api/auth/token with username+password to get a Bearer token",
        step2: "Include token as 'Authorization: Bearer <token>' header in all requests",
        step3: "Access the service endpoints listed under your role's permissions",
      },
    });
  });
}

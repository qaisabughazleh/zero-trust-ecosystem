# ============================================================
# Zero-Trust Authorization Policy
# Engine: Open Policy Agent (OPA)
# Language: Rego
#
# Policy hierarchy:
#   zerotrust.authz.allow   – final allow/deny decision
#   zerotrust.authz.reason  – human-readable denial reason
#   zerotrust.rbac.*        – role-based access tables
#   zerotrust.risk.*        – contextual risk signals
# ============================================================

package zerotrust.authz

import future.keywords.in
import future.keywords.every

# ── Default deny (Zero-Trust: deny unless explicitly allowed) ─────────────────
default allow := false
default reason := "default_deny"

# ── RBAC permission table ──────────────────────────────────────────────────────
# Format: role → set of permitted services
permissions := {
  "student": {
    "visitor",   # public catalog, events
    "student",   # own grades, schedule, enrollment
  },
  "professor": {
    "visitor",   # public catalog
    "student",   # read student records for their courses
    "professor", # course management, grade submission
  },
  "visitor": {
    "visitor",   # read-only public endpoints only
  },
  "admin": {
    "visitor",
    "student",
    "professor",
    "admin",     # system administration
  },
}

# ── Method-level restrictions per service ─────────────────────────────────────
# Restricts which HTTP methods a role may use on a service
method_permissions := {
  "student": {
    "student":   {"GET"},            # read own data only
    "visitor":   {"GET"},
    "professor": {},                 # no access
    "admin":     {},
  },
  "professor": {
    "student":   {"GET"},            # read student records
    "professor": {"GET", "POST", "PUT", "PATCH"},
    "visitor":   {"GET"},
    "admin":     {},
  },
  "visitor": {
    "visitor":   {"GET"},
    "student":   {},
    "professor": {},
    "admin":     {},
  },
  "admin": {
    "student":   {"GET", "POST", "PUT", "DELETE", "PATCH"},
    "professor": {"GET", "POST", "PUT", "DELETE", "PATCH"},
    "visitor":   {"GET", "POST", "PUT", "DELETE", "PATCH"},
    "admin":     {"GET", "POST", "PUT", "DELETE", "PATCH"},
  },
}

# ── Time-based access restrictions ────────────────────────────────────────────
# Visitors may only access the system between 06:00 and 22:00 UTC
visitor_allowed_hours := {h | h := numbers.range(6, 22)[_]}

# ── Blocked IPs (updated dynamically by AI engine via OPA Data API) ───────────
# GET /v1/data/zerotrust/blocklist
blocked_ips := data.zerotrust.blocklist.ips

# ── Core allow rule ───────────────────────────────────────────────────────────
allow if {
  role_allowed
  method_allowed
  not ip_blocked
  not time_restricted
  not rate_anomaly
}

# 1. Role has permission to access the service
role_allowed if {
  role := input.user.role
  svc  := input.resource.service
  svc in permissions[role]
}

reason := "role_not_permitted" if {
  not role_allowed
}

# 2. Method is permitted for this role × service combination
method_allowed if {
  role   := input.user.role
  svc    := input.resource.service
  method := input.resource.method
  method in method_permissions[role][svc]
}

reason := "method_not_permitted" if {
  role_allowed      # role is fine…
  not method_allowed # …but method is not
}

# 3. IP is not in the AI-engine-managed blocklist
ip_blocked if {
  input.context.ip in blocked_ips
}

reason := "ip_blocked" if {
  ip_blocked
}

# 4. Time restrictions for visitors
time_restricted if {
  input.user.role == "visitor"
  current_hour := time.clock(time.now_ns())[0]
  not current_hour in visitor_allowed_hours
}

reason := "outside_permitted_hours" if {
  time_restricted
}

# 5. AI-flagged rate anomaly (injected by AI engine into OPA Data API)
rate_anomaly if {
  user_id := input.user.id
  data.zerotrust.anomalies.users[user_id].anomaly_score > 0.85
}

reason := "ai_anomaly_detected" if {
  not ip_blocked     # not already blocked for another reason
  not time_restricted
  rate_anomaly
}

# ── Fine-grained data filters ─────────────────────────────────────────────────
# Services use these to filter query results

# Students may only see their own records
data_filter["own_records_only"] if {
  input.user.role == "student"
  input.resource.service == "student"
}

# Professors may see records for courses they teach (enforced in-service)
data_filter["course_scoped"] if {
  input.user.role == "professor"
  input.resource.service == "student"
}

# ── Audit metadata ─────────────────────────────────────────────────────────────
# OPA decision logs capture this automatically when decision_logs is enabled
audit := {
  "request_id": input.context.request_id,
  "user_id":    input.user.id,
  "role":       input.user.role,
  "service":    input.resource.service,
  "method":     input.resource.method,
  "decision":   allow,
  "reason":     reason,
  "timestamp":  input.context.timestamp,
}

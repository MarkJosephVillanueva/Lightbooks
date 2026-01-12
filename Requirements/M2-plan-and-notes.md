# LightBooks M2 Plan and Notes

## Ground Rules (from user)
- No MFA in M2; only basic username/password login.
- Password changes: users can change via their profile; admins can force a password change and notify via email.
- At this stage, password validity/complexity enforcement is not required (no strength/expiry/history checks in M2).

## ADO Placement
- Parent Feature: M2 - RBAC and Audit Logs
- Iteration Path: LightBooks\M2 - RBAC and Audit Logs
- Tag: M2
- Item type: User Story for each story below; Tasks under each story.

## User Stories, Acceptance Criteria, and Tasks

### 1) Authentication & Session Management (User Story)
**Description**: Implement token-based login (no MFA), enforce idle and absolute session timeouts, and support logout with auditability.
**Acceptance Criteria**:
- Login POST issues signed token (include user id, roles, issued-at, expiry); only active users authenticate.
- Idle timeout and absolute session lifetime enforced; expired tokens rejected with 401.
- Logout invalidates active session/token server-side (blacklist/rotation).
- Audit events for login success, login failure, logout, session expiry.
- Average login response time <= 2s under expected load.

**Tasks**:

#### Task 1.1: Build POST /login with token issuance
**Full Description**: 
Design and implement the login API endpoint that accepts username/password credentials, validates them against the user table, issues a signed JWT token if valid, and returns the token with metadata. The endpoint must be REST-based, idempotent on failure, and support concurrent login attempts without race conditions.

**Assumptions**:
- Username and password are plain text (no complexity rules in M2).
- User account has an "enabled" flag; disabled accounts cannot login.
- Token will be JWT format, signed with HS256 or RS256 (choice TBD).
- Token payload includes: sub (user id), roles (array), issued_at, expires_at, and optional claims for client UI.
- Password hashing is bcrypt or argon2 (already implemented in M1 or available).
- Token lifetime is configurable (typical 8–24 hours for absolute; idle 15–30 minutes).

**Implementation Details**:
- POST /api/auth/login with body { username: string, password: string }.
- Query user by username; if not found or disabled, return 401 (no detail leak).
- Verify password hash against stored hash using bcrypt.compare() (or equivalent).
- On success: query user roles from user_role join table; construct JWT claims including roles array.
- Sign token with private key (HS256 or RS256 depending on architecture).
- Return JSON: { token: "...", expires_in: 3600, token_type: "Bearer", user: { id, username, roles } }.
- Use consistent error message: "Invalid credentials" for all failures (login, disabled, etc.).
- Log access at info level (without password); detailed audit event emitted separately.

**Open-Ended Questions**:
- What is the chosen token signing algorithm (HS256, RS256, or EdDSA)? Where are keys stored (env var, vault, key store)?
- Should the client receive the full JWT decode on login, or just the token string?
- How should token refresh be handled in M2? (e.g., refresh token, sliding window, or no refresh?)
- What is the token absolute lifetime? (e.g., 8h, 24h, 7 days?)
- Should there be a rate limit per username or per IP before locking out login attempts temporarily?
- Should concurrent logins from different IPs/devices be allowed, or enforced single-session per user?

---

#### Task 1.2: Add idle/absolute session timeout middleware
**Full Description**:
Implement middleware that enforces session timeout policies: idle timeout (token valid only if last activity is within X minutes) and absolute timeout (token expires regardless of activity after Y hours). Middleware should detect expired tokens, reject with 401, and ensure no mutations occur on expired sessions.

**Assumptions**:
- Idle timeout is tracked via a last_activity timestamp in a session store (Redis, in-memory, or DB).
- Absolute timeout is encoded in the JWT exp claim.
- Middleware is applied to all protected routes; public routes are exempt (login, health checks).
- On timeout, client is responsible for redirecting to login page.
- Idle timer resets on each successful request.

**Implementation Details**:
- Middleware function that intercepts requests before route handlers.
- Extract token from Authorization header (Bearer scheme).
- Verify token signature and exp claim (standard JWT verification).
- If token expired, return 401 with error code "token_expired".
- If using idle tracking: query session store for user's last_activity; if > idle_timeout minutes ago, return 401 "session_idle".
- On success, update last_activity in session store to current time.
- Apply middleware globally to all protected routes (or decorator/guard per route).

**Open-Ended Questions**:
- What is the idle timeout value? (e.g., 15 min, 30 min, 1 hour?)
- What is the absolute timeout value? (e.g., 8 hours, 24 hours?)
- How is session state stored for idle tracking? (Redis, database, in-memory, or none?)
- Should idle timeout reset on every request, or only on API calls (not asset fetches)?
- How should SPA/long-lived pages handle timeout? Should background checks be made, or rely on first user action?

---

#### Task 1.3: Implement POST /logout to invalidate session
**Full Description**:
Build a logout endpoint that invalidates the user's current token, preventing further use of that token. This can be achieved via token blacklist, session store deletion, or token rotation. The endpoint must be fast and idempotent (logout twice should both succeed).

**Assumptions**:
- Token is in Authorization header; extract and invalidate it.
- Invalidation mechanism is either: (a) token blacklist in Redis/cache with exp time, or (b) session store deletion.
- Logout returns 200 (success) even if token already expired or doesn't exist.
- Client deletes token from local storage/cookie after receiving 200.

**Implementation Details**:
- POST /api/auth/logout with Authorization Bearer token header.
- Extract token from header; parse to get jti (JWT ID) or user_id + exp.
- If blacklist: add token (or jti) to Redis/cache set with TTL = token remaining lifetime.
- If session store: delete session record for user.
- Return 200 with message { message: "Logged out successfully" }.
- If token already expired, still return 200 (idempotent).
- Log logout event at info level.

**Open-Ended Questions**:
- Should logout invalidate all sessions for a user, or just the current token?
- If user has multiple devices, should logout on one device log them out everywhere?
- What is the TTL for a blacklist entry? (= token expiry - current time, or fixed value?)
- Should logout be synchronous or async?
- Should there be an endpoint to list/manage active sessions per user (for audit/security)?

---

#### Task 1.4: Emit audit events for auth success/failure/logout/expiry
**Full Description**:
Instrument authentication flow to emit audit events at key points: successful login, failed login (invalid creds, disabled account), logout, and session expiry. Events capture minimal fields required for compliance and troubleshooting, without leaking sensitive data.

**Assumptions**:
- Audit event structure: { timestamp, user_id (or "unknown" if login failed), action, outcome, ip_address, user_agent, correlation_id, reason (if failure) }.
- Events are emitted to audit log sink (separate from application logs).
- No password or token is logged; reason field is sanitized (e.g., "invalid_credentials" not "password_wrong").
- Correlation ID is generated per request and passed through the auth flow.

**Implementation Details**:
- Login success: emit { timestamp, user_id, action: "AUTH_LOGIN", outcome: "success", ip, user_agent, correlation_id }.
- Login failure (invalid creds): emit { timestamp, user_id: null, action: "AUTH_LOGIN", outcome: "failure", reason: "invalid_credentials", ip, user_agent, correlation_id }.
- Login failure (disabled account): emit { timestamp, user_id, action: "AUTH_LOGIN", outcome: "failure", reason: "account_disabled", ip, user_agent, correlation_id }.
- Logout: emit { timestamp, user_id, action: "AUTH_LOGOUT", outcome: "success", ip, user_agent, correlation_id }.
- Session expiry (idle/absolute): emit { timestamp, user_id, action: "AUTH_SESSION_EXPIRED", reason: "idle" or "absolute", correlation_id }.
- Call audit emitter service/function; ensure non-blocking (async/queue).

**Open-Ended Questions**:
- Should login failure count per IP be exposed in audit logs (for brute-force detection)?
- Should audit events be written synchronously or async? What is max latency tolerance?
- Should ip_address and user_agent be logged for compliance, or considered PII to be redacted?
- How long should audit logs be retained? (e.g., 90 days, 1 year, 7 years?)
- Should sensitive fields like session ID be logged for troubleshooting?

---

#### Task 1.5: Load/latency check for /login and /logout endpoints
**Full Description**:
Conduct baseline performance testing on login and logout endpoints under expected concurrency. Measure response time, throughput, error rates, and identify bottlenecks. Document findings and compare against SLA (avg <= 2s, p95 <= 3s).

**Assumptions**:
- Expected concurrency is known (e.g., 100 concurrent users, 50 reqs/sec).
- Database query for user lookup and token generation are the main latency drivers.
- Network latency to auth service is negligible (co-located or low-latency).
- Test data includes realistic number of users and roles.

**Implementation Details**:
- Use load testing tool (e.g., k6, JMeter, Locust, Apache Bench).
- Scenario: ramp up to target concurrency over 2 minutes; hold for 5 minutes; ramp down.
- Measure: average response time, p50/p95/p99 latency, throughput (req/s), error rate, connection pool utilization.
- Run at least 3 iterations; average results.
- Identify bottlenecks: database queries, token generation, password hashing, session store access.
- Compare against SLA: avg <= 2s, p95 <= 3s, error rate < 0.1%.
- Document in load-test-m2-auth-results.md: tool used, scenario, results, bottlenecks, recommendations.

**Open-Ended Questions**:
- What is the target concurrency for M2 (e.g., 50 concurrent users, 100, 500, 1000)?
- What is acceptable p95 latency? (e.g., 2s, 3s, 5s?)
- Should password hashing use a faster algorithm (e.g., scrypt vs bcrypt) for performance?
- Is session store (Redis vs DB) impact measured? Should we optimize access pattern?
- Should token generation use cached role mappings to speed up JWT payload construction?

### 2) Password Change & Admin-Enforced Reset (User Story)
**Description**: Allow users to change passwords in profile; allow admins to flag users to change password on next login and notify via email. No complexity/expiry rules in M2.
**Acceptance Criteria**:
- Users can change password from their profile after providing current password.
- Admin can set "must change on next login" flag; email notification is sent.
- Flagged users must change password immediately after login before accessing other pages.
- Audit logs for password change and admin enforcement events (who set the flag, who changed, when).
**Tasks**:

#### Task 2.1: Implement POST /users/me/password for self-service password change
**Full Description**:
Build an API endpoint that allows authenticated users to change their own password. The user must provide their current password for verification (security check); no complexity rules enforced in M2. On success, hash and persist the new password; on failure, reject with clear error.

**Assumptions**:
- Endpoint is protected; requires valid auth token (Authorization header).
- Current password is verified against the stored hash before accepting new password.
- New password is not checked for complexity, expiry, or history rules in M2.
- Password hashing uses bcrypt (or same algorithm as login).
- User record has password_hash and possibly password_changed_at timestamp.

**Implementation Details**:
- POST /api/users/me/password with body { current_password: string, new_password: string }.
- Authenticate request (extract user_id from token).
- Query user record; verify current_password against stored hash using bcrypt.compare().
- If mismatch, return 401 { error: "Current password is incorrect" }.
- Hash new_password with bcrypt; update user record with new hash and password_changed_at = now.
- Return 200 { message: "Password changed successfully" }.
- Clear any "must_change_on_next_login" flag if set.
- Log at info level; emit audit event (see Task 2.5).

**Open-Ended Questions**:
- Should password change force logout of all other active sessions, or only the current session?
- Is there a minimum/maximum length for the new password, or truly no rules in M2?
- Should new password be different from the current one (no reuse)?
- Should password changes be logged/tracked for audit of admin enforcement separately?
- Should users receive a confirmation email after password change?

---

#### Task 2.2: Implement PATCH /admin/users/{id}/force-password-change with email notification
**Full Description**:
Build an admin action endpoint that sets a flag on a user account to force a password change on next login. When this flag is set, an email notification is sent to the user informing them. The endpoint is restricted to admin role.

**Assumptions**:
- Endpoint is protected; requires admin role or specific permission (e.g., ADMIN_MANAGE_USERS).
- User record has a "must_change_password_on_next_login" boolean flag (default false).
- Email service is available (SMTP, SendGrid, AWS SES, or similar).
- Email template includes user name, reason (optional), and instructions.
- Request includes optional reason field to be included in email and audit.

**Implementation Details**:
- PATCH /api/admin/users/{id}/force-password-change with body { reason: string (optional) }.
- Authorize request (check admin permission).
- Query user by {id}; if not found, return 404.
- Set must_change_password_on_next_login = true on user record.
- Construct email subject: "Action Required: You must change your password"
- Construct email body with user name, optional reason, and link to profile/password page.
- Send email via email service (async/queue recommended).
- Return 200 { message: "User flagged for password change; notification sent" }.
- Emit audit event with admin user_id, action, target user, reason (if provided).

**Open-Ended Questions**:
- Should the admin be able to set a deadline (e.g., "change password within 24 hours")?
- Should there be a notification in the UI (banner or modal) when user logs in with this flag, separate from forced-change screen?
- Should the reason field be user-visible in email, or internal only for audit?
- If user doesn't change password within a timeout, should their account be auto-locked?
- Should audit show when the flag was cleared (auto on password change)?

---

#### Task 2.3: Implement forced-change flow on login
**Full Description**:
After successful login, detect if the user has the "must_change_password_on_next_login" flag. If set, immediately redirect the user to a password change screen before granting access to any other pages. Block all other routes until password is changed.

**Assumptions**:
- Flag is checked in the client after login (or server-side via API).
- Token is issued on successful authentication, but client-side checks flag in response.
- Password change endpoint (Task 2.1) is called to clear the flag.
- UI has a modal/full-page component dedicated to forced password change.
- No other actions (navigation, API calls) are allowed until password is changed.

**Implementation Details**:
- Modify POST /login response to include { must_change_password: true/false } (or return flag in token claims).
- On client, after login success, check response.must_change_password.
- If true, navigate to /change-password-forced route/modal.
- Disable all other navigation; overlay entire UI if needed.
- Password change form requires only new_password (no current_password since just logged in).
- On success of new password, clear flag, redirect to dashboard/home.
- Alternative server-side: return 210 (or custom code) from /login if flag is set, with redirect URL to change-password page.

**Open-Ended Questions**:
- Should the forced-change form have a "current password" field, or skip since user just logged in?
- What is the UX if user closes browser during forced change? (session expires, re-login, flag still set?)
- Should there be a timeout for forced change (e.g., user must complete within 30 minutes)?
- Should users be able to cancel/dismiss the forced-change screen, or fully blocking?
- Should audit log show forced-change start vs completion as separate events?

---

#### Task 2.4: Audit logging for password changes and admin enforcement
**Full Description**:
Instrument password change endpoints to emit audit events capturing who changed password (self or admin-enforced), when, and outcome. Events are sanitized and non-intrusive.

**Assumptions**:
- Audit event schema includes: timestamp, user_id, admin_user_id (if enforced by admin), action, outcome, reason (if applicable).
- Password change success is logged separately from admin enforcement action.
- No details of new password or current password are logged.
- Correlation ID is passed through requests for tracing.

**Implementation Details**:
- Self-service change success: { timestamp, user_id, action: "PASSWORD_CHANGE_SELF", outcome: "success" }.
- Self-service change failure: { timestamp, user_id, action: "PASSWORD_CHANGE_SELF", outcome: "failure", reason: "invalid_current_password" }.
- Admin enforce: { timestamp, admin_user_id, action: "PASSWORD_CHANGE_ENFORCED", target_user_id, reason (if provided), outcome: "flag_set" }.
- Forced-change completion: { timestamp, user_id, action: "PASSWORD_CHANGE_FORCED", outcome: "success" }.
- All events emitted asynchronously via audit service.

**Open-Ended Questions**:
- Should admin enforcement and user compliance be logged as single event or two separate events?
- Should the audit event include attempted vs actual password entropy/length data (without exposing password)?
- How long should password change audit logs be retained? (different from login logs?)
- Should there be alerts/escalations if password is changed multiple times in short period?

---

#### Task 2.5: Negative tests and edge cases
**Full Description**:
Write and execute test cases covering invalid/edge scenarios for password change and admin enforcement flows.

**Assumptions**:
- Test data includes users with and without the must_change flag.
- Tests run in isolated DB transaction or with cleanup.
- Tests cover API level and optionally UI level (Selenium, Cypress).

**Test Cases**:
- Self-change with wrong current password: expect 401 "Current password is incorrect".
- Self-change with expired token: expect 401 "Token expired".
- Self-change with same password as current: expect success (no rule against it in M2).
- Admin enforce on non-existent user: expect 404.
- Admin enforce without admin permission: expect 403.
- Forced-change screen attempt to access other routes: expect 403 or redirect.
- Forced-change with invalid new_password (e.g., empty): expect 400 validation error.
- Multiple concurrent password changes: expect last-write-wins or conflict handling.
- Forced-change flag cleared after successful change, re-login does not trigger forced-change again.

**Open-Ended Questions**:
- Should there be rate limiting on password change attempts (e.g., max 3 per hour)?
- Should invalid login attempts (wrong current password) increment a counter and lock after N tries?
- Should concurrent password changes be rejected (optimistic lock) or allowed?

### 3) RBAC Data Model & Seed Roles (User Story)
**Description**: Define RBAC schema and seed base roles for M2.
**Acceptance Criteria**:
- Tables/collections: users, roles, permissions, role_permission, user_role created and deployed.
- Seed roles/permissions for Sales, Warehouse, Accounting, Admin, Purchasing; mapping validated against matrix.
- Uniqueness and FK/constraint rules enforced; migrations idempotent.
- Audit events for role/permission creation/updates and user-role assignments.
**Tasks**:

#### Task 3.1: Design RBAC schema and create migrations
**Full Description**:
Design the database/collection schema for roles, permissions, and their relationships. Create idempotent migration scripts that can be run safely in dev/test/prod without side effects.

**Assumptions**:
- Database is relational (SQL) or document-based (NoSQL); decision impacts schema design.
- Roles and permissions are many-to-many relationship.
- User-role is also many-to-many (user can have multiple roles).
- Soft-delete or archival is not required in M2; hard-delete is acceptable.
- IDs are UUIDs or auto-increment integers (architecture decision).

**Implementation Details**:
- Table: roles { id (PK), name (unique), slug (unique), description, created_at, updated_at }.
- Table: permissions { id (PK), name (unique), slug (unique), description, resource (e.g., "catalog", "purchasing"), action (e.g., "create", "read", "update", "delete"), created_at, updated_at }.
- Table: role_permission { role_id (FK), permission_id (FK), created_at } with composite primary key (role_id, permission_id).
- Table: user_role { user_id (FK), role_id (FK), created_at } with composite primary key (user_id, role_id).
- Migration script: up() creates tables with constraints; down() drops tables (reversible).
- Ensure idempotency: use CREATE TABLE IF NOT EXISTS, CREATE UNIQUE INDEX IF NOT EXISTS, etc.
- Migration naming: 001_create_rbac_tables.sql or 20251217_001_create_rbac_tables.sql.

**Open-Ended Questions**:
- Should roles have a "created_by" field to track who created the role?
- Should role_permission entries have effective_date/expiry_date for time-limited permissions?
- Should there be a "default role" for new users (e.g., all users get Reader role)?
- Is soft-delete required for audit trail (keep deleted roles/permissions in DB but marked inactive)?
- Should permissions have a "requires_approval" flag for certain actions?

---

#### Task 3.2: Seed base roles and permissions
**Full Description**:
Populate the roles and permissions tables with base roles (Sales, Warehouse, Accounting, Admin, Purchasing) and their corresponding permissions. Create the role-permission mappings according to the approved matrix.

**Assumptions**:
- Approved role/permission matrix exists (to be aligned with PO/BA).
- Base roles are: Admin, Sales, Warehouse, Accounting, Purchasing.
- Admin role has all permissions; others have subset.
- Seed script is idempotent: check existence before insert, or use UPSERT.

**Implementation Details**:
- Create seed script: seeds/01_base_roles_and_permissions.sql or seeds/01_base_roles_and_permissions.js.
- Insert roles:
  - Admin: "Manage users, roles, system config, audit logs"
  - Sales: "Create customers, create/approve sales orders, manage customer credit"
  - Warehouse: "Receive goods, manage inventory, ship orders"
  - Accounting: "Post invoices, manage payments, run reports, reconcile"
  - Purchasing: "Create/approve purchase orders, match GR/invoice, approve payments"
- Insert permissions for each resource (catalog, customers, sales, inventory, purchases, payments, reports, audit).
- Map roles to permissions via role_permission table (e.g., Admin -> all, Sales -> specific perms).
- Seed script is idempotent: use "INSERT ... ON CONFLICT DO NOTHING" (Postgres) or similar.

**Open-Ended Questions**:
- Should there be an "Anonymous" or "Guest" role for unauthenticated users?
- Are there additional roles beyond the 5 base roles (e.g., Manager, Supervisor)?
- Should permissions be granular (e.g., "catalog_product_read") or coarse (e.g., "catalog_admin")?
- Should roles include permissions for deleting entities, or only soft-delete/deactivate?
- Should audit log permissions be visible to all roles, or restricted to Admin?

---

#### Task 3.3: Add constraints, indexes, and backfill data
**Full Description**:
Apply database constraints (PK, FK, unique, not null) and create indexes for performance. Backfill any existing user/role data if migrating from M1.

**Assumptions**:
- M1 may have existing users; if so, assign them to appropriate roles.
- Existing user records have user_id, username, enabled flag.
- No user-role associations exist yet; need to be created during backfill.

**Implementation Details**:
- Add constraints:
  - roles.name: NOT NULL, UNIQUE.
  - roles.slug: NOT NULL, UNIQUE.
  - permissions.name: NOT NULL, UNIQUE.
  - role_permission: PK (role_id, permission_id), FK to roles/permissions.
  - user_role: PK (user_id, role_id), FK to users/roles.
- Create indexes:
  - roles.slug (for fast lookup by slug).
  - permissions.slug (for fast lookup by slug).
  - user_role.user_id (for fast role lookup per user).
  - user_role.role_id (for fast user lookup per role).
- Backfill: if M1 has admin users, assign Admin role; if sales users, assign Sales role, etc.
- Backfill migration: separate script that queries existing users and inserts user_role records.
- Validate: count user_role records, verify roles are assigned, check no orphaned records.

**Open-Ended Questions**:
- Should backfill be done in separate script from schema creation, or combined?
- If existing users have no role info in M1, how should they be auto-assigned? (prompt admin, default role, or manual?)
- Should there be a validation step post-backfill (e.g., all users have at least one role)?
- Are there performance concerns with large user base (thousands) during backfill?

---

#### Task 3.4: Verify seed coverage vs. approved matrix
**Full Description**:
Run validation checks to ensure all roles and permissions from the approved matrix are seeded, and no extraneous entries exist. Document coverage and discrepancies.

**Assumptions**:
- Approved RBAC matrix exists in a file or document (e.g., Excel, CSV, markdown table).
- Matrix has rows for each role and columns for each resource/action.
- Coverage = all matrix entries have corresponding DB records.

**Implementation Details**:
- Create a seed_validation.sql or seed_validation.js script.
- Query DB for all roles and permissions; compare against matrix.
- For each role, list permissions assigned; compare against expected.
- Generate coverage report: e.g., "Admin: 45/45 permissions (100%), Sales: 12/15 (80%, missing: catalog_delete)".
- Check for extraneous entries: any permissions/roles in DB not in matrix?
- Output result to coverage_report.md with timestamp.
- If coverage < 100%, flag as blocker; require resolution before M2 sign-off.

**Open-Ended Questions**:
- What is the acceptable coverage threshold? (e.g., 100%, 95%, 90%?)
- Should the coverage report be automatically checked in CI, or manual run?
- Who owns the approved matrix (PO, BA, architect) and how is it versioned?
- Should there be a way to visualize the RBAC matrix (e.g., Swagger UI, admin console)?

---

#### Task 3.5: Audit events for RBAC schema changes
**Full Description**:
Ensure that any role/permission/user-role changes (creation, updates, deletion) are captured in audit logs. Initially, focus on seed operations; later, admin-triggered changes.

**Assumptions**:
- Seed operations should emit audit events for traceability.
- Admin operations (create role, assign role) emit events separately (handled in other stories).

**Implementation Details**:
- In seed script, after inserting roles/permissions, emit audit events.
- Event format: { timestamp, action: "ROLE_CREATED" or "PERMISSION_CREATED", entity_id, entity_name, created_by: "seed_script" }.
- For user-role assignment during backfill: { timestamp, action: "USER_ROLE_ASSIGNED", user_id, role_id, assigned_by: "seed_script" }.
- Emit events to same audit sink as other M2 operations.
- Seed script should be idempotent; if role already exists, skip without re-emitting event.

**Open-Ended Questions**:
- Should seed operations be logged differently (e.g., audit_source: "system" vs. "admin")?
- Should there be a bulk audit event for seed operations, or granular per entity?
- Should seed operations be visible in the audit log viewer, or hidden from users?

### 4) Permission Enforcement (Modules & Actions) (User Story)
**Description**: Enforce authorization checks on protected endpoints/actions across modules.
**Acceptance Criteria**:
- Every protected endpoint uses centralized guard/middleware; unauthorized returns 403 with no side effects.
- Coverage matches approved permission map (100%).
- Denied attempts recorded as audit events without leaking sensitive detail.
**Tasks**:

#### Task 4.1: Produce endpoint/action-to-permission matrix
**Full Description**:
Create a comprehensive mapping of all API endpoints and actions to required permissions. Organize by module (Catalog, Purchasing, Sales, Inventory, Returns, Accounting, Reporting) and include HTTP method, route, required permission, and rationale.

**Assumptions**:
- All endpoints from M1 (Catalog, Purchasing, Sales, Inventory, Returns, Accounting, Reporting) are in scope for M2 authorization.
- Each endpoint maps to at least one permission (e.g., GET /products → catalog_product_read).
- Some endpoints may require multiple permissions (e.g., approve invoice → accounting_invoice_approve + accounting_payment_approve).
- Public/unauthenticated endpoints (health check, login, etc.) are exempt from authorization.

**Implementation Details**:
- Create a matrix file: docs/rbac_endpoint_matrix.md or .xlsx.
- Format (markdown table or spreadsheet):
  | Module | HTTP Method | Endpoint | Description | Required Permission(s) | Rationale |
  | --- | --- | --- | --- | --- | --- |
  | Catalog | GET | /api/products | List products | catalog_product_read | Sales, Warehouse need to view catalog |
  | Catalog | POST | /api/products | Create product | catalog_product_create | Admin/Catalog manager only |
  | Catalog | PUT | /api/products/{id} | Update product | catalog_product_update | Admin/Catalog manager only |
  | Catalog | DELETE | /api/products/{id} | Delete product | catalog_product_delete | Admin only |
  | ... | ... | ... | ... | ... | ... |
- Include all CRUD endpoints for each entity.
- Include approval/action endpoints (e.g., POST /sales-orders/{id}/approve).
- Total expected endpoints: 80–150 depending on module complexity.
- Get sign-off from PO/BA on completeness and correctness.

**Open-Ended Questions**:
- Should read-only endpoints (GET) have permission checks, or only write/action endpoints?
- Should batch operations (e.g., PUT /products/batch-update) require batch-specific permission, or per-item?
- Should there be a "public" permission for unauthenticated endpoints, or enforce auth on all?
- Should endpoint permissions be stored in code (decorator), config file, or database?
- How should permissions handle resource-level restrictions (e.g., user can only approve invoices <= 10k)?

---

#### Task 4.2: Implement authorization middleware/guard and apply to all routes
**Full Description**:
Build a centralized authorization middleware/guard that intercepts requests, extracts the required permission(s) from the endpoint mapping, checks the user's roles/permissions, and blocks if unauthorized. Apply to all protected routes.

**Assumptions**:
- Auth token is extracted from Authorization header and contains user_id and roles array.
- Permission check is done by querying user_role -> role_permission join or caching role/permission data.
- Authorization logic is implemented once and reused across all routes (DRY).
- Framework has guard/middleware pattern (e.g., Express middleware, Spring interceptor, .NET filter).

**Implementation Details**:
- Create authz.ts/authz.js middleware/guard with function: checkPermission(requiredPermission: string).
- Middleware extracts user_id and roles from token.
- Query (or cache lookup) permissions for all user roles.
- Check if required permission is in user's permission set.
- If yes, continue to route handler.
- If no, return 403 { error: "Access denied", code: "permission_denied" }.
- Apply middleware to all protected routes: app.use("/api", checkAuth, checkPermission).
- For per-route permissions, use decorator/attribute pattern: @Authorize("catalog_product_read").
- Ensure no side effects on denial (no DB mutations, no side calls).

**Open-Ended Questions**:
- Should permission checks be done per-request (fresh DB query) or cached/precomputed?
- What is the max latency for permission check? (e.g., < 50ms?)
- Should denied requests trigger additional logging/alerting (e.g., alert on repeated denials from same user)?
- Should there be a "super-admin" bypass, or all admins bound by permissions?
- How should permissions be passed to route handlers (context object, function param)?

---

#### Task 4.3: Standardize 403 response and denial audit
**Full Description**:
Define consistent 403 (Forbidden) response format and ensure every denied request is audited without leaking sensitive info.

**Assumptions**:
- 403 response should be consistent with other error responses in M2.
- Audit should not include request body (to avoid logging sensitive data).
- Response should not leak what permission was denied (generic message).

**Implementation Details**:
- Define 403 response format: { error: "Access denied", code: "permission_denied", timestamp, request_id }.
- Do NOT include which permission was required or what the user's permissions are.
- Emit audit event on denial: { timestamp, user_id, action: "PERMISSION_DENIED", endpoint, required_permission, outcome: "denied", request_id, ip, user_agent }.
- Audit should be non-blocking (async).
- Log endpoint/method/path (not full URL with query params).
- Ensure error message is generic; same for all denied requests (no info leak).

**Open-Ended Questions**:
- Should 403 be returned immediately, or should actual authorization check be done after route execution (audit on side effect)?
- Should there be rate limiting on permission denials (e.g., block user after 5 denials in 1 minute)?
- Should the PO see access denial audit logs, or only shown to audit/security team?
- Should there be a "why was I denied?" endpoint that explains to user what permissions they need?

---

#### Task 4.4: Automated tests for allowed/denied paths
**Full Description**:
Write automated test cases covering authorization happy path (allowed access), denied access, and edge cases. Tests should be part of CI pipeline.

**Assumptions**:
- Test framework: Jest, Mocha, pytest, JUnit, or equivalent.
- Tests use realistic test data (users, roles, permissions, entities).
- Tests are isolated and repeatable (e.g., setup/teardown per test).

**Test Cases**:
- User with permission accesses endpoint: expect 200 or appropriate success code.
- User without permission accesses endpoint: expect 403.
- User with partial permissions (e.g., read but not write): expect 403 on write operation.
- Admin user (should have all permissions): expect 200.
- Disabled user: expect 401 or 403 (auth check before authz).
- Expired token: expect 401.
- Malformed Authorization header: expect 400 or 401.
- User with multiple roles: should have union of all role permissions.
- Batch operation with mixed permissions: expect 403 (all-or-nothing or granular error?).

**Open-Ended Questions**:
- Should tests be unit (mock user/role data) or integration (real DB)?
- Should permission tests be run per endpoint, or in batches by module?
- Should there be load tests to verify authorization latency doesn't regress?
- Should test coverage report be published (e.g., X% of endpoints have authz tests)?

---

#### Task 4.5: Spot-check high-risk financial/approval actions
**Full Description**:
Manually test and document authorization for critical operations (invoice approval, payment, purchase order approval, etc.) to ensure they're properly gated.

**Assumptions**:
- High-risk actions are: financial transactions, approvals, deletions, config changes.
- Manual testing complements automated tests.
- Spot-check includes both positive (allowed) and negative (denied) scenarios.

**Test Scenarios**:
- Accounting user approves invoice: expect success.
- Sales user attempts to approve invoice: expect 403.
- Purchasing user approves PO > 50k: should require 2-level approval? (scope question).
- Admin marks invoice as paid: expect success, audit event emitted.
- Warehouse user attempts to mark invoice as paid: expect 403.
- Batch delete products: only Admin with catalog_product_delete: expect success; others expect 403.

**Open-Ended Questions**:
- Should approval workflows require multiple permissions (e.g., creator != approver)?
- Should there be approval limits (e.g., Accounting Manager can approve <= 100k, Director can approve all)?
- Should approval actions have a "comment" field for audit trail?
- Should certain approvals require MFA or additional verification (out of M2 scope but design for future)?

### 5) User & Role Administration Console (User Story)
**Description**: Admin UI for user lifecycle and role/permission maintenance, including forced password change toggle.
**Acceptance Criteria**:
- Admins can create/disable users, reset/force password change, and assign/remove roles.
- Admins can create/edit roles and map permissions.
- Required fields validated; uniqueness enforced client-side where applicable.
- All admin actions emit audit logs.
- UX aligns with M2 wireframes.
**Tasks**:

#### Task 5.1: Build user list/detail forms (create, edit, disable, force-change, assign roles)
**Full Description**: Create user management UI with list view and detail forms for CRUD, including force password change toggle and role assignment.
**Assumptions**: Framework is React/Vue/Angular; user list shows username, email, created_at, enabled status, assigned roles; form fields include username (read-only after creation), email (optional), enabled toggle, must_change_password_on_next_login toggle, and role multi-select.
**Implementation Details**: Components: UserListPage, UserCreateForm, UserDetailForm, RoleMultiSelect. List actions: Create, View, Disable, Force password change. Form validation: username unique (API check), email format. Disable/force-change/role assignment via dedicated endpoints. Error handling: toast notifications, inline validation errors. Loading states: skeleton/spinner during fetch; disable during submit.
**Open-Ended Questions**: Should users be soft-deleted or hard-deleted? Bulk edit feature? Auto-generate password and send via email? Search/filter by username/email? User import from CSV?

#### Task 5.2: Build role create/edit form and permission mapping UI
**Full Description**: Create role management UI for create/edit roles and mapping permissions. Include visual permission selector organized by resource.
**Assumptions**: Role list shows all roles; permission selector shows permissions by resource; role name and slug must be unique; editing shows current permissions with add/remove capability.
**Implementation Details**: Components: RoleListPage, RoleCreateForm, RoleDetailForm, PermissionSelector. Permission selector UX: hierarchical checkboxes by resource or matrix table. API: PATCH /roles/{id}/permissions with { permission_ids: [...] }. Validation: unique name/slug, alphanumeric slug. Prevent editing/deleting system roles without confirmation. Show role usage count.
**Open-Ended Questions**: Admins create custom permissions or only assign predefined? Show affected users on role edit? Role descriptions/labels? Role templates?

#### Task 5.3: Wire UI to backend APIs and add form validation
**Full Description**: Connect forms to backend endpoints; add client-side and server-side validation; handle errors gracefully.
**Assumptions**: Backend APIs implemented (GET /users, POST /users, PATCH /users/{id}, GET /roles, POST /roles, PATCH /roles/{id}, PATCH /users/{id}/roles, PATCH /users/{id}/force-password-change). Server returns validation errors as { errors: { field: ["message"] } }.
**Implementation Details**: User validation (client): username 3–50 chars, email format (if provided). Role validation (client): name 3–100 chars, slug alphanumeric + underscore. Server: same + uniqueness checks. API calls: fetch/axios with error handling (400→validation, 401→auth, 403→authz, 500→server error). Error display: inline per-field messages; toast for network/server errors. Success feedback: toast "User created successfully"; auto-navigate.
**Open-Ended Questions**: Validation real-time or on-submit? Confirm dialog before disable/delete? Auto-save drafts? Undo feature?

#### Task 5.4: Hook audit calls on admin actions
**Full Description**: Ensure all admin operations emit audit events (create, edit, disable, role assign, password force) for traceability.
**Assumptions**: Audit handled server-side; includes admin user_id, action, target entity, old/new values, timestamp; all emissions are async/non-blocking.
**Implementation Details**: User create: emit { timestamp, admin_id, action: "USER_CREATED", target_user_id, field_values, outcome: "success" }. User edit: emit { action: "USER_UPDATED", changes: {...} }. Disable: emit { action: "USER_DISABLED" }. Force-change: emit { action: "PASSWORD_CHANGE_FORCED", reason (optional) }. Role assign: emit { action: "USER_ROLE_ASSIGNED", role_ids }. Role create/edit/delete: similar. All async via audit service.
**Open-Ended Questions**: Show before/after for all fields or only changed? Show permission additions/removals in role assignment audit? Alerts on critical role assignment (Admin)?

#### Task 5.5: UX review and adjust per M2 wireframes
**Full Description**: Review implemented UI against M2 design wireframes; adjust styling, layout, interactions to match.
**Assumptions**: M2 wireframes provided (Figma, mockups); define layout, colors, typography, interactions; responsive design expected.
**Implementation Details**: Schedule UX review with PO/designer; walk through user list, detail form, role management; compare against wireframes (layout, spacing, colors, typography, button placement); capture and prioritize discrepancies (critical, important, nice-to-have); implement iteratively; re-review with stakeholder; document final UI in screenshots.
**Open-Ended Questions**: Dark mode support? Accessibility (WCAG 2.1 AA)? Keyboard shortcuts? Help text/tooltips?

### 6) Audit Logging Framework (Capture & Storage) (User Story)
**Description**: Implement audit event capture, schema, persistence, and integrity for critical actions.
**Acceptance Criteria**:
- Event schema defined (who, what, when, where, request id, correlation id, entity, action, outcome, optional old/new where allowed).
- Critical event list implemented for auth, RBAC changes, config, critical CRUD, approvals, financial-impact actions.
- Logs are append-only and tamper-evident; write latency <= 5s.
- PII redaction rules applied where required.
**Tasks**:

#### Task 6.1: Define audit event catalog and schema
**Full Description**: Document complete audit event catalog listing all events to be captured, their fields, and redaction rules. Create the schema for audit_logs table/collection (append-only).
**Assumptions**: Audit events stored separately; append-only design. Event categories: AUTH, RBAC, CONFIG, CRUD (critical entities), APPROVAL, FINANCIAL. Event fields: id (UUID PK), timestamp (UTC ISO 8601), user_id (who, can be null for system events), action (enum: AUTH_LOGIN, PASSWORD_CHANGE_SELF, USER_CREATED, etc.), entity_type, entity_id, outcome (success/failure), reason (optional), old_value/new_value (optional, JSON), ip_address, user_agent, correlation_id, request_id, redacted (boolean).
**Implementation Details**: Create audit_logs table with schema above. Add indexes on timestamp, user_id, entity_type, action. Enforce immutability (trigger or app logic prevents UPDATE/DELETE). Set up insertion constraints: id NOT NULL PK, timestamp NOT NULL, action NOT NULL. Example: CREATE TABLE audit_logs ( id UUID PRIMARY KEY, timestamp TIMESTAMP WITH TIMEZONE NOT NULL, user_id UUID, action VARCHAR NOT NULL, ... ) WITH (autovacuum_analyze_scale_factor=0); CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp DESC); CREATE INDEX idx_audit_user ON audit_logs(user_id); CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit_logs FOR EACH ROW RAISE EXCEPTION 'Audit logs immutable';
**Open-Ended Questions**: Encrypt logs at rest? Archive old logs (> 1 year) to cold storage? Hash chain to detect tampering? Redact old_value/new_value or log fully? Reason field for successful ops too?

#### Task 6.2: Implement audit emitter library and persistence layer
**Full Description**: Build reusable audit service/library that emits events from any part of app and persists to audit log store. Service should auto-populate system fields (timestamp, correlation_id, request_id) and handle async persistence.
**Assumptions**: Audit service injected into handlers/services; persistence is async/non-blocking; auto-populates system fields from context; error on audit write doesn't fail business operation.
**Implementation Details**: Create AuditService class/module with emit(event: AuditEvent): Promise<void> method. Event interface: { action: string, entity_type?: string, entity_id?: string, outcome: "success" | "failure", reason?: string, old_value?: any, new_value?: any, user_id?: string, ip_address?: string, user_agent?: string, correlation_id?: string, request_id?: string }. Implementation: extract system fields from request context; insert to audit_logs table; handle DB pooling. Error handling: if write fails, log to app logs (don't fail business operation). Target latency: <= 5s. Example usage: this.auditService.emit({ action: 'USER_CREATED', entity_type: 'user', entity_id: newUser.id, outcome: 'success' }).
**Open-Ended Questions**: Sync or async service? Batch audit endpoint for bulk operations? Alert on failed audit writes? Max event payload size?

#### Task 6.3: Add correlation IDs and timestamps
**Full Description**: Ensure all audit events are timestamped and linked via correlation IDs for tracing related events across session/request.
**Assumptions**: Correlation ID generated per user session (login); passed through all requests via X-Correlation-ID header. Request ID generated per API request; stored in context. Timestamps in UTC, ISO 8601 format.
**Implementation Details**: Middleware: extract or generate correlation_id from X-Correlation-ID header; store in request context. Generate request_id (UUID) per request; store in context. On audit emit: auto-populate correlation_id and request_id from context. Example flow: login -> correlation_id = uuid1; all subsequent requests carry correlation_id in X-Correlation-ID header; 5 API calls in session all have same correlation_id. Timestamps: use server UTC time; store as TIMESTAMP WITH TIMEZONE in DB. Include correlation_id in app logs for cross-referencing. Example: 2025-12-17T14:30:45.123456Z (ISO 8601 UTC).
**Open-Ended Questions**: Expose correlation_id to end users (error messages, logs)? Persist correlation_id across sessions or reset on logout? Distinct session_id from correlation_id? User-visible timestamps?

#### Task 6.4: Performance check for log write latency
**Full Description**: Measure and validate that audit log writes don't bottleneck application. Target <= 5s latency for log persistence.
**Assumptions**: Audit writes are async (non-blocking); tested under realistic load; DB and audit service are co-located or low-latency.
**Implementation Details**: Test setup: write ~100 audit events with realistic data; measure insert time. Metrics: average latency, p95 latency, throughput (events/sec). Test scenarios: (1) Single event write: expect < 100ms. (2) Batch writes (100 events): expect < 1s total or < 10ms per event. (3) Concurrent writes (10 threads): expect no degradation beyond normal DB contention. Document findings in perf_audit_logs.md: tool/DB, results, bottlenecks, recommendations. If latency > 5s, optimize: connection pooling, index tweaks, or implement async queue with background worker.
**Open-Ended Questions**: Batch/buffer writes to improve throughput (eventual consistency trade-off)? Sampling strategy for high-traffic endpoints (log 10% of events)? Monitor audit latency in production (metrics/alerts)?

#### Task 6.5: Verify immutability and append-only behavior
**Full Description**: Implement and test that audit logs are append-only; no updates/deletes allowed except by DBAs (with audit trail). Ensures tamper-evident design.
**Assumptions**: Immutability enforced at DB level (triggers, RLS, or app logic); appending ensures tamper detection (any update would be visible).
**Implementation Details**: Database: add trigger/constraint to prevent UPDATE/DELETE on audit_logs. Postgres example: CREATE TRIGGER audit_logs_immutable BEFORE UPDATE OR DELETE ON audit_logs FOR EACH ROW RAISE EXCEPTION 'Audit logs are immutable'. SQL Server: similar via trigger or CHECK constraint. App logic: audit service exposes only insert() method; no update/delete. Test attempts: (1) UPDATE existing audit record -> expect error. (2) DELETE existing audit record -> expect error. (3) INSERT new records -> expect success. Optional: implement hash chain (SHA256(current_row || previous_row_hash)) and verify chain periodically.
**Open-Ended Questions**: Delete audit logs permission for admins or completely immutable? Archive old logs to cold storage? Meta-audit on any audit log deletion (if allowed)?

### 7) Audit Log Viewer & Export (User Story)
**Description**: Provide UI and API to query, filter, paginate, and export audit logs with role-based visibility.
**Acceptance Criteria**:
- Filters by user, role, entity, action, outcome, date range; pagination server-side; typical response <= 2s.
- CSV export for current filtered result set; only authorized roles can view/export.
- Sensitive values redacted per policy.
**Tasks**:

#### Task 7.1: Implement GET /audit-logs API with filters, pagination, sorting
**Full Description**: Build API endpoint to query audit logs with server-side filtering, pagination, sorting. Enforce role-based authorization (only admin/audit role can view). Support filters: user_id, action, entity_type, outcome, date_range (from/to). Return paginated result set with total count.
**Assumptions**: Request authorization header provides user context; user must have audit_logs_read permission. Query parameters: user_id, action, entity_type, outcome, from_date (ISO 8601), to_date (ISO 8601), page (int, default 1), page_size (int, default 20, max 100), sort_by (timestamp, user_id), sort_order (asc/desc, default desc).
**Implementation Details**: GET /api/audit-logs?user_id={id}&action={action}&from_date={date}&to_date={date}&page=1&page_size=20&sort_by=timestamp&sort_order=desc. Backend: (1) Authorize request (check audit_logs_read permission). (2) Build WHERE clause: user_id = ? AND action = ? AND timestamp BETWEEN ? AND ? ... (3) Execute COUNT(*) for total; execute SELECT with LIMIT/OFFSET. (4) Return { data: [...], total: N, page: 1, page_size: 20, total_pages: M }. Ensure server-side sorting/filtering (no client-side). Target response time: <= 2s for typical filters (e.g., date range of 1 week, user_id = X).
**Open-Ended Questions**: Should filters be AND (all must match) or OR (any can match)? Full-text search on event data? Export API endpoint separate or combined? Favorite/saved filters? Real-time updates (WebSocket)?

#### Task 7.2: Build UI for audit logs (filters, table, pagination)
**Full Description**: Create front-end UI displaying audit logs with interactive filters, sortable table, and pagination controls.
**Assumptions**: Framework: React/Vue/Angular; users expect intuitive filter/search UX; table shows: timestamp, user, action, entity_type, entity_id, outcome (success/failure), reason (if applicable).
**Implementation Details**: Components: AuditLogsPage, FilterPanel (user, action, date range, outcome multi-select), LogTable (sortable columns, row expansion for details), Pagination. Filter state: managed in URL query params or component state. Table columns: timestamp (sortable), user (clickable to filter), action, entity_type, entity_id, outcome (badge: green/red), reason. Row expansion: show full event JSON (old_value/new_value). Loading state: spinner during fetch; skeleton rows. Empty state: "No logs found matching filters". Error state: "Failed to load logs; please try again".
**Open-Ended Questions**: Real-time updates? Bulk actions (export, delete, etc.)? Saved filter presets? Inline editing (not recommended for audit logs)? Notifications on specific events?

#### Task 7.3: Implement CSV export for filtered results
**Full Description**: Add CSV export endpoint and UI button to export current filtered audit logs.
**Assumptions**: Export respects current filters and pagination; enforces same authorization as read endpoint; streams to client (avoid large memory allocation).
**Implementation Details**: GET /api/audit-logs/export?user_id=X&action=Y&format=csv. Backend: (1) Authorize (check audit_logs_read permission). (2) Apply same filters as GET /audit-logs. (3) Query all matching rows (no limit). (4) Stream CSV response: Content-Type: text/csv; Content-Disposition: attachment; filename=audit_logs_2025-12-17.csv. CSV format: timestamp, user_id, action, entity_type, entity_id, outcome, reason (redacted fields omitted or marked as [REDACTED]). Use CSV library to escape/quote fields. UI: add "Export to CSV" button; on click, trigger download; show progress (if large dataset).
**Open-Ended Questions**: Export format: CSV, JSON, XLSX? Limit export size (max 10k rows)? Email export if large (async)? Include/exclude redacted fields? Compress export (ZIP)?

#### Task 7.4: Apply redaction on sensitive fields before display/export
**Full Description**: Identify sensitive fields in audit events and redact before returning to user. Redaction rules: PII fields, password hashes, API keys, etc. should be masked.
**Assumptions**: Redaction rules defined (e.g., password_hash -> [REDACTED], credit_card -> [REDACTED]); rules apply equally to display and export.
**Implementation Details**: Define redaction config: list of sensitive field names/patterns. Before returning audit event (display or export), check if any field is flagged; replace value with [REDACTED]. Example fields to redact: password_hash, api_key, credit_card, ssn, phone_number, email (conditionally). Example event: { action: "USER_CREATED", new_value: { username: "john", password_hash: "bcrypt$...", email: "john@example.com" } }. Before return: { action: "USER_CREATED", new_value: { username: "john", password_hash: "[REDACTED]", email: "[REDACTED]" } }. Implement in audit service or serialization layer.
**Open-Ended Questions**: Different redaction levels per role (admin sees more detail)? Partial redaction (show first 4 chars of email)? Audit redaction actions themselves (log when data is redacted)?

#### Task 7.5: Add performance tests and authorization tests for audit log queries
**Full Description**: Write automated tests for audit log endpoint performance and authorization. Ensure query latency meets SLA and only authorized users access data.
**Assumptions**: Test framework: Jest, pytest, etc.; test data: 10k+ audit events; authorization tests cover happy/denied paths.
**Implementation Details**: Performance tests: (1) Query with single filter (user_id): expect < 500ms. (2) Query with date range (1 week): expect < 1s. (3) Query with multiple filters: expect < 2s. (4) Export 10k rows: expect < 5s. Authorization tests: (1) User without audit_logs_read permission: expect 403. (2) Admin with permission: expect 200. (3) User with permission can filter by own user_id, not others (row-level security, if applicable). (4) Malformed filters (invalid dates): expect 400. Document results in perf_audit_tests.md.
**Open-Ended Questions**: Load test (concurrent requests)? Slow query logging in prod? Index optimization if needed?

### 8) Security & Performance Hardening (M2 scope) (User Story)
**Description**: Baseline security controls and perf validation for auth/RBAC surfaces.
**Acceptance Criteria**:
- Rate limiting on login endpoints; lockout respected if configured.
- Security headers applied: CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy.
- Input validation and sanitized error responses for auth/RBAC endpoints.
- p95 latency for login and permission-check endpoints <= 2s under expected load.
- Vulnerability scan shows no high/critical issues in M2 scope.
**Tasks**:

#### Task 8.1: Configure rate limiting on /login endpoint
**Full Description**: Implement rate limiting on login endpoint to prevent brute-force attacks. Limit login attempts per IP and per username; temporary lockout after N failed attempts.
**Assumptions**: Rate limiter library available (e.g., express-rate-limit, python-ratelimit); uses in-memory or Redis store; configurable thresholds.
**Implementation Details**: Configure rate limiter on POST /api/auth/login: (1) Per-IP limit: max 5 attempts per minute; (2) Per-username limit: max 3 attempts per minute. After hitting limit: return 429 Too Many Requests with Retry-After header (e.g., 60 seconds). Failed login is tracked (invalid credentials or disabled account). Successful login resets the counter. Example config: { windowMs: 60000 (1 min), max: 5, keyGenerator: (req) => req.ip }. Test: attempt 6 logins in 1 minute -> 6th attempt returns 429. Also apply same rate limit to /forgot-password, /reset-password endpoints if they exist.
**Open-Ended Questions**: Whitelist certain IPs (internal networks)? Adaptive rate limiting based on threat level? Account lockout (disable after repeated failures) vs. time-based lockout? Integration with security monitoring/alerts?

#### Task 8.2: Add security headers middleware/policy
**Full Description**: Apply security headers to all HTTP responses to prevent common attacks (XSS, clickjacking, MIME sniffing, etc.).
**Assumptions**: Security headers: CSP (Content-Security-Policy), HSTS (Strict-Transport-Security), X-Content-Type-Options, X-Frame-Options, Referrer-Policy.
**Implementation Details**: Implement middleware to add headers to all responses:
- Content-Security-Policy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self';" (adjust allowlist per app needs).
- Strict-Transport-Security: "max-age=31536000; includeSubDomains; preload" (HTTPS enforcement).
- X-Content-Type-Options: "nosniff" (prevent MIME sniffing).
- X-Frame-Options: "DENY" or "SAMEORIGIN" (prevent clickjacking).
- Referrer-Policy: "strict-origin-when-cross-origin" or "no-referrer".
- Permissions-Policy: "geolocation=(), microphone=(), camera=()" (disable unnecessary features).
Example middleware (Express): app.use((req, res, next) => { res.setHeader('Content-Security-Policy', '...'); res.setHeader('Strict-Transport-Security', '...'); ... next(); });
Document CSP allowlist (e.g., "data:" for images, "https://cdn.example.com" for external scripts).
**Open-Ended Questions**: Nonce-based CSP vs. allowlist? Report-Uri for CSP violations? Subresource integrity (SRI) for CDN resources? Different CSP for admin vs. public pages?

#### Task 8.3: Add request validation and sanitized error responses
**Full Description**: Validate all input on auth/RBAC endpoints; return sanitized errors that don't leak system details.
**Assumptions**: Framework has validation library (Joi, Yup, zod, etc.); errors are logged internally but not exposed to client.
**Implementation Details**: POST /login validation: username and password must be strings; length requirements (e.g., 3–50 chars). On validation fail: return 400 { error: "Invalid request", code: "validation_error" } (no field-level detail). Sanitize error responses: "Invalid credentials" (not "user not found" or "password incorrect", which leak info). POST /api/audit-logs filter validation: date format must be ISO 8601; page/page_size must be integers within range. Log validation failures at debug level (for troubleshooting); don't expose internal error messages to client.
**Open-Ended Questions**: Detailed validation errors (which field failed) or generic? Client-side validation first or server-side only? Custom error codes for different failure types?

#### Task 8.4: Run baseline load test for login and permission-check endpoints
**Full Description**: Conduct load test on critical endpoints (login, permission check) to establish baseline performance and ensure SLA compliance.
**Assumptions**: Load testing tool: k6, JMeter, Locust, etc.; target concurrency known; expected load is reasonable (not billion reqs/sec).
**Implementation Details**: Load test scenario: (1) Login endpoint: ramp up to 50 concurrent users over 2 minutes; hold for 5 minutes; ramp down. Measure: avg latency, p95/p99 latency, throughput (reqs/sec), error rate, response time distribution. SLA: avg <= 2s, p95 <= 3s, error rate < 0.1%. (2) Permission check (simulated authorization check on a protected endpoint): similar scenario, but with valid token. Identify bottlenecks: DB query, token generation, password hashing (if slow), session store access. Document in load_test_m2_auth_results.md: tool, scenario, results, bottlenecks, recommendations. If SLA not met: optimize (cache, async, connection pooling, etc.) and re-test.
**Open-Ended Questions**: Sustained load or spike test? Mixed workload (successful + failed logins)? Test against staging or local env? Automated load tests in CI?

#### Task 8.5: Run vulnerability scan (SAST/DAST) and fix findings
**Full Description**: Execute vulnerability scan on M2 code/infra to identify security issues. Fix all high/critical findings in scope.
**Assumptions**: Scan tools available (e.g., SonarQube for SAST, OWASP ZAP for DAST, Snyk for dependencies); baseline scan done before M2; incremental scans during development.
**Implementation Details**: (1) SAST scan on M2 code (authentication, authorization, audit logging modules): check for hardcoded secrets, SQL injection, insecure crypto, etc. (2) DAST scan on M2 endpoints: test for XSS, CSRF, authentication bypass, etc. (3) Dependency scan on M2 libs: identify vulnerable transitive dependencies. Categorize findings: Critical (exploit available), High (likely exploitable), Medium (potential), Low (informational). Fix High/Critical in scope for M2; document Medium/Low for future sprints. Rerun scan after fixes; confirm remediation. Document in security_scan_m2_results.md: tool, findings count by severity, fixed count, open count (with justification).
**Open-Ended Questions**: Annual vs. per-release scan? Automated scan in CI? Third-party penetration testing? Bug bounty program?

### 9) QA & UAT Readiness for M2 (User Story)
**Description**: Ensure test coverage, automation, and UAT preparedness for M2 scope.
**Acceptance Criteria**:
- Test cases cover happy/edge paths for auth, RBAC, audit logging.
- Automated regression for M2 scope runs in CI and passes.
- UAT checklist and seeded data prepared; defects triaged to exit criteria.
- Demo completed with PO approval to promote to staging.
**Tasks**:

#### Task 9.1: Author manual test cases for auth, RBAC, audit logging
**Full Description**: Write comprehensive test cases covering happy, edge, and negative scenarios for authentication, permission enforcement, and audit logging. Organize by test type (functional, negative, boundary).
**Assumptions**: Test cases organized in test management tool or spreadsheet; testers execute manually before automation; test data seeded in test environment.
**Implementation Details**: Test case structure: ID, title, precondition, steps, expected result, status. Examples: (1) TC-001: User logs in with valid credentials -> expect success, token issued, audit event logged. (2) TC-002: User logs in with invalid password -> expect 401, no token, audit failure event. (3) TC-003: Admin creates user and assigns role -> user created, role assigned, audit events. (4) TC-004: Sales user views Accounting reports -> expect 403, audit denial logged. (5) TC-005: User changes password -> audit event includes action=PASSWORD_CHANGE_SELF, outcome=success, no password logged. Total: ~50–100 test cases covering M2 scope. Document in test_cases_m2_auth_rbac.xlsx or markdown.
**Open-Ended Questions**: API-level or UI-level or both? Automated (Selenium/Cypress) or manual? Test data setup (SQL script, API, fixtures)?

#### Task 9.2: Add automated API/UI tests to CI for M2 scope
**Full Description**: Implement automated regression tests for M2 features (auth, RBAC, audit) integrated into CI pipeline. Tests are deterministic and repeatable.
**Assumptions**: Test framework: Jest/Mocha for API, Cypress/Playwright for UI; test data seeded/cleaned per test run; CI mirrors production; tests kept in repo.
**Implementation Details**: Test structure: API tests (login success/failure, logout, permission denial, audit queries, role CRUD); UI tests (login flow, user admin console, audit log viewer). Setup: migrate test DB, seed test users/roles, cleanup after. Assertions: response codes, bodies, DB state, audit events. Example tests: (1) "should login with valid credentials" -> 200, token issued. (2) "should return 401 with invalid password" -> 401, no token. (3) "should emit AUTH_LOGIN audit event on success" -> query audit_logs, verify event. (4) "should return 403 if user lacks permission" -> 403, audit denial logged. CI integration: run on every PR; block merge on failure. Target: 80%+ code coverage for M2 scope.
**Open-Ended Questions**: E2E or unit tests? Mock external services? Parallel execution? Perf tests in CI?

#### Task 9.3: Prepare UAT checklist, scenarios, and seed data
**Full Description**: Create UAT artifacts: scenarios, checklist, and seed data setup. Align with roles/permissions matrix.
**Assumptions**: UAT run by client/business users in staging; testers non-technical; scenarios cover end-to-end workflows and edge cases.
**Implementation Details**: UAT Checklist:
1. Authentication: Sales user logs in (valid creds), disabled user cannot login, session expires after 30 min inactivity, user logs out, old token rejected.
2. Password: User changes password in profile, admin forces change, user notified via email, flagged user must change on next login.
3. RBAC: Admin creates/disables users, assigns roles, Sales user accesses Sales module (not Accounting), role permissions enforced on all endpoints.
4. Audit: Audit logs show login attempts, user creation, role assignment, password changes; logs tamper-evident (no delete/edit).
Seed data: 5 test users (one per role: Admin, Sales, Warehouse, Accounting, Purchasing); 3–5 products/orders for testing; secure password doc.
**Open-Ended Questions**: PO approval? Multiple test cycles? Perf expectations?

#### Task 9.4: Execute regression testing; triage and close defects to exit criteria
**Full Description**: Run automated and manual tests; log failures as defects; prioritize/fix before M2 sign-off.
**Assumptions**: Defect tracking (Jira/ADO); priority: Critical (blocks feature), High (significant), Medium (minor), Low (cosmetic); exit criteria: zero critical/high, max 3 open medium.
**Implementation Details**: (1) Run automated tests; create defect on failure. (2) Run manual UAT checklist; log failures. (3) Per defect: assign priority, log steps, estimate effort. (4) Triage with tech lead: prioritize, assign. (5) Fix; re-test; confirm. (6) Track to closure. (7) Report: X total defects, Y fixed, Z remaining (by priority). (8) Get PO sign-off. Exit criteria: zero critical, max 1–2 high, max 3 medium, low deferred.
**Open-Ended Questions**: Regression suite per-commit (costly) or nightly? Coverage metrics? Flaky test quarantine?

#### Task 9.5: Schedule and run demo; record PO sign-off for staging promotion
**Full Description**: Demo M2 features to PO/stakeholders; capture approvals for staging promotion. Walkthrough: login, RBAC, audit logging, admin console.
**Assumptions**: Demo audience: PO, BA, tech lead; 30–60 min; recording available for reference.
**Implementation Details**: Demo script: (1) Authentication (login different users, session timeout, logout). (2) Password mgmt (admin forces change, user prompted on login). (3) RBAC (admin creates roles, assign, users denied access per role). (4) Audit logs (filter, view, export CSV). (5) Admin console (create/disable user, assign roles, all audited). Environment: staging or test env with realistic data. Record demo; capture PO comments/approvals. On approval: document sign-off in M2 completion spreadsheet; proceed to staging deployment.
**Open-Ended Questions**: Live or pre-recorded? Separate demo (technical vs. business)? Feedback survey?

### 10) Staging Environment for Client Self-Testing (Cloud) (User Story)
**Description**: Provision and wire a cloud staging environment for M2, with client access and auditability.
**Acceptance Criteria**:
- Staging infra provisioned (app, API, DB, storage/logs) with network/security controls.
- CI/CD deploys M2 builds to staging with env-specific config/secrets; rollback plan documented.
- Staging data seeding strategy defined (anonymized or synthetic) and applied.
- Client testers have access (with basic auth/MFA not required per ground rule, but account-based access), audit logging enabled.
- Smoke test checklist executed post-deploy; results recorded.
**Tasks**:

#### Task 10.1: Provision staging infra (app, API, DB, logs) with network/security controls
**Full Description**: Set up cloud-hosted staging environment with application servers, APIs, databases, logging, and networking controls. Ensure isolation from production and client-secure access.
**Assumptions**: Cloud provider: AWS, Azure, GCP, or on-prem; infrastructure as code (Terraform, CloudFormation) preferred; network isolation (VPC/VNet, security groups/NSGs); TLS certificates for HTTPS.
**Implementation Details**: Infrastructure components: (1) Application server (2–4 instances, load balanced). (2) API server (shared or separate). (3) Database (PostgreSQL, MySQL, or equivalent; separate from prod). (4) Logging/audit storage (append-only). (5) Cache (Redis, if needed for sessions). Network: (1) VPC/VNet isolated from production. (2) Security groups: allow inbound HTTPS (443) from client IPs; SSH (22) from admin IPs only; outbound to app/API/DB. (3) TLS certificates (self-signed for staging OK, or use Let's Encrypt). (4) DNS: staging.lightbooks.example.com -> load balancer. Data storage: encrypt at rest; enable versioning/backup. Logging: centralized (ELK stack, CloudWatch, etc.) for troubleshooting. Document infrastructure in terraform/ or CloudFormation/ directory; IaC versioned in repo.
**Open-Ended Questions**: Single-region or multi-region? Auto-scaling? Disaster recovery/backup strategy? Cost optimization (spot instances)?

#### Task 10.2: Configure CI/CD pipeline to deploy M2 builds to staging with env-specific config/secrets
**Full Description**: Wire CI/CD pipeline to automatically deploy M2 builds to staging environment. Manage environment-specific configuration and secrets securely.
**Assumptions**: CI/CD tool: Jenkins, GitLab CI, GitHub Actions, Azure DevOps; configuration externalized (env vars, config files); secrets managed in vault (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault, etc.); rollback capability.
**Implementation Details**: CI/CD stages: (1) Build (compile code, run tests, lint). (2) Security scan (SAST, dependency check). (3) Container image (Docker, push to registry). (4) Deploy to staging (SSH to instances, pull image, update config, restart). Staging config: (1) Environment variables (APP_ENV=staging, DEBUG=true, DB_HOST=staging-db.internal, API_KEY_THIRD_PARTY=xxx). (2) Secrets (DB password, JWT signing key, email API key): fetch from vault at deploy time. (3) Config file (logging level, session timeout, audit retention): mount from ConfigMap or config file. Rollback: keep previous N builds; allow quick rollback via manual trigger or automatic on health check failure. Pipeline documentation: .github/workflows/deploy-staging.yml or .gitlab-ci.yml (in repo).
**Open-Ended Questions**: Blue-green deployment or rolling? Canary deployment? Smoke tests post-deploy (auto-rollback on failure)? Feature flags?

#### Task 10.3: Define and run data seeding (synthetic/anonymized) appropriate for client testing
**Full Description**: Create data seeding strategy for staging: populate with realistic but non-sensitive test data so client can test without PII concerns.
**Assumptions**: Production data export not used (privacy/security); synthetic or anonymized data used instead; seed script idempotent (safe to re-run).
**Implementation Details**: Data categories: (1) Users: synthetic (test_admin@example.com, test_sales@example.com, etc.) with known passwords (documented in secure location). (2) Products/Catalog: copy from M1 staging or generate synthetic. (3) Customers: anonymized (remove PII like real customer names/addresses if copying from prod). (4) Orders/Transactions: synthetic or masked. Seed strategy: (1) Migration script: creates schema and inserts seed data. (2) Idempotent: uses UPSERT or "insert if not exists" (safe to re-run). (3) Parameterized: can seed varying quantities (100 vs. 1000 products) for perf testing. Execute on staging deploy: migrations run, seed runs, DB ready for testing. Document: scripts in db/seeds/ directory; README with seed instructions.
**Open-Ended Questions**: Reset staging data between test cycles? Snapshot for quick revert? Realistic data distribution (many small orders vs. few large)?

#### Task 10.4: Create client tester accounts; enable audit logging; share access instructions
**Full Description**: Provision user accounts for client testing team; enable audit logging in staging; provide secure access credentials and instructions.
**Assumptions**: Client provides list of tester names/emails; accounts created with temporary passwords; MFA optional (per ground rule, not required); audit logging on and verified.
**Implementation Details**: (1) Create test accounts: POST /admin/users with usernames test_user1@client.com, test_user2@client.com, etc.; assign roles (Sales, Warehouse, Accounting, etc.) as requested. (2) Set temporary passwords (auto-generated); send via secure email. (3) Force password change on first login (use Task 2.2: force-password-change flag). (4) Verify audit logging: confirm audit_logs table populated on login/actions; spot-check a few events. (5) Share access instructions: document with (i) URL, (ii) username, (iii) temporary password, (iv) link to reset password, (v) expected role/permissions, (vi) troubleshooting contact. Email securely (separate from password if possible).
**Open-Ended Questions**: VPN/IP whitelisting for client access? Support contact/helpdesk? Training materials? Feedback collection (survey, bug report form)?

#### Task 10.5: Execute smoke test checklist; record outcomes and rollback readiness
**Full Description**: After deploy to staging, run quick smoke tests to verify basic functionality works. Document results and confirm rollback plan.
**Assumptions**: Smoke test checklist covers critical paths: login, RBAC, audit; not exhaustive (full testing in UAT). Rollback plan is documented and team is ready.
**Implementation Details**: Smoke test checklist (manual or automated):
1. [ ] App is accessible at staging URL (200 OK on landing page).
2. [ ] Can login with test user credentials; receive token.
3. [ ] Session timeout enforced; token rejected after expiry.
4. [ ] Different role (Sales user) denied access to Accounting module (403).
5. [ ] Audit logs captured login events; visible in audit log viewer.
6. [ ] Admin can create user and assign role; actions audited.
7. [ ] Password change works; user can change and re-login with new password.
8. [ ] Admin can force password change; user prompted on next login.
9. [ ] Logout works; token invalidated.
10. [ ] No errors in logs or monitoring alerts.
Execute tests; document results (pass/fail/blocked); time of execution. If any critical fail: rollback (use rollback plan below); investigate; fix; redeploy. On success: sign-off from QA/tech lead.
**Open-Ended Questions**: Automated smoke tests (CI integration)? Performance baseline (capture baseline metrics)? Security scan on staging post-deploy?

### 11) Deployment & Rollback (M2) (User Story)
**Description**: Document and validate deployment and rollback for M2 services.
**Acceptance Criteria**:
- Deployment runbook and rollback procedure documented and validated in staging.
- Config as code; secrets managed securely; health checks defined and executed post-deploy.
- Rollback tested at least once in staging.
**Tasks**:
- Write deployment runbook (steps, pre-checks, post-checks) for M2 changes.
- Externalize config (files/vars) and wire to secrets manager; document overrides per env.
- Implement health checks and post-deploy validation script; add to pipeline.
- Execute a rollback drill in staging; document results and fixes.

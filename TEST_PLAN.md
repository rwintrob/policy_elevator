# 🧪 Comprehensive System & Security Test Plan: JIT Policy Elevator

- **Repository**: `https://github.com/rwintrob/policy_elevator`
- **Target System**: JIT Policy Elevator GCP IAM Broker (FastAPI + IAM Policy v3 CEL + Cloud Audit Watchdog)
- **Test Framework**: `pytest` + `fastapi.testclient.TestClient`
- **Document Version**: `1.0.0`
- **Date**: `2026-09-15`

---

## 🎯 1. Test Objectives & Scope

This test plan provides end-to-end verification of the **JIT Policy Elevator** control plane across two primary dimensions:
1. **System Functional Verification (`FUNC-01` – `FUNC-12`)**: Validates all core operational workflows—identity eligibility, request creation, four-eyes approval, CEL condition synthesis, manual & automatic revocation, ETag cryptographic verification, Watchdog telemetry, audit logging, and email notifications.
2. **Security & Remediation Verification (`SEC-01` – `SEC-09`)**: Verifies security invariants and regression tests mapped directly to the 9 vulnerabilities identified in the Cybersecurity Assessment (`REMEDIATION_PLAN.md`).

---

## ⚙️ 2. Test Execution Environment

### Running the Automated Test Suite
The test suite runs in isolated unit/integration mode using FastAPI's `TestClient` with `iam_mgr.mock_mode = True` and in-memory `audit_mgr` state:

```bash
# Execute all functional and security verification tests via uv:
uv run --with-requirements requirements.txt --with pytest --with httpx pytest -v
```

---

## 📋 3. System Functional Verification Matrix (`FUNC-01` – `FUNC-12`)

| Test ID | Feature / Subsystem | Endpoint / Component | Test Description & Inputs | Expected Result & Invariants |
| :--- | :--- | :--- | :--- | :--- |
| **`FUNC-01`** | Service Health & Readiness | `GET /api/health` | Query health endpoint for liveness and service metadata. | Returns `200 OK` with `{"status": "HEALTHY", "service": "jit-policy-elevator"}`. |
| **`FUNC-02`** | Identity Eligibility & Domain Policy | `GET /api/identity/check` | Test authorized domain (`admin@rwintrob.altostrat.com`), unauthorized domain (`user@external.com`), and malformed emails. | Authorized domain returns `ELIGIBLE` (`is_eligible_requester=True`, `is_eligible_approver=True`); external returns `INELIGIBLE`. |
| **`FUNC-03`** | Supported Roles Catalog | `GET /api/roles` | Retrieve available GCP IAM roles eligible for JIT elevation. | Returns `200 OK` with list of `RoleOption` items including `roles/orgpolicy.policyAdmin`, `roles/resourcemanager.projectIamAdmin`, etc. |
| **`FUNC-04`** | Elevation Request Creation | `POST /api/requests` | Submit valid elevation request (`requester_email`, `target_project_id`, `role`, `duration_minutes`, `approver_email`, `justification`). | Returns `200 OK`, assigns unique 8-char `request_id`, sets `status="PENDING"`, and writes `REQUEST_CREATED` audit log entry. |
| **`FUNC-05`** | Four-Eyes Approval & IAM CEL Binding | `POST /api/requests/{id}/approve` | Designated approver submits `{"approved": true, "comments": "..."}`. | Status transitions to `ACTIVE`, `iam_mgr.grant_project_role` binds role with condition `resource.name.startsWith("projects/{target_project_id}")`, stamps `etag`, and starts Watchdog monitoring. |
| **`FUNC-06`** | Request Rejection Workflow | `POST /api/requests/{id}/approve` | Designated approver submits `{"approved": false, "comments": "Insufficient justification"}`. | Status transitions to `REJECTED`, no IAM binding is created, and `REQUEST_REJECTED` audit event is logged. |
| **`FUNC-07`** | Manual Revocation & ETag Proof | `POST /api/requests/{id}/revoke` | Revoke an `ACTIVE` elevation grant before expiration. | Status transitions to `REVOKED`, conditional IAM binding is removed, `verify_permission_removed` returns `verified_removed=True` with policy `etag` proof, and logs `GRANT_REVOKED`. |
| **`FUNC-08`** | Independent Cryptographic Re-Verification | `POST /api/requests/{id}/verify` | Trigger on-demand verification check on a `REVOKED` or `EXPIRED` request. | Queries Organization IAM Policy v3, confirms absence of member binding, updates `verification_result`, and logs `PERMISSION_REMOVAL_VERIFIED`. |
| **`FUNC-09`** | Watchdog Activity Telemetry & Auto-Rollback | `GET /api/requests/{id}/watchdog` | Poll Watchdog summary for an active grant through `IDLE` -> `ACTIVE_OPERATIONS` -> `COMPLETED` states. | Watchdog records detected Cloud Audit Log operations (`DetectedOperation`), transitions state, and triggers early `WATCHDOG_AUTO_REVOKED` once idle quiet window elapses. |
| **`FUNC-10`** | Time-Based Expiration Auto-Revocation | Background `auto_revocation_loop` | Simulate an `ACTIVE` request whose `expires_at` timestamp is in the past (`now >= expires_at`). | Worker detects expired grant, revokes IAM binding, verifies removal, sets status to `EXPIRED`, and logs `GRANT_EXPIRED_AUTO_REVOKED`. |
| **`FUNC-11`** | Audit Log Persistence & Filtering | `GET /api/audit` | Query audit logs unfiltered and filtered by `project_id`, `requester_email`, `approver_email`, and `event_type`. | Returns chronological list of `AuditLogEntry` records matching filter predicates with complete event payloads. |
| **`FUNC-12`** | Notification Configuration & Test Dispatch | `GET /api/notifications/config`<br>`POST /api/notifications/test` | Query active notification provider configuration and trigger test dispatch. | Returns active provider settings (`CONSOLE`, `SMTP`, `SENDGRID`, `MAILGUN`) and dispatches test message with diagnostic status. |

---

## 🛡️ 4. Security & Remediation Verification Matrix (`SEC-01` – `SEC-09`)

Each security test case verifies the defense against the corresponding finding from `REMEDIATION_PLAN.md`:

| Test ID | Finding Ref | Vulnerability Tested | Test Procedure / Attack Vector | Expected Post-Remediation Outcome |
| :--- | :---: | :--- | :--- | :--- |
| **`SEC-01`** | `FINDING-01` | Unauthenticated Self-Approval & Approver Spoofing | Requester `bob@rwintrob.altostrat.com` calls `POST /api/requests/{id}/approve` with header `X-Goog-Authenticated-User-Email: bob@rwintrob.altostrat.com` but JSON body `{"approver_email": "admin@rwintrob.altostrat.com", "approved": true}`. | **Blocked (`403 Forbidden`)**: Backend derives caller strictly from authenticated header and rejects caller mismatch against `req.approver_email`. |
| **`SEC-02`** | `FINDING-02` | Arbitrary CEL Condition Injection | Submit `POST /api/requests` with `target_project_id`: `'test") \|\| true \|\| resource.name.startsWith("'`. | **Blocked (`400` / `422`)**: Strict regex validator (`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`) rejects non-conforming project IDs before CEL synthesis. |
| **`SEC-03`** | `FINDING-03` | Separation of Duties (SoD) Subaddressing & Dot Bypass | Submit `POST /api/requests` with `requester_email="alice.smith@rwintrob.altostrat.com"` and `approver_email="alicesmith+admin@rwintrob.altostrat.com"`. | **Blocked (`400 Bad Request`)**: `canonicalize_email()` normalizes both addresses to `alicesmith@rwintrob.altostrat.com` and enforces SoD violation. |
| **`SEC-04`** | `FINDING-04` | Stored DOM XSS via Inline Event Handlers | Inspect frontend table row rendering for project ID containing quotes/JS payloads; verify absence of inline `onclick="filterByProject('...')"` string interpolation. | **Safe DOM Rendering**: Values stored in `data-filter-value` attributes and handled via `addEventListener` without JS execution. |
| **`SEC-05`** | `FINDING-05` | Tier-0 Organization Admin Over-Privileging | Audit `deploy.sh` IAM role bindings for Cloud Run service account (`jit-policy-elevator-sa`). | **Least Privilege**: Uses minimal custom role (`jitPolicyElevatorBroker`) instead of global `roles/resourcemanager.organizationAdmin`. |
| **`SEC-06`** | `FINDING-06` | HTML Injection in Approval Emails | Call `send_approver_notification` with `justification='<a href="https://evil.com">Phishing Link</a>'`. | **Escaped Output**: `html.escape()` converts `<`, `>`, and `"` into safe HTML entities (`&lt;a href=&quot;...&quot;&gt;`). |
| **`SEC-07`** | `FINDING-07` | Watchdog Production Default Mock Mode | Instantiate `WatchdogAgent()` without arguments in default environment (`ENABLE_MOCK_WATCHDOG` unset). | **Production Safe**: `watchdog.mock_mode` defaults to `False` and `idle_quiet_seconds` defaults to `180` seconds. |
| **`SEC-08`** | `FINDING-08` | False-Positive Revocation Verification | In mock org policy, add an unconditional binding (`condition=None`) for `user:dev@domain.com` alongside the conditional JIT binding. Revoke the JIT binding and call `verify_permission_removed`. | **Accurate Detection**: Verification detects that `user:dev@domain.com` still holds unconditional access to `target_role` and returns `verified_removed=False`. |
| **`SEC-09`** | `FINDING-09` | Plaintext Secret Passing & Hardcoded Org ID | Audit `deploy.sh` secret flags and fallback configuration behavior. | **Secret Manager Integration**: Sensitive keys use `--set-secrets` rather than plaintext `--set-env-vars`. |

---

## 🧪 5. Automated Test Suite Structure

The repository includes two complementary automated test modules in [`tests/`](file:///usr/local/google/home/rwintrob/code/policy_elevator/tests):
1. [`tests/test_elevator.py`](file:///usr/local/google/home/rwintrob/code/policy_elevator/tests/test_elevator.py): Core unit tests covering identity checks, request lifecycle, multi-role elevation, Watchdog state transitions, and notification configuration.
2. [`tests/test_system_verification.py`](file:///usr/local/google/home/rwintrob/code/policy_elevator/tests/test_system_verification.py): Comprehensive end-to-end functional test suite implementing `FUNC-01` through `FUNC-12` and security verification checks.

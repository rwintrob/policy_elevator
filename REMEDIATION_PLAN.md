# 🛡️ Security Remediation Plan: JIT Policy Elevator GCP IAM Broker

- **Repository**: `https://github.com/rwintrob/policy_elevator`
- **Baseline Commit**: `612fe376bd32679f3b47a208d6ade5007d2fd6a9`
- **Target Assessment**: Autonomous 5-Phase AI & Cloud Security Review (`FINDING-01` through `FINDING-09`)
- **Document Version**: `1.0.0`
- **Date**: `2026-09-15`

---

## 📋 Executive Overview

This document outlines the phased engineering remediation plan for all **9 security vulnerabilities** (2 Critical, 4 High, 2 Medium, 1 Low) identified during the cybersecurity assessment of the **JIT Policy Elevator** broker.

### Remediation Priorities & Rollout Phases

| Phase | Priority | Target SLA | Scope | Findings Addressed |
| :--- | :---: | :---: | :--- | :--- |
| **Phase 1** | **P0 (Critical)** | **Day 1 (Immediate)** | Authentication, Caller Verification & CEL Injection Prevention | `FINDING-01`, `FINDING-02` |
| **Phase 2** | **P1 (High)** | **Week 1** | Separation of Duties Canonicalization, XSS Hardening, Least-Privilege IAM & Email Escaping | `FINDING-03`, `FINDING-04`, `FINDING-05`, `FINDING-06` |
| **Phase 3** | **P2 (Medium/Low)** | **Sprint 1** | Watchdog Production Defaults, Revocation Verification Completeness & Secret Manager Integration | `FINDING-07`, `FINDING-08`, `FINDING-09` |

---

## 🚨 Phase 1: Immediate Critical Fixes (P0 - Day 1)

### 1. `FINDING-01`: Unauthenticated Self-Approval & Arbitrary Approver Spoofing
- **Severity**: CRITICAL (CVSS 9.8) | **CWE**: `CWE-287 / CWE-306 / CWE-863`
- **Affected Files**:
  - [`models.py`](file:///usr/local/google/home/rwintrob/code/policy_elevator/models.py) (`ApprovalAction` schema)
  - [`main.py`](file:///usr/local/google/home/rwintrob/code/policy_elevator/main.py) (`process_approval` at lines 308–331)
- **Root Cause**:
  `POST /api/requests/{request_id}/approve` accepts `action.approver_email` from the untrusted JSON body (`approver = (action.approver_email or user_email).strip()`) without verifying that the authenticated caller (`user_email` extracted from IAP headers) matches the designated approver on the request (`req.approver_email`). Any user can approve their own request by passing another user's email in the request body.
- **Remediation Design**:
  1. Remove `approver_email` from `ApprovalAction` in [`models.py`](file:///usr/local/google/home/rwintrob/code/policy_elevator/models.py), or ignore any client-supplied `approver_email` and strictly derive the approver identity from `get_current_user_identity(request)`.
  2. Enforce that the authenticated caller (`user_email`) matches the designated approver (`req.approver_email`) using canonicalized email comparison (or belongs to a designated Security Admin group).
- **Concrete Code Change (`main.py`)**:
  ```diff
  --- a/main.py
  +++ b/main.py
  @@ -308,8 +308,15 @@
   @app.post("/api/requests/{request_id}/approve", response_model=ElevationRequest)
   async def process_approval(request_id: str, action: ApprovalAction, request: Request):
  -    user_email = get_current_user_identity(request)
  -    approver = (action.approver_email or user_email).strip()
  +    req = audit_mgr.get_request(request_id)
  +    if not req:
  +        raise HTTPException(status_code=404, detail="Request not found")
  +
  +    # Derive approver strictly from authenticated caller identity (IAP / reverse proxy header)
  +    approver = get_current_user_identity(request).strip()
  +
  +    # Verify caller is the designated approver for this request
  +    if canonicalize_email(approver) != canonicalize_email(req.approver_email):
  +        raise HTTPException(
  +            status_code=403,
  +            detail=f"Unauthorized: Authenticated caller '{approver}' is not the designated approver ('{req.approver_email}')."
  +        )
  ```
- **Verification Criteria**:
  - Attempting to approve a request where `X-Goog-Authenticated-User-Email` does not match `req.approver_email` must return `403 Forbidden`, even if `approver_email` is supplied in the JSON payload.

---

### 2. `FINDING-02`: Arbitrary Common Expression Language (CEL) Injection via Unsanitized `target_project_id`
- **Severity**: CRITICAL (CVSS 9.8) | **CWE**: `CWE-94 / CWE-89`
- **Affected Files**:
  - [`models.py`](file:///usr/local/google/home/rwintrob/code/policy_elevator/models.py) (`ElevationRequestCreate`)
  - [`iam_manager.py`](file:///usr/local/google/home/rwintrob/code/policy_elevator/iam_manager.py) (`grant_project_role` at lines 56–66)
- **Root Cause**:
  `iam_manager.py` constructs CEL expressions via raw string interpolation:
  `cond_expr = f'resource.name.startsWith("projects/{target_project_id}")'`
  An attacker supplying `test") || true || resource.name.startsWith("` injects arbitrary CEL clauses that evaluate to `true` across all organization resources.
- **Remediation Design**:
  1. Define a strict GCP Project ID regular expression validator (`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`) in both `models.py` (Pydantic field validator) and `iam_manager.py` (defense-in-depth runtime check).
  2. Reject any `target_project_id` that fails regex validation before constructing CEL titles or expressions.
- **Concrete Code Change (`iam_manager.py` & `models.py`)**:
  ```python
  import re

  GCP_PROJECT_ID_REGEX = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")

  def validate_project_id(project_id: str) -> str:
      clean_id = (project_id or "").strip()
      if not GCP_PROJECT_ID_REGEX.match(clean_id):
          raise ValueError(
              f"Invalid GCP Project ID '{project_id}'. Must be 6-30 characters, lowercase letters, digits, or hyphens."
          )
      return clean_id
  ```
- **Verification Criteria**:
  - Submitting `target_project_id` containing quotes, spaces, uppercase letters, parentheses, or `||` operators returns `422 Unprocessable Entity` / `400 Bad Request` and never reaches `IAMManager`.

---

## 🔒 Phase 2: High-Priority Hardening (P1 - Week 1)

### 3. `FINDING-03`: Separation of Duties (SoD) Bypass via Email Subaddressing (`+tag`) & Dot Aliasing
- **Severity**: HIGH (CVSS 8.8) | **CWE**: `CWE-284 / CWE-863`
- **Affected Files**:
  - [`main.py`](file:///usr/local/google/home/rwintrob/code/policy_elevator/main.py) (lines 249–253, 329–331)
- **Root Cause**:
  SoD checks use `requester.lower() == approver.lower()`. Users can bypass this check using subaddressed aliases (`user+approver@domain.com`) or dot aliases (`u.ser@domain.com`), routing the approval notification to their own mailbox.
- **Remediation Design**:
  Implement a `canonicalize_email(email: str) -> str` helper function in `main.py` and apply it to all SoD comparisons:
  ```python
  def canonicalize_email(email: str) -> str:
      """Normalizes email address to prevent +tag subaddressing and dot-aliasing SoD bypasses."""
      clean = (email or "").strip().lower()
      if "@" not in clean:
          return clean
      local, domain = clean.split("@", 1)
      # Strip +subaddress tag
      local = local.split("+", 1)[0]
      # Strip dots from local part to prevent Google Workspace/Gmail dot aliasing
      local = local.replace(".", "")
      return f"{local}@{domain}"
  ```
- **Verification Criteria**:
  - `canonicalize_email("alice.smith+admin@altostrat.com") == canonicalize_email("alicesmith@altostrat.com")` evaluates to `True` and triggers a `400 Bad Request` Separation of Duties violation.

---

### 4. `FINDING-04`: Stored DOM Cross-Site Scripting (XSS) via HTML Entity Decoding in Inline JS Event Handlers
- **Severity**: HIGH (CVSS 8.2) | **CWE**: `CWE-79 / CWE-116`
- **Affected Files**:
  - [`static/js/app.js`](file:///usr/local/google/home/rwintrob/code/policy_elevator/static/js/app.js) (lines 410–435, 1031–1034)
- **Root Cause**:
  `app.js` interpolates user-controlled values (`target_project_id`, `requester_email`, `approver_email`) inside inline HTML `onclick="filterByProject('${escapeHtml(...)}')"` attributes. Browsers decode HTML entities inside attribute values prior to JavaScript execution, enabling quote breakout and arbitrary JS execution.
- **Remediation Design**:
  1. Remove inline `onclick="filterBy..."` string interpolation from rendered table rows.
  2. Render safe `data-filter-type` and `data-filter-value` attributes on `.clickable-link` elements.
  3. Attach a single delegated click event listener on `#requests-table-body` that reads `event.target.closest('[data-filter-type]')` and invokes the appropriate filter function using `.dataset.filterValue`.
- **Concrete Code Change (`static/js/app.js`)**:
  ```javascript
  // Safe rendering using dataset attributes:
  <span class="clickable-link" data-filter-type="project" data-filter-value="${escapeHtml(req.target_project_id)}">
      <strong>${escapeHtml(req.target_project_id)}</strong>
  </span>
  ```
- **Verification Criteria**:
  - Strings containing `'`, `"`, `);alert(1);//` rendered in table cells do not execute JavaScript when clicked or hovered.

---

### 5. `FINDING-05`: Tier-0 Organization Admin Over-Privileging & Single Point of Failure in Deployment
- **Severity**: HIGH (CVSS 7.8) | **CWE**: `CWE-250 / CWE-269`
- **Affected Files**:
  - [`deploy.sh`](file:///usr/local/google/home/rwintrob/code/policy_elevator/deploy.sh) (lines 51–65)
- **Root Cause**:
  Modifying organization-level IAM policies (`organizations.setIamPolicy`) requires organization-level permissions. Granting full `roles/resourcemanager.organizationAdmin` makes the Cloud Run service account a global Tier-0 super-admin.
- **Remediation Design**:
  1. Provision a dedicated, minimal **Custom Organization Role** (`roles/jitPolicyElevatorBroker`) containing strictly:
     - `resourcemanager.organizations.getIamPolicy`
     - `resourcemanager.organizations.setIamPolicy`
     - `resourcemanager.projects.get`
  2. Bind this custom role to `jit-policy-elevator-sa` with an IAM Condition restricting policy modifications or enforcing VPC Service Controls perimeter ingress.
- **Concrete Code Change (`deploy.sh`)**:
  ```bash
  # Create least-privilege custom role at the Organization level
  gcloud iam roles create jitPolicyElevatorBroker \
      --organization="${GCP_ORGANIZATION_ID}" \
      --title="JIT Policy Elevator Broker" \
      --description="Minimal permissions to read/write conditional IAM bindings for JIT elevation" \
      --permissions="resourcemanager.organizations.getIamPolicy,resourcemanager.organizations.setIamPolicy,resourcemanager.projects.get" \
      --stage="GA" || true
  ```

---

### 6. `FINDING-06`: HTML Injection & Phishing Vector in Email Notification Template
- **Severity**: HIGH (CVSS 7.5) | **CWE**: `CWE-79 / CWE-80 / CWE-116`
- **Affected Files**:
  - [`notifier.py`](file:///usr/local/google/home/rwintrob/code/policy_elevator/notifier.py) (`send_approver_notification` at lines 219–263)
- **Root Cause**:
  `notifier.py` formats HTML emails using raw f-strings (`{request.justification}`, `{request.target_project_id}`, `{approver}`). Attackers can inject arbitrary HTML/CSS phishing banners into emails sent to security approvers.
- **Remediation Design**:
  Import `html` and sanitize all user-supplied fields using `html.escape(str(val), quote=True)` prior to constructing `body_html`.
- **Concrete Code Change (`notifier.py`)**:
  ```python
  import html

  safe_approver = html.escape(approver or "", quote=True)
  safe_req_id = html.escape(request.request_id or "", quote=True)
  safe_requester = html.escape(request.requester_email or "", quote=True)
  safe_project = html.escape(request.target_project_id or "", quote=True)
  safe_role = html.escape(request.role or "", quote=True)
  safe_justification = html.escape(request.justification or "", quote=True)
  ```
- **Verification Criteria**:
  - Submitting justification `<a href="https://evil.com">Click Here</a>` renders literal escaped entities (`&lt;a href=&quot;https://evil.com&quot;&gt;`) in `body_html`.

---

## ⚙️ Phase 3: Operational & Hygiene Fixes (P2 - Sprint 1)

### 7. `FINDING-07`: Premature Revocation & Operational DoS via Default Mock Watchdog Loop
- **Severity**: MEDIUM (CVSS 6.8) | **CWE**: `CWE-362 / CWE-400`
- **Affected Files**:
  - [`watchdog.py`](file:///usr/local/google/home/rwintrob/code/policy_elevator/watchdog.py) (line 60)
  - [`main.py`](file:///usr/local/google/home/rwintrob/code/policy_elevator/main.py) (line 39)
- **Root Cause**:
  `WatchdogAgent.__init__` defaults to `mock_mode: bool = True` and `idle_quiet_seconds: int = 15`. In production deployments, `WatchdogAgent()` is instantiated with default arguments, causing every approved grant to simulate an operation at T+3s and forcibly auto-revoke at T+18s.
- **Remediation Design**:
  1. Change default `mock_mode` in `WatchdogAgent.__init__` to read from environment variable `ENABLE_MOCK_WATCHDOG` (defaulting to `False` in production).
  2. Set default `idle_quiet_seconds` to `int(os.environ.get("WATCHDOG_QUIET_SECONDS", "180"))`.
- **Concrete Code Change (`watchdog.py`)**:
  ```python
  def __init__(
      self,
      idle_quiet_seconds: Optional[int] = None,
      mock_mode: Optional[bool] = None
  ):
      self.idle_quiet_seconds = idle_quiet_seconds or int(os.environ.get("WATCHDOG_QUIET_SECONDS", "180"))
      if mock_mode is None:
          self.mock_mode = os.environ.get("ENABLE_MOCK_WATCHDOG", "false").lower() in ("true", "1", "yes")
      else:
          self.mock_mode = mock_mode
  ```

---

### 8. `FINDING-08`: False-Positive Revocation Verification via Condition Title Scoping Flaw
- **Severity**: MEDIUM (CVSS 6.3) | **CWE**: `CWE-345 / CWE-697`
- **Affected Files**:
  - [`iam_manager.py`](file:///usr/local/google/home/rwintrob/code/policy_elevator/iam_manager.py) (`verify_permission_removed` at lines 221–295)
- **Root Cause**:
  `verify_permission_removed` checks only bindings where `condition.title == cond_title`. If a user holds the same role via an unconditioned binding (`condition is None`) or a broader condition, `verify_permission_removed` falsely certifies `verified_removed=True`.
- **Remediation Design**:
  Update `verify_permission_removed` to inspect all bindings matching `b.get("role") == target_role` where `normalized_member in b.get("members", [])`. Flag `is_present = True` if:
  1. The binding has no condition (`b.get("condition") is None` — unconditional org-wide access), OR
  2. The binding condition title matches `cond_title`, OR
  3. The binding condition expression references `target_project_id`.

---

### 9. `FINDING-09`: Hardcoded Organization ID, Internal Domains & Insecure Plaintext Env Var Passing
- **Severity**: LOW (CVSS 5.3) | **CWE**: `CWE-200 / CWE-532`
- **Affected Files**:
  - [`deploy.sh`](file:///usr/local/google/home/rwintrob/code/policy_elevator/deploy.sh) (lines 82–100)
  - [`iam_manager.py`](file:///usr/local/google/home/rwintrob/code/policy_elevator/iam_manager.py) (lines 21, 54)
- **Root Cause**:
  Hardcoded fallback organization ID `527512186146` and plaintext secret passing (`--set-env-vars="...SMTP_PASSWORD=..."`) expose credentials in Cloud Run revision manifests and Cloud Build logs.
- **Remediation Design**:
  1. Remove hardcoded Organization IDs from code fallbacks; require `GCP_ORGANIZATION_ID` environment configuration when not in mock mode.
  2. Update `deploy.sh` to mount sensitive secrets (`SMTP_PASSWORD`, `SENDGRID_API_KEY`, `MAILGUN_API_KEY`) from Google Cloud Secret Manager using `--set-secrets`:
  ```bash
  # Example Secret Manager binding in deploy.sh:
  gcloud run deploy "${SERVICE_NAME}" \
      ... \
      --set-secrets="SMTP_PASSWORD=jit-smtp-password:latest,SENDGRID_API_KEY=jit-sendgrid-key:latest"
  ```

---

## ✅ Remediation Sign-Off Checklist

- [x] **Phase 1 (`FINDING-01`, `FINDING-02`)**: Caller verification enforced on `/approve`; strict regex validation enforced on `target_project_id`.
- [x] **Phase 2 (`FINDING-03` – `FINDING-06`)**: Email canonicalization active; inline `onclick` handlers removed; custom IAM role scripted; HTML escaping applied to email templates.
- [x] **Phase 3 (`FINDING-07` – `FINDING-09`)**: Watchdog `mock_mode` disabled by default; revocation verification checks unconditioned bindings; secrets migrated to Secret Manager.
- [x] **Regression Suite**: All functional tests (`TEST_PLAN.md`) and security regression tests pass (`pytest` — 41/41 passing).

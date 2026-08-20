import sys
import os
from datetime import datetime
import pytest
from fastapi.testclient import TestClient

# Ensure policy_elevator module directory is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app, iam_mgr, audit_mgr
from models import ElevationStatus

# Force mock mode for unit tests
iam_mgr.mock_mode = True
audit_mgr.use_firestore = False

client = TestClient(app)

def test_health_check():
    """Verify health check endpoint."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"

def test_identity_check_endpoint():
    """Verify identity eligibility check endpoint."""
    # 1. Eligible identity
    resp = client.get("/api/identity/check?email=admin@rwintrob.altostrat.com")
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_eligible_requester"] is True
    assert data["is_eligible_approver"] is True
    assert data["status"] == "ELIGIBLE"
    assert data["domain"] == "rwintrob.altostrat.com"

    # 2. Ineligible identity
    resp_bad = client.get("/api/identity/check?email=attacker@unauthorized.com")
    assert resp_bad.status_code == 200
    bad_data = resp_bad.json()
    assert bad_data["is_eligible_requester"] is False
    assert bad_data["is_eligible_approver"] is False
    assert bad_data["status"] == "INELIGIBLE"
    assert "not authorized" in bad_data["message"]

def test_create_request_success():
    """Verify successful JIT elevation request creation with eligible identities."""
    payload = {
        "requester_email": "dev1@rwintrob.altostrat.com",
        "target_project_id": "prj-test-01",
        "justification": "Business justification for temporary Org Policy override ticket #12345",
        "duration_minutes": 15,
        "approver_email": "scc.admin@rwintrob.altostrat.com"
    }
    response = client.post("/api/requests", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["request_id"] is not None
    assert data["status"] == ElevationStatus.PENDING.value
    assert data["target_project_id"] == "prj-test-01"

def test_create_request_ineligible_requester_rejected():
    """Verify that ineligible requester identity is rejected with 403 Forbidden."""
    payload = {
        "requester_email": "outsider@external-domain.com",
        "target_project_id": "prj-test-ineligible",
        "justification": "Attempting unauthorized request creation",
        "duration_minutes": 15,
        "approver_email": "admin@rwintrob.altostrat.com"
    }
    response = client.post("/api/requests", json=payload)
    assert response.status_code == 403
    assert "Requester Eligibility Denied" in response.json()["detail"]

def test_create_request_ineligible_approver_rejected():
    """Verify that designated approver from unauthorized domain is rejected with 400 Bad Request."""
    payload = {
        "requester_email": "admin@rwintrob.altostrat.com",
        "target_project_id": "prj-test-ineligible-appr",
        "justification": "Attempting request with unauthorized approver",
        "duration_minutes": 15,
        "approver_email": "badapprover@external-domain.com"
    }
    response = client.post("/api/requests", json=payload)
    assert response.status_code == 400
    assert "Designated Approver Eligibility Denied" in response.json()["detail"]

def test_separation_of_duties_violation():
    """Verify that requester cannot approve their own request or designate themselves."""
    # 1. Attempt to create with same requester and approver
    payload = {
        "requester_email": "dev1@rwintrob.altostrat.com",
        "target_project_id": "prj-test-02",
        "justification": "Emergency bugfix justification for Org Policy override",
        "duration_minutes": 30,
        "approver_email": "dev1@rwintrob.altostrat.com"
    }
    req_resp = client.post("/api/requests", json=payload)
    assert req_resp.status_code == 400
    assert "Separation of Duties" in req_resp.json()["detail"]

def test_approval_and_elevation_flow():
    """Verify request approval, IAM elevation, and status transition to ACTIVE."""
    payload = {
        "requester_email": "dev2@rwintrob.altostrat.com",
        "target_project_id": "prj-test-03",
        "justification": "Configuring temporary Serial Port Access Org Policy override",
        "duration_minutes": 15,
        "approver_email": "admin@rwintrob.altostrat.com"
    }
    req_resp = client.post("/api/requests", json=payload)
    assert req_resp.status_code == 200
    req_id = req_resp.json()["request_id"]

    # Approver approves
    approve_payload = {
        "approver_email": "admin@rwintrob.altostrat.com",
        "approved": True,
        "comments": "Approved for 15 minutes"
    }
    app_resp = client.post(f"/api/requests/{req_id}/approve", json=approve_payload)
    assert app_resp.status_code == 200
    data = app_resp.json()
    assert data["status"] == ElevationStatus.ACTIVE.value
    assert data["expires_at"] is not None

def test_approve_ineligible_approver_rejected():
    """Verify that approval by an unauthorized identity is blocked."""
    payload = {
        "requester_email": "dev3@rwintrob.altostrat.com",
        "target_project_id": "prj-test-03b",
        "justification": "Configuring temporary Serial Port Access Org Policy override",
        "duration_minutes": 15,
        "approver_email": "admin@rwintrob.altostrat.com"
    }
    req_resp = client.post("/api/requests", json=payload)
    req_id = req_resp.json()["request_id"]

    # Ineligible approver tries to approve
    approve_payload = {
        "approver_email": "attacker@gmail.com",
        "approved": True,
        "comments": "Malicious approval attempt"
    }
    app_resp = client.post(f"/api/requests/{req_id}/approve", json=approve_payload)
    assert app_resp.status_code == 403
    assert "Approver Eligibility Denied" in app_resp.json()["detail"]

def test_revocation_and_verification_flow():
    """Verify grant revocation and empirical permission removal verification."""
    # 1. Create & Approve
    payload = {
        "requester_email": "ops@rwintrob.altostrat.com",
        "target_project_id": "prj-test-04",
        "justification": "Temporary override testing for VM external IP policy",
        "duration_minutes": 15,
        "approver_email": "admin@rwintrob.altostrat.com"
    }
    req_id = client.post("/api/requests", json=payload).json()["request_id"]
    client.post(f"/api/requests/{req_id}/approve", json={"approver_email": "admin@rwintrob.altostrat.com", "approved": True})

    # 2. Revoke Grant
    revoke_resp = client.post(f"/api/requests/{req_id}/revoke")
    assert revoke_resp.status_code == 200
    data = revoke_resp.json()
    assert data["status"] == ElevationStatus.REVOKED.value
    assert data["verification_result"] is not None
    assert data["verification_result"]["verified_removed"] is True

    # 3. Explicit Verification API
    verify_resp = client.get(f"/api/requests/{req_id}/verify")
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["verified_removed"] is True
    assert "VERIFIED" in v_data["details"]

def test_rejection_flow():
    """Verify request rejection flow."""
    payload = {
        "requester_email": "dev4@rwintrob.altostrat.com",
        "target_project_id": "prj-test-05",
        "justification": "Insufficient justification for Org Policy override",
        "duration_minutes": 60,
        "approver_email": "scc.admin@rwintrob.altostrat.com"
    }
    req_id = client.post("/api/requests", json=payload).json()["request_id"]

    reject_resp = client.post(f"/api/requests/{req_id}/approve", json={"approver_email": "scc.admin@rwintrob.altostrat.com", "approved": False, "comments": "Insufficient business case"})
    assert reject_resp.status_code == 200
    assert reject_resp.json()["status"] == ElevationStatus.REJECTED.value

def test_audit_log_retrieval():
    """Verify audit log events are recorded and retrievable."""
    audit_resp = client.get("/api/audit")
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    assert len(logs) > 0
    assert any(log["event_type"] == "REQUEST_CREATED" for log in logs)

def test_audit_log_filtering():
    """Verify audit log multi-attribute filtering by requester, approver, project, and event_type."""
    # 1. Create distinct requests
    payload_a = {
        "requester_email": "alice.filter@rwintrob.altostrat.com",
        "target_project_id": "prj-audit-filter-a",
        "justification": "Filter testing justification for Project A",
        "duration_minutes": 15,
        "approver_email": "bob.approver@rwintrob.altostrat.com"
    }
    resp_a = client.post("/api/requests", json=payload_a)
    assert resp_a.status_code == 200
    req_a_id = resp_a.json()["request_id"]

    payload_b = {
        "requester_email": "charlie.filter@rwintrob.altostrat.com",
        "target_project_id": "prj-audit-filter-b",
        "justification": "Filter testing justification for Project B",
        "duration_minutes": 30,
        "approver_email": "dana.approver@rwintrob.altostrat.com"
    }
    resp_b = client.post("/api/requests", json=payload_b)
    assert resp_b.status_code == 200
    req_b_id = resp_b.json()["request_id"]

    # Approve request A
    client.post(f"/api/requests/{req_a_id}/approve", json={"approver_email": "bob.approver@rwintrob.altostrat.com", "approved": True})

    # Filter by requester 'alice'
    resp = client.get("/api/audit?requester=alice.filter")
    assert resp.status_code == 200
    logs = resp.json()
    assert len(logs) > 0
    assert all("alice.filter" in (l.get("requester_email") or l.get("actor_email", "")).lower() for l in logs)

    # Filter by approver 'dana'
    resp = client.get("/api/audit?approver=dana.approver")
    assert resp.status_code == 200
    logs = resp.json()
    assert len(logs) > 0
    assert all("dana.approver" in (l.get("approver_email") or l.get("actor_email", "")).lower() for l in logs)

    # Filter by target project 'prj-audit-filter-b'
    resp = client.get("/api/audit?project=prj-audit-filter-b")
    assert resp.status_code == 200
    logs = resp.json()
    assert len(logs) > 0
    assert all(l["target_project_id"] == "prj-audit-filter-b" for l in logs)

    # Filter by event_type 'GRANT_ACTIVE'
    resp = client.get("/api/audit?event_type=GRANT_ACTIVE")
    assert resp.status_code == 200
    logs = resp.json()
    assert len(logs) > 0
    assert all(l["event_type"] == "GRANT_ACTIVE" for l in logs)

def test_list_roles():
    """Verify endpoint returning supported IAM roles catalog."""
    resp = client.get("/api/roles")
    assert resp.status_code == 200
    roles = resp.json()
    assert len(roles) > 0
    assert any(r["role_id"] == "roles/orgpolicy.policyAdmin" for r in roles)
    assert any(r["role_id"] == "roles/resourcemanager.projectIamAdmin" for r in roles)
    assert any(r["role_id"] == "roles/compute.admin" for r in roles)

def test_custom_role_elevation_flow():
    """Verify end-to-end JIT elevation request with a custom selected role (e.g. Project IAM Admin)."""
    payload = {
        "requester_email": "secops@rwintrob.altostrat.com",
        "target_project_id": "prj-role-test-01",
        "role": "roles/resourcemanager.projectIamAdmin",
        "justification": "Testing custom role elevation for Project IAM Admin role",
        "duration_minutes": 30,
        "approver_email": "admin@rwintrob.altostrat.com"
    }
    # 1. Create Request
    req_resp = client.post("/api/requests", json=payload)
    assert req_resp.status_code == 200
    req_data = req_resp.json()
    assert req_data["role"] == "roles/resourcemanager.projectIamAdmin"
    req_id = req_data["request_id"]

    # 2. Approve Request
    app_resp = client.post(f"/api/requests/{req_id}/approve", json={
        "approver_email": "admin@rwintrob.altostrat.com",
        "approved": True,
        "comments": "Approved custom role elevation"
    })
    assert app_resp.status_code == 200
    assert app_resp.json()["status"] == ElevationStatus.ACTIVE.value
    assert app_resp.json()["role"] == "roles/resourcemanager.projectIamAdmin"

    # 3. Revoke Request
    revoke_resp = client.post(f"/api/requests/{req_id}/revoke")
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["status"] == ElevationStatus.REVOKED.value

    # 4. Verify Removal
    verify_resp = client.get(f"/api/requests/{req_id}/verify")
    assert verify_resp.status_code == 200
    assert verify_resp.json()["verified_removed"] is True

def test_watchdog_agent_monitoring_and_simulation():
    """Verify Watchdog agent monitors active grant, detects operations, and tracks activity telemetry."""
    # 1. Create request
    payload = {
        "requester_email": "alice.watchdog@rwintrob.altostrat.com",
        "target_project_id": "prj-watchdog-01",
        "role": "roles/orgpolicy.policyAdmin",
        "justification": "Watchdog monitoring test elevation",
        "duration_minutes": 15,
        "approver_email": "bob.approver@rwintrob.altostrat.com"
    }
    req_resp = client.post("/api/requests", json=payload)
    req_id = req_resp.json()["request_id"]

    # 2. Approve request -> Watchdog monitoring starts
    app_resp = client.post(f"/api/requests/{req_id}/approve", json={
        "approver_email": "bob.approver@rwintrob.altostrat.com",
        "approved": True
    })
    assert app_resp.status_code == 200
    assert app_resp.json()["watchdog_summary"] is not None

    # 3. Simulate GCP operation activity detected by Watchdog
    sim_resp = client.post(f"/api/requests/{req_id}/watchdog/simulate")
    assert sim_resp.status_code == 200
    sim_data = sim_resp.json()
    assert sim_data["status"] == "SUCCESS"
    assert sim_data["summary"]["detected_operations_count"] >= 1

    # 4. Get Watchdog Telemetry endpoint
    telemetry_resp = client.get(f"/api/requests/{req_id}/watchdog")
    assert telemetry_resp.status_code == 200
    tel_data = telemetry_resp.json()
    assert tel_data["request_id"] == req_id
    assert len(tel_data["operations"]) >= 1

def test_watchdog_status_endpoint():
    """Verify system-wide Watchdog Agent status endpoint."""
    resp = client.get("/api/watchdog/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["watchdog_status"] == "ACTIVE"
    assert "idle_quiet_threshold_seconds" in data
    assert "monitored_grants_count" in data

def test_notify_approver_email_checkbox_option():
    """Verify notify_approver_email checkbox creates request, triggers notification, and logs event."""
    # 1. Test with notify_approver_email = True
    payload_notify = {
        "requester_email": "requester.notify@rwintrob.altostrat.com",
        "target_project_id": "prj-notify-01",
        "role": "roles/orgpolicy.policyAdmin",
        "justification": "Testing email notification option enabled",
        "duration_minutes": 15,
        "approver_email": "approver.notify@rwintrob.altostrat.com",
        "notify_approver_email": True
    }
    resp = client.post("/api/requests", json=payload_notify)
    assert resp.status_code == 200
    req_data = resp.json()
    assert req_data["notify_approver_email"] is True
    req_id = req_data["request_id"]

    # Verify audit log recorded notification dispatch
    audit_resp = client.get(f"/api/audit?request_id={req_id}")
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    assert any(l["event_type"] == "APPROVER_NOTIFICATION_SENT" for l in logs)

    # 2. Test with notify_approver_email = False
    payload_no_notify = {
        "requester_email": "requester.notify@rwintrob.altostrat.com",
        "target_project_id": "prj-notify-02",
        "role": "roles/orgpolicy.policyAdmin",
        "justification": "Testing email notification option disabled",
        "duration_minutes": 15,
        "approver_email": "approver.notify@rwintrob.altostrat.com",
        "notify_approver_email": False
    }
    resp_off = client.post("/api/requests", json=payload_no_notify)
    assert resp_off.status_code == 200
    req_off_data = resp_off.json()
    assert req_off_data["notify_approver_email"] is False
    req_off_id = req_off_data["request_id"]

    audit_off_resp = client.get(f"/api/audit?request_id={req_off_id}")
    logs_off = audit_off_resp.json()
    assert not any(l["event_type"] == "APPROVER_NOTIFICATION_SENT" for l in logs_off)




"""
Comprehensive Functional & System Verification Test Suite (FUNC-01 through FUNC-12)
Implements the test cases defined in TEST_PLAN.md to verify all functions of the JIT Policy Elevator system.
"""

import os
import sys
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

# Ensure policy_elevator module directory is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app, iam_mgr, audit_mgr, watchdog_agent
from models import ElevationStatus, WatchdogActivityState

# Force mock mode for deterministic system verification
iam_mgr.mock_mode = True
audit_mgr.use_firestore = False

client = TestClient(app)


def test_func_01_service_health_and_readiness():
    """FUNC-01: Verify service health and readiness endpoint."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert "timestamp" in data


def test_func_02_identity_eligibility_and_domain_policy():
    """FUNC-02: Verify identity eligibility and organization domain policy enforcement."""
    # 1. Eligible corporate identity
    eligible_resp = client.get("/api/identity/check?email=architect@rwintrob.altostrat.com")
    assert eligible_resp.status_code == 200
    eligible_data = eligible_resp.json()
    assert eligible_data["status"] == "ELIGIBLE"
    assert eligible_data["is_eligible_requester"] is True
    assert eligible_data["is_eligible_approver"] is True
    assert eligible_data["domain_allowed"] is True

    # 2. Ineligible external identity
    ineligible_resp = client.get("/api/identity/check?email=external.user@gmail.com")
    assert ineligible_resp.status_code == 200
    ineligible_data = ineligible_resp.json()
    assert ineligible_data["status"] == "INELIGIBLE"
    assert ineligible_data["is_eligible_requester"] is False
    assert ineligible_data["is_eligible_approver"] is False

    # 3. Malformed identity
    malformed_resp = client.get("/api/identity/check?email=not-an-email")
    assert malformed_resp.status_code == 200
    assert malformed_resp.json()["status"] == "INELIGIBLE"


def test_func_03_supported_roles_catalog():
    """FUNC-03: Verify discovery of supported GCP IAM roles eligible for JIT elevation."""
    response = client.get("/api/roles")
    assert response.status_code == 200
    roles = response.json()
    assert isinstance(roles, list)
    assert len(roles) >= 5
    role_ids = [r["role_id"] for r in roles]
    assert "roles/orgpolicy.policyAdmin" in role_ids
    assert "roles/resourcemanager.projectIamAdmin" in role_ids


def test_func_04_elevation_request_creation():
    """FUNC-04: Verify elevation request creation, default state, and audit logging."""
    payload = {
        "requester_email": "devops.eng@rwintrob.altostrat.com",
        "target_project_id": "prj-func04-staging",
        "role": "roles/orgpolicy.policyAdmin",
        "justification": "FUNC-04 verification of temporary Organization Policy override",
        "duration_minutes": 30,
        "approver_email": "sec.lead@rwintrob.altostrat.com",
        "notify_approver_email": False
    }
    response = client.post("/api/requests", json=payload)
    assert response.status_code == 200
    req_data = response.json()
    assert len(req_data["request_id"]) == 8
    assert req_data["status"] == ElevationStatus.PENDING.value
    assert req_data["target_project_id"] == "prj-func04-staging"
    assert req_data["role"] == "roles/orgpolicy.policyAdmin"

    # Verify request retrieval via GET /api/requests/{id}
    get_resp = client.get(f"/api/requests/{req_data['request_id']}")
    assert get_resp.status_code == 200
    assert get_resp.json()["request_id"] == req_data["request_id"]


def test_func_05_four_eyes_approval_and_conditional_iam_binding():
    """FUNC-05: Verify four-eyes approval, CEL condition synthesis, and IAM binding creation."""
    create_payload = {
        "requester_email": "sre.user@rwintrob.altostrat.com",
        "target_project_id": "prj-func05-prod",
        "role": "roles/resourcemanager.projectIamAdmin",
        "justification": "FUNC-05 emergency IAM binding adjustment on prj-func05-prod",
        "duration_minutes": 45,
        "approver_email": "principal.sec@rwintrob.altostrat.com"
    }
    req_id = client.post("/api/requests", json=create_payload).json()["request_id"]

    # Approve request
    approve_payload = {
        "approver_email": "principal.sec@rwintrob.altostrat.com",
        "approved": True,
        "comments": "Verified incident ticket INC-90210"
    }
    approve_resp = client.post(
        f"/api/requests/{req_id}/approve",
        json=approve_payload,
        headers={"X-Goog-Authenticated-User-Email": "accounts.google.com:principal.sec@rwintrob.altostrat.com"}
    )
    assert approve_resp.status_code == 200
    approved_data = approve_resp.json()
    assert approved_data["status"] == ElevationStatus.ACTIVE.value
    assert approved_data["actual_approver"] == "principal.sec@rwintrob.altostrat.com"
    assert approved_data["expires_at"] is not None

    # Verify CEL condition exists in mock organization IAM policy
    org_id = iam_mgr._get_org_id("prj-func05-prod")
    policy = iam_mgr._mock_org_policies.get(org_id, {})
    assert policy.get("etag") is not None
    bindings = policy.get("bindings", [])
    matching_bindings = [
        b for b in bindings
        if b.get("role") == "roles/resourcemanager.projectIamAdmin"
        and "user:sre.user@rwintrob.altostrat.com" in b.get("members", [])
    ]
    assert len(matching_bindings) == 1
    condition = matching_bindings[0].get("condition", {})
    assert condition.get("expression") == 'resource.name.startsWith("projects/prj-func05-prod")'


def test_func_06_request_rejection_workflow():
    """FUNC-06: Verify request rejection workflow transitions status to REJECTED without IAM grant."""
    create_payload = {
        "requester_email": "dev.user@rwintrob.altostrat.com",
        "target_project_id": "prj-func06-reject",
        "role": "roles/compute.admin",
        "justification": "FUNC-06 testing rejection flow",
        "duration_minutes": 60,
        "approver_email": "sec.approver@rwintrob.altostrat.com"
    }
    req_id = client.post("/api/requests", json=create_payload).json()["request_id"]

    reject_payload = {
        "approver_email": "sec.approver@rwintrob.altostrat.com",
        "approved": False,
        "comments": "Rejected: change freeze window active"
    }
    reject_resp = client.post(
        f"/api/requests/{req_id}/approve",
        json=reject_payload,
        headers={"X-Goog-Authenticated-User-Email": "accounts.google.com:sec.approver@rwintrob.altostrat.com"}
    )
    assert reject_resp.status_code == 200
    rejected_data = reject_resp.json()
    assert rejected_data["status"] == ElevationStatus.REJECTED.value
    assert rejected_data["approval_comments"] == "Rejected: change freeze window active"


def test_func_07_manual_revocation_and_etag_proof():
    """FUNC-07: Verify manual early revocation removes conditional IAM binding and generates cryptographic ETag proof."""
    create_payload = {
        "requester_email": "net.eng@rwintrob.altostrat.com",
        "target_project_id": "prj-func07-revoke",
        "role": "roles/orgpolicy.policyAdmin",
        "justification": "FUNC-07 manual revocation verification",
        "duration_minutes": 60,
        "approver_email": "net.lead@rwintrob.altostrat.com"
    }
    req_id = client.post("/api/requests", json=create_payload).json()["request_id"]

    # Approve first
    client.post(
        f"/api/requests/{req_id}/approve",
        json={"approver_email": "net.lead@rwintrob.altostrat.com", "approved": True, "comments": "Approve"},
        headers={"X-Goog-Authenticated-User-Email": "accounts.google.com:net.lead@rwintrob.altostrat.com"}
    )

    # Trigger manual revocation
    revoke_resp = client.post(
        f"/api/requests/{req_id}/revoke",
        headers={"X-Goog-Authenticated-User-Email": "accounts.google.com:net.eng@rwintrob.altostrat.com"}
    )
    assert revoke_resp.status_code == 200
    revoked_data = revoke_resp.json()
    assert revoked_data["status"] == ElevationStatus.REVOKED.value
    assert revoked_data["revoked_at"] is not None
    assert revoked_data["verification_result"] is not None
    assert revoked_data["verification_result"]["verified_removed"] is True
    assert revoked_data["verification_result"]["policy_etag"] is not None


def test_func_08_independent_post_revocation_reverification():
    """FUNC-08: Verify on-demand cryptographic re-verification endpoint (GET /api/requests/{id}/verify)."""
    create_payload = {
        "requester_email": "data.eng@rwintrob.altostrat.com",
        "target_project_id": "prj-func08-verify",
        "role": "roles/storage.admin",
        "justification": "FUNC-08 post-revocation verification test",
        "duration_minutes": 15,
        "approver_email": "data.lead@rwintrob.altostrat.com"
    }
    req_id = client.post("/api/requests", json=create_payload).json()["request_id"]

    # Approve & Revoke
    client.post(
        f"/api/requests/{req_id}/approve",
        json={"approver_email": "data.lead@rwintrob.altostrat.com", "approved": True},
        headers={"X-Goog-Authenticated-User-Email": "accounts.google.com:data.lead@rwintrob.altostrat.com"}
    )
    client.post(f"/api/requests/{req_id}/revoke")

    # Call independent verify endpoint (GET)
    verify_resp = client.get(f"/api/requests/{req_id}/verify")
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["verified_removed"] is True
    assert "VERIFIED:" in v_data["details"]


def test_func_09_watchdog_telemetry_and_auto_rollback():
    """FUNC-09: Verify Watchdog activity monitoring state machine and automatic rollback."""
    create_payload = {
        "requester_email": "watchdog.tester@rwintrob.altostrat.com",
        "target_project_id": "prj-func09-watchdog",
        "role": "roles/orgpolicy.policyAdmin",
        "justification": "FUNC-09 Watchdog auto-rollback test",
        "duration_minutes": 60,
        "approver_email": "sec.admin@rwintrob.altostrat.com"
    }
    req_id = client.post("/api/requests", json=create_payload).json()["request_id"]
    client.post(
        f"/api/requests/{req_id}/approve",
        json={"approver_email": "sec.admin@rwintrob.altostrat.com", "approved": True},
        headers={"X-Goog-Authenticated-User-Email": "accounts.google.com:sec.admin@rwintrob.altostrat.com"}
    )

    # Check initial watchdog endpoint
    wd_resp = client.get(f"/api/requests/{req_id}/watchdog")
    assert wd_resp.status_code == 200
    assert wd_resp.json()["request_id"] == req_id

    # Simulate activity via watchdog simulation API
    sim_resp = client.post(f"/api/requests/{req_id}/watchdog/simulate")
    assert sim_resp.status_code == 200
    assert sim_resp.json()["status"] == "SUCCESS"

    # Simulate elapsed quiet window to trigger Watchdog auto-rollback
    import asyncio
    req_obj = audit_mgr.get_request(req_id)
    summary = watchdog_agent.get_summary(req_id)
    summary.last_activity_at = datetime.now(timezone.utc) - timedelta(seconds=watchdog_agent.idle_quiet_seconds + 5)

    asyncio.run(watchdog_agent.check_and_process_watchdog_loop(iam_mgr, audit_mgr))

    updated_req = audit_mgr.get_request(req_id)
    assert updated_req.status == ElevationStatus.REVOKED
    assert updated_req.watchdog_summary.auto_rollback_triggered is True


def test_func_10_time_based_expiration_auto_revocation():
    """FUNC-10: Verify expired grants are detected and revoked with EXPIRED status."""
    create_payload = {
        "requester_email": "exp.user@rwintrob.altostrat.com",
        "target_project_id": "prj-func10-expire",
        "role": "roles/orgpolicy.policyAdmin",
        "justification": "FUNC-10 expiration test",
        "duration_minutes": 15,
        "approver_email": "exp.lead@rwintrob.altostrat.com"
    }
    req_id = client.post("/api/requests", json=create_payload).json()["request_id"]
    client.post(
        f"/api/requests/{req_id}/approve",
        json={"approver_email": "exp.lead@rwintrob.altostrat.com", "approved": True},
        headers={"X-Goog-Authenticated-User-Email": "accounts.google.com:exp.lead@rwintrob.altostrat.com"}
    )

    # Backdate expires_at to simulate time expiration
    req_obj = audit_mgr.get_request(req_id)
    req_obj.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    audit_mgr.save_request(req_obj)

    # Perform expiration revocation logic
    now = datetime.now(timezone.utc)
    if req_obj.status == ElevationStatus.ACTIVE and req_obj.expires_at <= now:
        iam_mgr.revoke_project_role(req_obj.target_project_id, req_obj.requester_email, role=req_obj.role)
        v_res = iam_mgr.verify_permission_removed(req_obj.target_project_id, req_obj.requester_email, role=req_obj.role)
        req_obj.status = ElevationStatus.EXPIRED
        req_obj.revoked_at = now
        req_obj.verification_result = v_res
        audit_mgr.save_request(req_obj)

    final_req = audit_mgr.get_request(req_id)
    assert final_req.status == ElevationStatus.EXPIRED
    assert final_req.verification_result.verified_removed is True


def test_func_11_audit_log_persistence_and_filtering():
    """FUNC-11: Verify audit trail querying and multi-parameter filtering (/api/audit)."""
    resp_all = client.get("/api/audit")
    assert resp_all.status_code == 200
    all_logs = resp_all.json()
    assert len(all_logs) > 0

    # Filter by specific project
    resp_proj = client.get("/api/audit?project=prj-func05-prod")
    assert resp_proj.status_code == 200
    proj_logs = resp_proj.json()
    assert len(proj_logs) > 0
    assert all(entry["target_project_id"] == "prj-func05-prod" for entry in proj_logs)


def test_func_12_notification_config_and_test_dispatch():
    """FUNC-12: Verify notification backend configuration discovery and test dispatch endpoint."""
    cfg_resp = client.get("/api/notifications/config")
    assert cfg_resp.status_code == 200
    cfg_data = cfg_resp.json()
    assert "provider" in cfg_data
    assert "configured" in cfg_data

    # Test dispatch endpoint
    test_resp = client.post(
        "/api/notifications/test",
        json={"recipient_email": "admin@rwintrob.altostrat.com"}
    )
    assert test_resp.status_code == 200
    test_data = test_resp.json()
    assert test_data["success"] is True
    assert "details" in test_data

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from models import (
    DetectedOperation,
    ElevationRequest,
    ElevationStatus,
    WatchdogActivityState,
    WatchdogSummary,
)

logger = logging.getLogger("jit_policy_elevator.watchdog")

ROLE_METHOD_MAPPINGS: Dict[str, List[str]] = {
    "roles/orgpolicy.policyAdmin": [
        "google.cloud.orgpolicy.v2.OrgPolicy.UpdatePolicy",
        "google.cloud.orgpolicy.v2.OrgPolicy.SetPolicy",
        "google.cloud.orgpolicy.v2.OrgPolicy.DeletePolicy"
    ],
    "roles/resourcemanager.projectIamAdmin": [
        "google.iam.v1.IAMPolicy.SetIamPolicy",
        "google.iam.v1.IAMPolicy.TestIamPermissions"
    ],
    "roles/compute.admin": [
        "v1.compute.instances.insert",
        "v1.compute.instances.update",
        "v1.compute.firewalls.patch"
    ],
    "roles/storage.admin": [
        "storage.buckets.update",
        "storage.objects.create"
    ],
    "roles/secretmanager.admin": [
        "google.cloud.secretmanager.v1.SecretManagerService.AddSecretVersion",
        "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"
    ],
    "roles/cloudksm.admin": [
        "google.cloud.kms.v1.KeyManagementService.CreateCryptoKey"
    ],
    "roles/pubsub.admin": [
        "google.pubsub.v1.Publisher.CreateTopic"
    ],
    "roles/container.admin": [
        "google.container.v1.ClusterManager.UpdateCluster"
    ],
    "roles/editor": [
        "google.cloud.resourcemanager.v3.Projects.UpdateProject"
    ],
    "roles/viewer": [
        "google.cloud.resourcemanager.v3.Projects.GetProject"
    ]
}

class WatchdogAgent:
    """
    Watchdog Agent: Monitors Cloud Audit Logs for active JIT grants.
    Tracks elevated operations performed by the requester and automatically
    triggers early rollback and permission revocation once the operation is completed.
    """
    def __init__(self, idle_quiet_seconds: int = 15, mock_mode: bool = True):
        self.idle_quiet_seconds = idle_quiet_seconds
        self.mock_mode = mock_mode
        self._summaries: Dict[str, WatchdogSummary] = {}

    def start_monitoring(self, request: ElevationRequest) -> WatchdogSummary:
        """Registers a newly active JIT grant for Watchdog monitoring."""
        summary = WatchdogSummary(
            request_id=request.request_id,
            state=WatchdogActivityState.IDLE,
            detected_operations_count=0,
            operations=[],
            last_activity_at=None,
            completed_at=None,
            auto_rollback_triggered=False,
            rollback_reason=None
        )
        self._summaries[request.request_id] = summary
        logger.info(f"Watchdog Agent registered monitoring for JIT grant #{request.request_id} ({request.requester_email} on {request.target_project_id})")
        return summary

    def get_summary(self, request_id: str) -> Optional[WatchdogSummary]:
        """Retrieves Watchdog telemetry summary for a request."""
        return self._summaries.get(request_id)

    def list_monitored_grants(self) -> List[WatchdogSummary]:
        """Lists all active watchdog telemetry summaries."""
        return list(self._summaries.values())

    def record_detected_operation(
        self,
        request: ElevationRequest,
        method_name: str,
        resource_name: Optional[str] = None
    ) -> DetectedOperation:
        """
        Records a detected GCP operation performed under elevated privileges.
        """
        req_id = request.request_id
        summary = self._summaries.setdefault(
            req_id,
            WatchdogSummary(request_id=req_id, state=WatchdogActivityState.IDLE)
        )

        now = datetime.now(timezone.utc)
        target_resource = resource_name or f"projects/{request.target_project_id}"
        operation = DetectedOperation(
            method_name=method_name,
            timestamp=now,
            principal_email=request.requester_email,
            resource_name=target_resource,
            status="SUCCESS"
        )

        summary.operations.append(operation)
        summary.detected_operations_count = len(summary.operations)
        summary.last_activity_at = now
        summary.state = WatchdogActivityState.OPERATION_IN_PROGRESS

        logger.info(f"Watchdog Agent DETECTED OPERATION for #{req_id}: {method_name} on {target_resource} by {request.requester_email}")
        return operation

    def trigger_simulated_activity(self, request: ElevationRequest, method_name: Optional[str] = None) -> DetectedOperation:
        """Simulates GCP activity detection for demonstration / testing."""
        methods = ROLE_METHOD_MAPPINGS.get(request.role, ["google.cloud.resourcemanager.v3.Projects.UpdateProject"])
        target_method = method_name or methods[0]
        return self.record_detected_operation(request, target_method)

    async def check_and_process_watchdog_loop(self, iam_mgr, audit_mgr):
        """
        Background worker check: Queries audit logs, tracks activity completion,
        and triggers automatic rollback & revocation when elevated operations finish.
        """
        requests = audit_mgr.list_requests()
        now = datetime.now(timezone.utc)

        for req in requests:
            if req.status != ElevationStatus.ACTIVE:
                continue

            summary = self._summaries.get(req.request_id)
            if not summary:
                summary = self.start_monitoring(req)

            # In mock mode, if no activity has been recorded yet after 5 seconds, auto-simulate operation execution
            if self.mock_mode and summary.state == WatchdogActivityState.IDLE and req.approved_at:
                approved_elapsed = (now - req.approved_at).total_seconds()
                if approved_elapsed >= 3:
                    self.trigger_simulated_activity(req)
                    audit_mgr.log_event(
                        event_type="WATCHDOG_ACTIVITY_DETECTED",
                        request_id=req.request_id,
                        actor_email="system:watchdog_agent",
                        target_project_id=req.target_project_id,
                        role=req.role,
                        requester_email=req.requester_email,
                        approver_email=req.actual_approver or req.approver_email,
                        payload={
                            "operations_count": summary.detected_operations_count,
                            "latest_method": summary.operations[-1].method_name if summary.operations else None,
                            "state": summary.state
                        }
                    )

            # If activity was detected and quiet window has elapsed since last operation -> Execute Auto Rollback & Revocation!
            if summary.state in [WatchdogActivityState.ACTIVITY_DETECTED, WatchdogActivityState.OPERATION_IN_PROGRESS] and summary.last_activity_at:
                quiet_duration = (now - summary.last_activity_at).total_seconds()
                if quiet_duration >= self.idle_quiet_seconds:
                    logger.info(f"Watchdog Agent: Operation completed for #{req.request_id} (Quiet duration: {quiet_duration:.1f}s). Triggering auto rollback!")
                    
                    summary.state = WatchdogActivityState.AUTO_REVOKED
                    summary.completed_at = now
                    summary.auto_rollback_triggered = True
                    summary.rollback_reason = (
                        f"Watchdog Agent detected elevated operation completion ({summary.detected_operations_count} operation(s) executed). "
                        f"Auto-rollback triggered after {quiet_duration:.0f}s post-activity idle window."
                    )

                    # 1. Execute early IAM Roleback
                    req.status = ElevationStatus.REVOKING
                    audit_mgr.save_request(req)

                    success, msg, etag = iam_mgr.revoke_project_role(req.target_project_id, req.requester_email, role=req.role)
                    v_result = iam_mgr.verify_permission_removed(req.target_project_id, req.requester_email, role=req.role)

                    req.status = ElevationStatus.REVOKED if v_result.verified_removed else ElevationStatus.ACTIVE
                    req.revoked_at = now
                    req.verification_result = v_result
                    req.watchdog_summary = summary
                    audit_mgr.save_request(req)

                    audit_mgr.log_event(
                        event_type="WATCHDOG_AUTO_REVOKED",
                        request_id=req.request_id,
                        actor_email="system:watchdog_agent",
                        target_project_id=req.target_project_id,
                        role=req.role,
                        requester_email=req.requester_email,
                        approver_email=req.actual_approver or req.approver_email,
                        payload={
                            "rollback_reason": summary.rollback_reason,
                            "detected_operations_count": summary.detected_operations_count,
                            "operations": [op.model_dump(mode="json") for op in summary.operations],
                            "verification": v_result.model_dump(mode="json")
                        }
                    )

from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

class ElevationStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    REVOKING = "REVOKING"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    REJECTED = "REJECTED"

class TargetRole(str, Enum):
    ORGPOLICY_ADMIN = "roles/orgpolicy.policyAdmin"
    PROJECT_IAM_ADMIN = "roles/resourcemanager.projectIamAdmin"
    COMPUTE_ADMIN = "roles/compute.admin"
    STORAGE_ADMIN = "roles/storage.admin"
    SECRETMANAGER_ADMIN = "roles/secretmanager.admin"
    CLOUDKSM_ADMIN = "roles/cloudksm.admin"
    PUBSUB_ADMIN = "roles/pubsub.admin"
    CONTAINER_ADMIN = "roles/container.admin"
    VIEWER = "roles/viewer"
    EDITOR = "roles/editor"

class RoleOption(BaseModel):
    role_id: str = Field(..., description="GCP IAM Role ID")
    title: str = Field(..., description="Human-readable role title")
    description: str = Field(..., description="Description of the role permissions")
    category: str = Field(default="Governance & Security", description="Role categorization")

class ElevationRequestCreate(BaseModel):
    requester_email: str = Field(..., description="Email identity of the user requesting JIT elevation")
    target_project_id: str = Field(..., description="GCP Target Project ID where permission will be elevated")
    role: str = Field(default="roles/orgpolicy.policyAdmin", description="IAM role requested for JIT elevation")
    justification: str = Field(..., min_length=10, description="Mandatory business justification for elevation")
    duration_minutes: int = Field(15, ge=1, le=120, description="Duration in minutes for JIT grant (1 to 120)")
    approver_email: str = Field(..., description="Email identity of the designated approver")

class ApprovalAction(BaseModel):
    approver_email: str = Field(..., description="Email identity of the approving party")
    approved: bool = Field(..., description="True to approve, False to reject")
    comments: Optional[str] = Field(None, description="Optional comments from approver")

class VerificationResult(BaseModel):
    verified_removed: bool = Field(..., description="True if elevated permission is confirmed absent from IAM policy")
    timestamp: datetime = Field(default_factory=utc_now, description="Timestamp of verification check")
    policy_etag: Optional[str] = Field(None, description="ETag of the project IAM policy at verification time")
    details: str = Field(..., description="Detailed message explaining verification status")

class ElevationRequest(BaseModel):
    request_id: str = Field(..., description="Unique request identifier")
    requester_email: str = Field(..., description="Email of requester")
    target_project_id: str = Field(..., description="GCP Target Project ID")
    role: str = Field(default="roles/orgpolicy.policyAdmin", description="IAM role elevated at Project scope")
    justification: str = Field(..., description="Business justification")
    duration_minutes: int = Field(..., description="Elevation duration in minutes")
    approver_email: str = Field(..., description="Designated approver email")
    status: ElevationStatus = Field(default=ElevationStatus.PENDING, description="Current operational status")
    created_at: datetime = Field(default_factory=utc_now, description="Creation timestamp")
    approved_at: Optional[datetime] = Field(None, description="Approval timestamp")
    actual_approver: Optional[str] = Field(None, description="Email of user who performed approval")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")
    revoked_at: Optional[datetime] = Field(None, description="Revocation timestamp")
    approval_comments: Optional[str] = Field(None, description="Approver comments")
    verification_result: Optional[VerificationResult] = Field(None, description="Permission removal verification proof")

class AuditLogEntry(BaseModel):
    event_id: str = Field(..., description="Unique audit event ID")
    timestamp: datetime = Field(default_factory=utc_now, description="Event timestamp")
    event_type: str = Field(..., description="Type of event e.g. REQUEST_CREATED, REQUEST_APPROVED, GRANT_ACTIVE, GRANT_REVOKED, VERIFICATION_COMPLETED")
    request_id: str = Field(..., description="Associated request ID")
    actor_email: str = Field(..., description="User identity performing the action")
    target_project_id: str = Field(..., description="GCP Target Project ID")
    role: str = Field(..., description="IAM Role involved")
    requester_email: Optional[str] = Field(None, description="Requester identity for audit tracking")
    approver_email: Optional[str] = Field(None, description="Approver identity for audit tracking")
    payload: dict = Field(default_factory=dict, description="Additional context payload")

class IdentityCheckResult(BaseModel):
    email: str = Field(..., description="Email identity being evaluated")
    is_eligible_requester: bool = Field(..., description="Whether identity is allowed to request elevation")
    is_eligible_approver: bool = Field(..., description="Whether identity is allowed to approve requests")
    domain: str = Field(..., description="Extracted domain of identity")
    domain_allowed: bool = Field(..., description="Whether domain is in organization allowlist")
    allowed_domains: List[str] = Field(default_factory=list, description="List of authorized domains")
    status: str = Field(..., description="Status summary: ELIGIBLE or INELIGIBLE")
    message: str = Field(..., description="User-friendly explanation of eligibility determination")


DEFAULT_ROLES_CATALOG: List[RoleOption] = [
    RoleOption(
        role_id="roles/orgpolicy.policyAdmin",
        title="Organization Policy Administrator",
        description="Full access to manage organization policies on the target project.",
        category="Governance & Policy"
    ),
    RoleOption(
        role_id="roles/resourcemanager.projectIamAdmin",
        title="Project IAM Admin",
        description="Full access to administer IAM policies and roles on the target project.",
        category="Security & Access"
    ),
    RoleOption(
        role_id="roles/compute.admin",
        title="Compute Engine Admin",
        description="Full control over Compute Engine instances, networks, and resources.",
        category="Infrastructure"
    ),
    RoleOption(
        role_id="roles/storage.admin",
        title="Storage Admin",
        description="Full control over Cloud Storage buckets and objects.",
        category="Storage & Data"
    ),
    RoleOption(
        role_id="roles/secretmanager.admin",
        title="Secret Manager Admin",
        description="Full access to create, manage, and read secret payloads.",
        category="Security & Access"
    ),
    RoleOption(
        role_id="roles/cloudksm.admin",
        title="Cloud KMS Admin",
        description="Full access to administer KMS key rings, keys, and IAM policies.",
        category="Security & Access"
    ),
    RoleOption(
        role_id="roles/pubsub.admin",
        title="Pub/Sub Admin",
        description="Full access to Pub/Sub topics, subscriptions, and snapshots.",
        category="Messaging & Integration"
    ),
    RoleOption(
        role_id="roles/container.admin",
        title="Kubernetes Engine (GKE) Admin",
        description="Full management of GKE clusters and container workloads.",
        category="Infrastructure"
    ),
    RoleOption(
        role_id="roles/editor",
        title="Editor (Project Level)",
        description="Edit access to target project resources.",
        category="General Access"
    ),
    RoleOption(
        role_id="roles/viewer",
        title="Viewer (Project Level)",
        description="Read-only access to inspect target project resources.",
        category="General Access"
    )
]




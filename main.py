import os
import asyncio
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from models import (
    ApprovalAction,
    AuditLogEntry,
    DEFAULT_ROLES_CATALOG,
    ElevationRequest,
    ElevationRequestCreate,
    ElevationStatus,
    IdentityCheckResult,
    RoleOption,
    VerificationResult,
)
from iam_manager import IAMManager
from audit import AuditManager

BASE_DIR = Path(__file__).resolve().parent

# Initialize managers
iam_mgr = IAMManager()
audit_mgr = AuditManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start background auto-revocation worker
    task = asyncio.create_task(auto_revocation_loop())
    yield
    # Shutdown: Cancel background worker
    task.cancel()

app = FastAPI(
    title="JIT Org Policy Permission Elevator & Dashboard",
    description="Self-service portal for Just-In-Time elevation of roles/orgpolicy.policyAdmin restricted to target GCP projects.",
    version="1.0.0",
    lifespan=lifespan
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

def get_allowed_domains() -> List[str]:
    """Retrieves list of authorized organization domains for JIT portal operations."""
    raw = os.environ.get("ALLOWED_DOMAINS", "rwintrob.altostrat.com,altostrat.com")
    domains = [d.strip().lower() for d in raw.split(",") if d.strip()]
    return domains or ["rwintrob.altostrat.com", "altostrat.com"]

def validate_identity_eligibility(email: str, role_type: str = "requester") -> IdentityCheckResult:
    """
    Validates whether an identity email belongs to an authorized organization domain
    and is eligible to request or approve JIT elevation.
    """
    clean_email = (email or "").strip().lower()
    allowed_domains = get_allowed_domains()

    if not clean_email or "@" not in clean_email:
        return IdentityCheckResult(
            email=email or "",
            is_eligible_requester=False,
            is_eligible_approver=False,
            domain="",
            domain_allowed=False,
            allowed_domains=allowed_domains,
            status="INELIGIBLE",
            message="Invalid email address format. Email must include username and domain (e.g. user@rwintrob.altostrat.com)."
        )

    parts = clean_email.split("@")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return IdentityCheckResult(
            email=clean_email,
            is_eligible_requester=False,
            is_eligible_approver=False,
            domain="",
            domain_allowed=False,
            allowed_domains=allowed_domains,
            status="INELIGIBLE",
            message="Malformed email structure. Expected format: username@domain.com."
        )

    domain = parts[1]
    is_domain_allowed = ("*" in allowed_domains) or (domain in allowed_domains)

    if not is_domain_allowed:
        allowed_str = ", ".join([f"@{d}" for d in allowed_domains])
        role_label = "request elevation" if role_type == "requester" else "act as designated approver"
        return IdentityCheckResult(
            email=clean_email,
            is_eligible_requester=False,
            is_eligible_approver=False,
            domain=domain,
            domain_allowed=False,
            allowed_domains=allowed_domains,
            status="INELIGIBLE",
            message=f"Identity domain '@{domain}' is not authorized to {role_label}. Permitted organization domains: {allowed_str}."
        )

    return IdentityCheckResult(
        email=clean_email,
        is_eligible_requester=True,
        is_eligible_approver=True,
        domain=domain,
        domain_allowed=True,
        allowed_domains=allowed_domains,
        status="ELIGIBLE",
        message=f"Identity '{clean_email}' is verified and eligible under authorized organization domain '@{domain}'."
    )

def get_current_user_identity(request: Request) -> str:
    """
    Extracts authenticated user identity from GCP Identity-Aware Proxy (IAP) header,
    falling back to standard headers or configured active default user.
    """
    iap_email = request.headers.get("X-Goog-Authenticated-User-Email")
    if iap_email:
        # IAP headers often format as accounts.google.com:email@domain.com
        return iap_email.split(":")[-1]
    
    forwarded_user = request.headers.get("X-Forwarded-User")
    if forwarded_user:
        return forwarded_user

    user_header = request.headers.get("X-User-Email")
    if user_header and user_header != "null" and user_header != "undefined":
        return user_header

    return os.environ.get("GCP_DEFAULT_USER", "admin@rwintrob.altostrat.com")

async def auto_revocation_loop():
    """Background worker loop checking for expired active JIT grants every 10 seconds."""
    while True:
        try:
            now = datetime.now(timezone.utc)
            requests = audit_mgr.list_requests()
            for req in requests:
                if req.status == ElevationStatus.ACTIVE and req.expires_at and now >= req.expires_at:
                    logger_msg = f"Auto-revoking expired JIT grant {req.request_id} ({req.role}) for {req.requester_email} on project {req.target_project_id}"
                    print(logger_msg)
                    
                    req.status = ElevationStatus.REVOKING
                    audit_mgr.save_request(req)
                    
                    # Revoke permission
                    success, msg, etag = iam_mgr.revoke_project_role(req.target_project_id, req.requester_email, role=req.role)
                    
                    # Verify removal
                    v_result = iam_mgr.verify_permission_removed(req.target_project_id, req.requester_email, role=req.role)
                    
                    req.status = ElevationStatus.EXPIRED if v_result.verified_removed else ElevationStatus.ACTIVE
                    req.revoked_at = datetime.now(timezone.utc)
                    req.verification_result = v_result
                    audit_mgr.save_request(req)

                    audit_mgr.log_event(
                        event_type="GRANT_EXPIRED_REVOKED",
                        request_id=req.request_id,
                        actor_email="system:auto_revoker",
                        target_project_id=req.target_project_id,
                        role=req.role,
                        requester_email=req.requester_email,
                        approver_email=req.actual_approver or req.approver_email,
                        payload={"revocation_message": msg, "verification": v_result.model_dump(mode="json")}
                    )
        except Exception as e:
            print(f"Error in auto_revocation_loop: {e}")
        
        await asyncio.sleep(10)

# Dashboard Route
@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    user_email = get_current_user_identity(request)
    eligibility = validate_identity_eligibility(user_email)
    template = templates.get_template("index.html")
    content = template.render(
        request=request, 
        user_email=user_email,
        user_eligible=eligibility.is_eligible_requester,
        eligibility_status=eligibility.status,
        eligibility_msg=eligibility.message,
        allowed_domains=",".join(get_allowed_domains()),
        v=int(datetime.now(timezone.utc).timestamp())
    )
    return HTMLResponse(content=content)

# API Endpoints
@app.get("/api/health")
async def health_check():
    return {"status": "HEALTHY", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/api/roles", response_model=List[RoleOption])
async def list_supported_roles():
    """Retrieves list of supported IAM roles available for JIT elevation."""
    return DEFAULT_ROLES_CATALOG

@app.get("/api/identity/check", response_model=IdentityCheckResult)
async def check_identity(email: Optional[str] = None, request: Request = None):
    target_email = email if (email and email.strip()) else get_current_user_identity(request)
    return validate_identity_eligibility(target_email)

@app.post("/api/requests", response_model=ElevationRequest)
async def create_elevation_request(req_data: ElevationRequestCreate, request: Request):
    user_email = get_current_user_identity(request)
    
    # Enforce identity matching if provided by requester or set from header
    requester = (req_data.requester_email or user_email).strip()
    approver = req_data.approver_email.strip()
    requested_role = (req_data.role or "roles/orgpolicy.policyAdmin").strip()

    # 1. Validate Requester Eligibility
    req_check = validate_identity_eligibility(requester, role_type="requester")
    if not req_check.is_eligible_requester:
        raise HTTPException(
            status_code=403,
            detail=f"Requester Eligibility Denied: {req_check.message}"
        )

    # 2. Validate Designated Approver Eligibility
    appr_check = validate_identity_eligibility(approver, role_type="approver")
    if not appr_check.is_eligible_approver:
        raise HTTPException(
            status_code=400,
            detail=f"Designated Approver Eligibility Denied: {appr_check.message}"
        )

    # 3. Enforce Separation of Duties
    if requester.lower() == approver.lower():
        raise HTTPException(
            status_code=400,
            detail="Separation of Duties violation: Requester cannot designate themselves as their own approver."
        )

    new_req = ElevationRequest(
        request_id=str(uuid.uuid4())[:8],
        requester_email=requester,
        target_project_id=req_data.target_project_id.strip(),
        role=requested_role,
        justification=req_data.justification.strip(),
        duration_minutes=req_data.duration_minutes,
        approver_email=approver,
        status=ElevationStatus.PENDING,
        created_at=datetime.now(timezone.utc)
    )

    audit_mgr.save_request(new_req)
    audit_mgr.log_event(
        event_type="REQUEST_CREATED",
        request_id=new_req.request_id,
        actor_email=requester,
        target_project_id=new_req.target_project_id,
        role=new_req.role,
        requester_email=new_req.requester_email,
        approver_email=new_req.approver_email,
        payload={"justification": new_req.justification, "duration_minutes": new_req.duration_minutes, "approver_email": new_req.approver_email, "role": new_req.role}
    )

    return new_req

@app.get("/api/requests", response_model=List[ElevationRequest])
async def list_elevation_requests():
    return audit_mgr.list_requests()

@app.get("/api/requests/{request_id}", response_model=ElevationRequest)
async def get_elevation_request(request_id: str):
    req = audit_mgr.get_request(request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")
    return req

@app.post("/api/requests/{request_id}/approve", response_model=ElevationRequest)
async def process_approval(request_id: str, action: ApprovalAction, request: Request):
    user_email = get_current_user_identity(request)
    approver = (action.approver_email or user_email).strip()

    # Validate Approver Eligibility
    appr_check = validate_identity_eligibility(approver, role_type="approver")
    if not appr_check.is_eligible_approver:
        raise HTTPException(
            status_code=403,
            detail=f"Approver Eligibility Denied: {appr_check.message}"
        )

    req = audit_mgr.get_request(request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")

    if req.status != ElevationStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Cannot approve request in status {req.status}")

    # Enforce separation of duties: Approver cannot be the Requester
    if approver.lower() == req.requester_email.lower():
        raise HTTPException(status_code=403, detail="Separation of Duties violation: Requester cannot approve their own request.")

    if not action.approved:
        req.status = ElevationStatus.REJECTED
        req.actual_approver = approver
        req.approval_comments = action.comments
        audit_mgr.save_request(req)
        audit_mgr.log_event(
            event_type="REQUEST_REJECTED",
            request_id=req.request_id,
            actor_email=approver,
            target_project_id=req.target_project_id,
            role=req.role,
            requester_email=req.requester_email,
            approver_email=approver,
            payload={"comments": action.comments}
        )
        return req

    # Perform IAM elevation
    success, msg, etag = iam_mgr.grant_project_role(req.target_project_id, req.requester_email, role=req.role)
    if not success:
        raise HTTPException(status_code=500, detail=f"IAM Elevation Failed: {msg}")

    req.status = ElevationStatus.ACTIVE
    req.actual_approver = approver
    req.approved_at = datetime.now(timezone.utc)
    req.expires_at = datetime.now(timezone.utc) + timedelta(minutes=req.duration_minutes)
    req.approval_comments = action.comments
    audit_mgr.save_request(req)

    audit_mgr.log_event(
        event_type="GRANT_ACTIVE",
        request_id=req.request_id,
        actor_email=approver,
        target_project_id=req.target_project_id,
        role=req.role,
        requester_email=req.requester_email,
        approver_email=approver,
        payload={"expires_at": req.expires_at.isoformat(), "policy_etag": etag, "message": msg, "role": req.role}
    )

    return req

@app.post("/api/requests/{request_id}/revoke", response_model=ElevationRequest)
async def revoke_elevation_grant(request_id: str, request: Request):
    user_email = get_current_user_identity(request)
    req = audit_mgr.get_request(request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")

    if req.status not in [ElevationStatus.ACTIVE, ElevationStatus.PENDING]:
        raise HTTPException(status_code=400, detail=f"Cannot revoke grant in status {req.status}")

    req.status = ElevationStatus.REVOKING
    audit_mgr.save_request(req)

    # 1. Execute IAM Revocation
    success, msg, etag = iam_mgr.revoke_project_role(req.target_project_id, req.requester_email, role=req.role)
    
    # 2. Execute Verification Check
    v_result = iam_mgr.verify_permission_removed(req.target_project_id, req.requester_email, role=req.role)

    req.status = ElevationStatus.REVOKED if v_result.verified_removed else ElevationStatus.ACTIVE
    req.revoked_at = datetime.now(timezone.utc)
    req.verification_result = v_result
    audit_mgr.save_request(req)

    audit_mgr.log_event(
        event_type="GRANT_MANUALLY_REVOKED",
        request_id=req.request_id,
        actor_email=user_email,
        target_project_id=req.target_project_id,
        role=req.role,
        requester_email=req.requester_email,
        approver_email=req.actual_approver or req.approver_email,
        payload={"revocation_message": msg, "verification": v_result.model_dump(mode="json"), "role": req.role}
    )

    return req

@app.get("/api/requests/{request_id}/verify", response_model=VerificationResult)
async def verify_permission_removal(request_id: str):
    req = audit_mgr.get_request(request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")

    v_result = iam_mgr.verify_permission_removed(req.target_project_id, req.requester_email, role=req.role)
    req.verification_result = v_result
    audit_mgr.save_request(req)

    audit_mgr.log_event(
        event_type="VERIFICATION_COMPLETED",
        request_id=req.request_id,
        actor_email="system:verifier",
        target_project_id=req.target_project_id,
        role=req.role,
        requester_email=req.requester_email,
        approver_email=req.actual_approver or req.approver_email,
        payload=v_result.model_dump(mode="json")
    )

    return v_result

@app.get("/api/audit", response_model=List[AuditLogEntry])
async def get_audit_trail(
    request_id: Optional[str] = None,
    requester: Optional[str] = None,
    approver: Optional[str] = None,
    project: Optional[str] = None,
    event_type: Optional[str] = None
):
    return audit_mgr.get_audit_logs(
        request_id=request_id,
        requester=requester,
        approver=approver,
        project=project,
        event_type=event_type
    )


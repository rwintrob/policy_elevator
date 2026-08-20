import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from google.cloud import firestore
from models import AuditLogEntry, ElevationRequest

# Configure structured JSON logger for GCP Cloud Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("jit_policy_elevator")

def to_utc(dt: Optional[datetime]) -> datetime:
    """Safely converts any datetime (naive or aware) to UTC-aware datetime."""
    if dt is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

class AuditManager:
    """
    Manages JIT Elevation requests state, lifecycle transitions,
    and structured audit logging with multi-attribute filtering.
    """
    def __init__(self, use_firestore: bool = True):
        self.use_firestore = use_firestore
        self.db = None
        self._in_memory_requests: Dict[str, ElevationRequest] = {}
        self._in_memory_logs: List[AuditLogEntry] = []

        if self.use_firestore:
            try:
                import os
                project_id = os.environ.get("TARGET_PROJECT_ID", os.environ.get("GCP_PROJECT", "policy-elevator"))
                self.db = firestore.Client(project=project_id)
                logger.info(f"Connected to Google Cloud Firestore (project: {project_id}) for JIT Audit persistence.")
            except Exception as e:
                logger.warning(f"Could not initialize Firestore client, falling back to in-memory store: {e}")
                self.use_firestore = False

    def log_event(
        self,
        event_type: str,
        request_id: str,
        actor_email: str,
        target_project_id: str,
        role: str,
        requester_email: Optional[str] = None,
        approver_email: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None
    ) -> AuditLogEntry:
        """
        Records an immutable audit log entry into Cloud Logging and Firestore.
        """
        entry = AuditLogEntry(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            request_id=request_id,
            actor_email=actor_email,
            target_project_id=target_project_id,
            role=role,
            requester_email=requester_email,
            approver_email=approver_email,
            payload=payload or {}
        )

        # Structured JSON Cloud Logging output
        event_dict = entry.model_dump(mode="json")
        log_payload = {
            "severity": "INFO",
            "message": f"JIT_ELEVATOR_AUDIT: {event_type} for project {target_project_id} by {actor_email}",
            "audit_event": event_dict
        }
        logger.info(json.dumps(log_payload))

        # Store in Firestore if available
        if self.use_firestore and self.db:
            try:
                doc_ref = self.db.collection("jit_elevation_audit").document(entry.event_id)
                doc_ref.set(event_dict)
            except Exception as e:
                logger.error(f"Failed to persist audit log to Firestore: {e}")

        # Always append to in-memory store
        self._in_memory_logs.append(entry)
        return entry

    def save_request(self, request: ElevationRequest):
        """
        Persists request state to Firestore and in-memory cache.
        """
        self._in_memory_requests[request.request_id] = request
        if self.use_firestore and self.db:
            try:
                doc_ref = self.db.collection("jit_elevation_requests").document(request.request_id)
                data = request.model_dump(mode="json")
                doc_ref.set(data)
            except Exception as e:
                logger.error(f"Failed to save request to Firestore: {e}")

    def get_request(self, request_id: str) -> Optional[ElevationRequest]:
        """
        Fetches request state from Firestore or in-memory store.
        """
        if self.use_firestore and self.db:
            try:
                doc = self.db.collection("jit_elevation_requests").document(request_id).get()
                if doc.exists:
                    data = doc.to_dict()
                    return ElevationRequest(**data)
            except Exception as e:
                logger.error(f"Failed to read request from Firestore: {e}")

        return self._in_memory_requests.get(request_id)

    def list_requests(self) -> List[ElevationRequest]:
        """
        Lists all JIT elevation requests safely sorted by created_at.
        """
        if self.use_firestore and self.db:
            try:
                docs = self.db.collection("jit_elevation_requests").stream()
                requests = []
                for doc in docs:
                    requests.append(ElevationRequest(**doc.to_dict()))
                return sorted(requests, key=lambda r: to_utc(r.created_at), reverse=True)
            except Exception as e:
                logger.error(f"Failed to list requests from Firestore: {e}")

        return sorted(list(self._in_memory_requests.values()), key=lambda r: to_utc(r.created_at), reverse=True)

    def get_audit_logs(
        self,
        request_id: Optional[str] = None,
        requester: Optional[str] = None,
        approver: Optional[str] = None,
        project: Optional[str] = None,
        event_type: Optional[str] = None
    ) -> List[AuditLogEntry]:
        """
        Retrieves audit log entries with multi-attribute filtering (requester, approver, project, event_type).
        """
        raw_logs: List[AuditLogEntry] = []
        if self.use_firestore and self.db:
            try:
                docs = self.db.collection("jit_elevation_audit").stream()
                raw_logs = [AuditLogEntry(**d.to_dict()) for d in docs]
            except Exception as e:
                logger.error(f"Failed to fetch audit logs from Firestore: {e}")

        if not raw_logs:
            raw_logs = list(self._in_memory_logs)

        # Ensure requester_email and approver_email are resolved for each log entry
        resolved_logs: List[AuditLogEntry] = []
        for log in raw_logs:
            entry = log
            if not entry.requester_email or not entry.approver_email:
                req = self.get_request(entry.request_id)
                if req:
                    r_email = entry.requester_email or req.requester_email
                    a_email = entry.approver_email or req.approver_email or req.actual_approver
                    if r_email != entry.requester_email or a_email != entry.approver_email:
                        entry = entry.model_copy(update={
                            "requester_email": r_email,
                            "approver_email": a_email
                        })
                elif entry.payload:
                    r_email = entry.requester_email or entry.payload.get("requester_email") or (entry.actor_email if entry.event_type == "REQUEST_CREATED" else None)
                    a_email = entry.approver_email or entry.payload.get("approver_email") or (entry.actor_email if "APPROV" in entry.event_type or "REJECT" in entry.event_type else None)
                    if r_email != entry.requester_email or a_email != entry.approver_email:
                        entry = entry.model_copy(update={
                            "requester_email": r_email,
                            "approver_email": a_email
                        })
            resolved_logs.append(entry)

        # Apply in-memory multi-field filters
        filtered: List[AuditLogEntry] = []
        for log in resolved_logs:
            if request_id and log.request_id.lower() != request_id.lower():
                continue
            if project and project.lower() not in log.target_project_id.lower():
                continue
            if event_type and event_type.upper() != "ALL" and log.event_type.upper() != event_type.upper():
                continue
            if requester:
                req_val = (log.requester_email or (log.actor_email if log.event_type == "REQUEST_CREATED" else "")).lower()
                if requester.lower() not in req_val:
                    continue
            if approver:
                appr_val = (log.approver_email or (log.actor_email if "APPROV" in log.event_type or "REJECT" in log.event_type else "")).lower()
                if approver.lower() not in appr_val:
                    continue
            filtered.append(log)

        return sorted(filtered, key=lambda l: to_utc(l.timestamp), reverse=True)

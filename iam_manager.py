import os
import re
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from models import VerificationResult, GCP_PROJECT_ID_REGEX

logger = logging.getLogger("jit_policy_elevator")

TARGET_ROLE = "roles/orgpolicy.policyAdmin"

class IAMManager:
    """
    GCP IAM & Resource Manager Engine for JIT Org Policy Permission Elevation.
    Enforces strict least-privilege scoping of roles/orgpolicy.policyAdmin to the TARGET PROJECT ONLY
    using GCP IAM Conditions (resource.name.startsWith("projects/{target_project_id}")).
    Provides mock/simulation capabilities when GCP credentials are not present or for unit testing.
    """

    def __init__(self, mock_mode: bool = False, default_org_id: Optional[str] = None):
        self.mock_mode = mock_mode
        self.default_org_id = default_org_id or os.environ.get("GCP_ORGANIZATION_ID")
        self._resourcemanager = None
        self._mock_org_policies: Dict[str, dict] = {}

        if not self.mock_mode:
            try:
                from googleapiclient import discovery
                self._resourcemanager = discovery.build('cloudresourcemanager', 'v1', cache_discovery=False)
                logger.info("Successfully initialized GCP Resource Manager v1 client.")
            except Exception as e:
                logger.warning(f"Could not initialize GCP Resource Manager API client ({e}). Operating in simulation mode.")
                self.mock_mode = True

    def _normalize_member(self, member: str) -> str:
        """Ensures member has valid GCP IAM prefix e.g., user: or serviceAccount:"""
        if ":" in member:
            return member
        if member.endswith(".gserviceaccount.com"):
            return f"serviceAccount:{member}"
        return f"user:{member}"

    def _get_org_id(self, target_project_id: str) -> str:
        """Determines the parent organization ID for the target project."""
        if self.default_org_id:
            return self.default_org_id
        if self._resourcemanager:
            try:
                proj = self._resourcemanager.projects().get(projectId=target_project_id).execute()
                parent = proj.get("parent", {})
                if parent.get("type") == "organization":
                    return parent.get("id")
            except Exception as e:
                logger.warning(f"Could not fetch parent organization for project {target_project_id}: {e}")
        return os.environ.get("GCP_ORGANIZATION_ID", "mock-org-000000")

    def grant_project_role(self, target_project_id: str, member: str, role: str = TARGET_ROLE) -> Tuple[bool, str, Optional[str]]:
        """
        Binds the specified role with an IAM Condition restricting the scope strictly to target_project_id.
        Returns: (success: bool, message: str, policy_etag: Optional[str])
        """
        clean_project_id = (target_project_id or "").strip()
        if not GCP_PROJECT_ID_REGEX.match(clean_project_id):
            raise ValueError(f"Invalid GCP Project ID '{target_project_id}'. CEL condition synthesis aborted.")

        target_role = role or TARGET_ROLE
        normalized_member = self._normalize_member(member)
        role_slug = target_role.split("/")[-1]
        cond_title = f"JIT-Project-{clean_project_id}-{role_slug}"
        cond_expr = f'resource.name.startsWith("projects/{clean_project_id}")'
        logger.info(f"Initiating JIT IAM grant: Binding {target_role} for {normalized_member} scoped strictly to project {clean_project_id}")

        if self.mock_mode:
            org_id = self._get_org_id(clean_project_id)
            policy = self._mock_org_policies.setdefault(org_id, {"version": 3, "etag": "mock-etag-01", "bindings": []})
            bindings = policy.setdefault("bindings", [])
            
            target_binding = None
            for b in bindings:
                if b.get("role") == target_role and (b.get("condition", {}).get("title") == cond_title or b.get("condition", {}).get("title") == f"JIT-Project-{clean_project_id}"):
                    target_binding = b
                    break
            
            if not target_binding:
                target_binding = {
                    "role": target_role,
                    "members": [],
                    "condition": {
                        "title": cond_title,
                        "description": f"JIT {target_role} scoped strictly to project {target_project_id}",
                        "expression": cond_expr
                    }
                }
                bindings.append(target_binding)
            
            if normalized_member not in target_binding["members"]:
                target_binding["members"].append(normalized_member)
            
            policy["etag"] = f"mock-etag-{int(datetime.now(timezone.utc).timestamp())}"
            return True, f"Successfully bound {target_role} (scoped to {target_project_id}) to {normalized_member} (Simulated)", policy["etag"]

        try:
            org_id = self._get_org_id(target_project_id)
            org_resource = f"organizations/{org_id}"

            # 1. Fetch current Org IAM Policy (Version 3)
            policy = self._resourcemanager.organizations().getIamPolicy(
                resource=org_resource,
                body={"options": {"requestedPolicyVersion": 3}}
            ).execute()

            policy["version"] = 3
            bindings = policy.get("bindings", [])
            target_binding = None
            for b in bindings:
                if b.get("role") == target_role and (b.get("condition", {}).get("title") == cond_title or b.get("condition", {}).get("title") == f"JIT-Project-{target_project_id}"):
                    target_binding = b
                    break

            if not target_binding:
                target_binding = {
                    "role": target_role,
                    "members": [],
                    "condition": {
                        "title": cond_title,
                        "description": f"JIT {target_role} scoped strictly to project {target_project_id}",
                        "expression": cond_expr
                    }
                }
                bindings.append(target_binding)

            if normalized_member not in target_binding["members"]:
                target_binding["members"].append(normalized_member)

            policy["bindings"] = bindings

            # 2. Update Org IAM Policy with Conditional Binding
            updated_policy = self._resourcemanager.organizations().setIamPolicy(
                resource=org_resource,
                body={"policy": policy}
            ).execute()

            new_etag = updated_policy.get("etag", "")
            logger.info(f"Successfully bound {target_role} (conditional for {target_project_id}) to {normalized_member}. New ETag: {new_etag}")
            return True, f"Successfully elevated {normalized_member} to {target_role} strictly on project {target_project_id}", new_etag

        except Exception as e:
            err_msg = f"Failed to grant IAM permission for project {target_project_id}: {str(e)}"
            logger.error(err_msg)
            return False, err_msg, None

    def grant_project_orgpolicy_admin(self, target_project_id: str, member: str, role: str = TARGET_ROLE) -> Tuple[bool, str, Optional[str]]:
        """Backwards compatible alias for grant_project_role."""
        return self.grant_project_role(target_project_id, member, role)

    def revoke_project_role(self, target_project_id: str, member: str, role: str = TARGET_ROLE) -> Tuple[bool, str, Optional[str]]:
        """
        Removes specified role condition binding for member scoped to target_project_id.
        Returns: (success: bool, message: str, policy_etag: Optional[str])
        """
        target_role = role or TARGET_ROLE
        normalized_member = self._normalize_member(member)
        role_slug = target_role.split("/")[-1]
        cond_title = f"JIT-Project-{target_project_id}-{role_slug}"
        logger.info(f"Initiating JIT IAM revocation: Purging {target_role} for {normalized_member} on project {target_project_id}")

        if self.mock_mode:
            org_id = self._get_org_id(target_project_id)
            policy = self._mock_org_policies.setdefault(org_id, {"version": 3, "etag": "mock-etag-01", "bindings": []})
            bindings = policy.get("bindings", [])
            for b in bindings:
                if b.get("role") == target_role and (b.get("condition", {}).get("title") == cond_title or b.get("condition", {}).get("title") == f"JIT-Project-{target_project_id}"):
                    if normalized_member in b.get("members", []):
                        b["members"].remove(normalized_member)
            policy["bindings"] = [b for b in bindings if len(b.get("members", [])) > 0]
            policy["etag"] = f"mock-etag-{int(datetime.now(timezone.utc).timestamp())}"
            return True, f"Successfully revoked {target_role} from {normalized_member} for project {target_project_id} (Simulated)", policy["etag"]

        try:
            org_id = self._get_org_id(target_project_id)
            org_resource = f"organizations/{org_id}"

            # 1. Fetch current Org IAM Policy (Version 3)
            policy = self._resourcemanager.organizations().getIamPolicy(
                resource=org_resource,
                body={"options": {"requestedPolicyVersion": 3}}
            ).execute()

            policy["version"] = 3
            bindings = policy.get("bindings", [])
            modified = False
            for b in bindings:
                if b.get("role") == target_role and (b.get("condition", {}).get("title") == cond_title or b.get("condition", {}).get("title") == f"JIT-Project-{target_project_id}"):
                    if normalized_member in b.get("members", []):
                        b["members"].remove(normalized_member)
                        modified = True

            # Clean up empty conditional bindings
            policy["bindings"] = [b for b in bindings if len(b.get("members", [])) > 0]

            if not modified:
                return True, f"Member {normalized_member} was already not present in {target_role} for project {target_project_id}", policy.get("etag")

            # 2. Update Org IAM Policy
            updated_policy = self._resourcemanager.organizations().setIamPolicy(
                resource=org_resource,
                body={"policy": policy}
            ).execute()

            new_etag = updated_policy.get("etag", "")
            logger.info(f"Successfully purged {target_role} for {normalized_member} on project {target_project_id}. New ETag: {new_etag}")
            return True, f"Successfully purged {target_role} from {normalized_member} for project {target_project_id}", new_etag

        except Exception as e:
            err_msg = f"Failed to revoke IAM permission for project {target_project_id}: {str(e)}"
            logger.error(err_msg)
            return False, err_msg, None

    def revoke_project_orgpolicy_admin(self, target_project_id: str, member: str, role: str = TARGET_ROLE) -> Tuple[bool, str, Optional[str]]:
        """Backwards compatible alias for revoke_project_role."""
        return self.revoke_project_role(target_project_id, member, role)

    def _binding_grants_access_to_project(
        self,
        binding: dict,
        target_role: str,
        normalized_member: str,
        target_project_id: str,
        cond_title: str
    ) -> bool:
        """
        Checks whether a binding grants target_role to normalized_member on target_project_id,
        accounting for both unconditioned (global org-wide) bindings and conditional bindings.
        """
        if binding.get("role") != target_role:
            return False
        if normalized_member not in binding.get("members", []):
            return False
        condition = binding.get("condition")
        if not condition:
            # Unconditioned binding grants global access across all projects in the organization
            return True
        title = condition.get("title", "")
        expr = condition.get("expression", "")
        if title == cond_title or title == f"JIT-Project-{target_project_id}":
            return True
        if f"projects/{target_project_id}" in expr:
            return True
        return False

    def verify_permission_removed(self, target_project_id: str, member: str, role: str = TARGET_ROLE) -> VerificationResult:
        """
        Empirically verifies that specified role is completely absent for member on target_project_id,
        checking both project-scoped conditional bindings and unconditioned organization-wide bindings.
        Returns: VerificationResult
        """
        target_role = role or TARGET_ROLE
        normalized_member = self._normalize_member(member)
        role_slug = target_role.split("/")[-1]
        cond_title = f"JIT-Project-{target_project_id}-{role_slug}"
        logger.info(f"Executing permission removal verification check for {normalized_member} on project {target_project_id} (role: {target_role})")

        if self.mock_mode:
            org_id = self._get_org_id(target_project_id)
            policy = self._mock_org_policies.get(org_id, {"bindings": [], "etag": "mock-etag-01"})
            bindings = policy.get("bindings", [])
            is_present = False
            for b in bindings:
                if self._binding_grants_access_to_project(b, target_role, normalized_member, target_project_id, cond_title):
                    is_present = True
                    break

            now_utc = datetime.now(timezone.utc)
            if not is_present:
                return VerificationResult(
                    verified_removed=True,
                    timestamp=now_utc,
                    policy_etag=policy.get("etag"),
                    details=f"VERIFIED: {normalized_member} is confirmed absent from {target_role} scoped to project {target_project_id}."
                )
            else:
                return VerificationResult(
                    verified_removed=False,
                    timestamp=now_utc,
                    policy_etag=policy.get("etag"),
                    details=f"VERIFICATION FAILURE: {normalized_member} still possesses {target_role} binding (conditioned or unconditioned) for project {target_project_id}!"
                )

        try:
            org_id = self._get_org_id(target_project_id)
            org_resource = f"organizations/{org_id}"

            policy = self._resourcemanager.organizations().getIamPolicy(
                resource=org_resource,
                body={"options": {"requestedPolicyVersion": 3}}
            ).execute()

            bindings = policy.get("bindings", [])
            is_present = False
            for b in bindings:
                if self._binding_grants_access_to_project(b, target_role, normalized_member, target_project_id, cond_title):
                    is_present = True
                    break

            etag = policy.get("etag", "")
            now_utc = datetime.now(timezone.utc)
            if not is_present:
                return VerificationResult(
                    verified_removed=True,
                    timestamp=now_utc,
                    policy_etag=etag,
                    details=f"VERIFIED: {normalized_member} is confirmed absent from {target_role} on project {target_project_id} (Org Policy ETag: {etag})."
                )
            else:
                return VerificationResult(
                    verified_removed=False,
                    timestamp=now_utc,
                    policy_etag=etag,
                    details=f"VERIFICATION FAILURE: {normalized_member} still possesses active {target_role} binding for project {target_project_id} (Org Policy ETag: {etag})!"
                )

        except Exception as e:
            return VerificationResult(
                verified_removed=False,
                timestamp=datetime.now(timezone.utc),
                policy_etag=None,
                details=f"Error checking organization IAM policy for verification: {str(e)}"
            )


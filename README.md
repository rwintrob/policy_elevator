# JIT Policy Elevator

An automated Just-In-Time (JIT) IAM Elevation Service for Google Cloud Platform (GCP).

## Features
- **Dynamic Role Selection**: Request temporary elevation for specific IAM roles from an extensive catalog (e.g., Organization Policy Administrator, Project IAM Admin, Compute Engine Admin, Storage Admin, etc.).
- **Self-Service Elevation Requests**: Submit JIT elevation requests specifying target project, requested role, justification, and duration.
- **Identity Eligibility Checks**: Domain-based identity verification for requesters and approvers with enforced Separation of Duties.
- **Automated Revocation Loop**: Background worker continuously monitors active grants and automatically revokes access upon expiration.
- **Empirical Revocation Verification**: Queries GCP Resource Manager API to verify IAM policy removal after revocation.
- **Immutable Audit Logging**: Structured audit trail persisted to Cloud Logging and Firestore.

## API Endpoints
- `GET /api/health` - Service health status
- `GET /api/roles` - Catalog of available IAM roles for JIT elevation
- `GET /api/identity/check` - Check user identity eligibility
- `POST /api/requests` - Create a new JIT elevation request
- `GET /api/requests` - List all elevation requests
- `POST /api/requests/{id}/approve` - Approve or reject a request
- `POST /api/requests/{id}/revoke` - Manually revoke an active grant
- `GET /api/requests/{id}/verify` - Empirically verify permission removal
- `GET /api/notifications/config` - Inspect email notification backend status
- `POST /api/notifications/test` - Send a test email to verify SMTP / SendGrid connectivity
- `GET /api/audit` - Filterable audit log stream

## Email Notification Configuration
Approver notifications can be dispatched via standard SMTP, SendGrid, Mailgun, or Google Workspace Relay. Copy `.env.example` to `.env` or export environment variables:

### Option A: Standard SMTP / Gmail App Passwords
```bash
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT=587
export SMTP_USER="your-email@rwintrob.altostrat.com"
export SMTP_PASSWORD="your-app-password"
export SMTP_SENDER="jit-elevator@rwintrob.altostrat.com"
export SMTP_USE_TLS=true
```

### Option B: SendGrid Web API
```bash
export SENDGRID_API_KEY="SG.your_sendgrid_api_key_here"
export SMTP_SENDER="jit-elevator@rwintrob.altostrat.com"
```

### Option C: Google Workspace Unauthenticated Relay (IP Whitelisted)
```bash
export SMTP_HOST="smtp-relay.gmail.com"
export SMTP_PORT=25
export SMTP_SENDER="jit-elevator@rwintrob.altostrat.com"
```

## Quick Start
```bash
# Install dependencies
pip install -r requirements.txt

# Run application
python3 -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```


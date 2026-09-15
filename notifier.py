import os
import html
import logging
import smtplib
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict, Optional, Tuple
from models import ElevationRequest

logger = logging.getLogger("jit_policy_elevator.notifier")

def load_env(override: bool = True) -> None:
    """Loads environment variables from .env if present in workspace or cwd."""
    search_paths = [
        Path(__file__).resolve().parent / ".env",
        Path.cwd() / ".env"
    ]
    for path in search_paths:
        if path.exists() and path.is_file():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            key, val = line.split("=", 1)
                            key = key.strip()
                            val = val.strip().strip("'\"")
                            if override or key not in os.environ or not os.environ[key]:
                                os.environ[key] = val
            except Exception as e:
                logger.warning(f"Could not read .env file at {path}: {e}")

# Initial load on module import
load_env()

def get_notification_config() -> Dict[str, Any]:
    """Retrieves safe, sanitised metadata on currently configured notification backend."""
    load_env()
    sendgrid_key = os.environ.get("SENDGRID_API_KEY")
    mailgun_key = os.environ.get("MAILGUN_API_KEY")
    mailgun_domain = os.environ.get("MAILGUN_DOMAIN")
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER") or os.environ.get("SMTP_USERNAME")
    smtp_sender = os.environ.get("SMTP_SENDER") or os.environ.get("DEFAULT_FROM_EMAIL") or (smtp_user if smtp_user and "@" in smtp_user else "jit-elevator-noreply@altostrat.com")
    
    use_ssl = os.environ.get("SMTP_USE_SSL", "").lower() in ("true", "1", "yes") or smtp_port == 465
    use_tls = os.environ.get("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes") and not use_ssl

    smtp_password = os.environ.get("SMTP_PASSWORD") or os.environ.get("SMTP_PASS")
    has_password = bool(smtp_password and smtp_password.strip())
    # Providers requiring authentication
    requires_auth = bool(smtp_host and any(k in smtp_host.lower() for k in ["gmail", "google", "outlook", "office365", "sendgrid", "mailgun", "amazonaws"]))

    if sendgrid_key:
        provider = "SENDGRID"
        configured = True
    elif mailgun_key and mailgun_domain:
        provider = "MAILGUN"
        configured = True
    elif smtp_host and (has_password or not requires_auth):
        provider = "SMTP"
        configured = True
    else:
        provider = "SIMULATION"
        configured = False

    return {
        "configured": configured,
        "provider": provider,
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_user": smtp_user,
        "sender_email": smtp_sender,
        "use_tls": use_tls,
        "use_ssl": use_ssl,
        "has_password": has_password,
        "pending_credentials": bool(smtp_host and requires_auth and not has_password),
        "sendgrid_configured": bool(sendgrid_key),
        "mailgun_configured": bool(mailgun_key and mailgun_domain),
    }

def dispatch_email(
    to_email: str,
    subject: str,
    body_html: str,
    body_text: Optional[str] = None
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Sends an email via the configured backend (SendGrid, Mailgun, SMTP, or Simulation).
    Returns (success: bool, status_code: str, details: dict).
    """
    config = get_notification_config()
    sender_email = config["sender_email"]

    # 1. SendGrid API Backend
    if config["provider"] == "SENDGRID":
        try:
            import json
            import urllib.request
            api_key = os.environ.get("SENDGRID_API_KEY")
            url = "https://api.sendgrid.com/v3/mail/send"
            payload = {
                "personalizations": [{"to": [{"email": to_email}]}],
                "from": {"email": sender_email},
                "subject": subject,
                "content": [{"type": "text/html", "value": body_html}]
            }
            if body_text:
                payload["content"].insert(0, {"type": "text/plain", "value": body_text})

            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status in (200, 202):
                    logger.info(f"Email successfully dispatched to {to_email} via SendGrid API.")
                    return True, "DELIVERED_SENDGRID", {"provider": "SENDGRID", "status_code": resp.status}
                else:
                    msg = f"SendGrid API responded with status {resp.status}"
                    logger.error(msg)
                    return False, "ERROR_SENDGRID", {"error": msg}
        except Exception as e:
            logger.error(f"Failed to dispatch email via SendGrid: {e}")
            return False, "FAILED_SENDGRID", {"error": str(e)}

    # 2. Mailgun API Backend
    if config["provider"] == "MAILGUN":
        try:
            import urllib.parse
            import urllib.request
            import base64
            api_key = os.environ.get("MAILGUN_API_KEY")
            domain = os.environ.get("MAILGUN_DOMAIN")
            url = f"https://api.mailgun.net/v3/{domain}/messages"
            data = urllib.parse.urlencode({
                "from": sender_email,
                "to": to_email,
                "subject": subject,
                "html": body_html,
                "text": body_text or ""
            }).encode("utf-8")

            auth_str = base64.b64encode(f"api:{api_key}".encode("utf-8")).decode("ascii")
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Authorization": f"Basic {auth_str}"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    logger.info(f"Email successfully dispatched to {to_email} via Mailgun API.")
                    return True, "DELIVERED_MAILGUN", {"provider": "MAILGUN", "status_code": resp.status}
        except Exception as e:
            logger.error(f"Failed to dispatch email via Mailgun: {e}")
            return False, "FAILED_MAILGUN", {"error": str(e)}

    # 3. SMTP Server Backend
    if config["provider"] == "SMTP":
        smtp_host = config["smtp_host"]
        smtp_port = config["smtp_port"]
        smtp_user = config["smtp_user"]
        smtp_password = os.environ.get("SMTP_PASSWORD") or os.environ.get("SMTP_PASS")
        use_ssl = config["use_ssl"]
        use_tls = config["use_tls"]

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = sender_email
            msg["To"] = to_email
            if body_text:
                msg.attach(MIMEText(body_text, "plain"))
            msg.attach(MIMEText(body_html, "html"))

            if use_ssl:
                server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10)
            else:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
                if use_tls:
                    server.starttls()

            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)

            server.sendmail(sender_email, [to_email], msg.as_string())
            server.quit()
            logger.info(f"Email notification successfully sent to {to_email} via SMTP ({smtp_host}:{smtp_port}).")
            return True, "DELIVERED_SMTP", {"provider": "SMTP", "host": smtp_host, "port": smtp_port}
        except Exception as e:
            logger.error(f"Failed to send SMTP email notification to {to_email} via {smtp_host}:{smtp_port}: {e}")
            return False, "FAILED_SMTP", {"error": str(e), "host": smtp_host, "port": smtp_port}

    # 4. Simulation Fallback
    logger.info(
        f"SIMULATED EMAIL DISPATCH: No external email provider configured (SMTP_HOST or SENDGRID_API_KEY not set). "
        f"Recipient: '{to_email}', Subject: '{subject}'"
    )
    return True, "SIMULATED", {
        "provider": "SIMULATION",
        "note": "To enable real email delivery, configure SMTP_HOST or SENDGRID_API_KEY in environment or .env file."
    }

def build_approver_notification_html(request: ElevationRequest) -> str:
    """Builds safely HTML-escaped notification body for designated approvers (FINDING-06)."""
    safe_approver = html.escape(request.approver_email or "", quote=True)
    safe_req_id = html.escape(request.request_id or "", quote=True)
    safe_requester = html.escape(request.requester_email or "", quote=True)
    safe_project = html.escape(request.target_project_id or "", quote=True)
    safe_role = html.escape(request.role or "", quote=True)
    safe_justification = html.escape(request.justification or "", quote=True)

    return f"""
    <html>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
          <h2 style="color: #2563eb; margin-top: 0;">🛡️ JIT Elevation Request Pending Approval</h2>
          <p>Hello <strong>{safe_approver}</strong>,</p>
          <p>You have been designated as the approver for a Just-In-Time (JIT) IAM permission elevation request on Google Cloud Platform.</p>
          
          <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
            <tr style="background-color: #f8fafc;">
              <td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold;">Request ID:</td>
              <td style="padding: 10px; border: 1px solid #e2e8f0;"><code>#{safe_req_id}</code></td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold;">Requester:</td>
              <td style="padding: 10px; border: 1px solid #e2e8f0;">{safe_requester}</td>
            </tr>
            <tr style="background-color: #f8fafc;">
              <td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold;">Target Project ID:</td>
              <td style="padding: 10px; border: 1px solid #e2e8f0;"><strong>{safe_project}</strong></td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold;">Requested Role:</td>
              <td style="padding: 10px; border: 1px solid #e2e8f0;"><code>{safe_role}</code></td>
            </tr>
            <tr style="background-color: #f8fafc;">
              <td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold;">Duration:</td>
              <td style="padding: 10px; border: 1px solid #e2e8f0;">{request.duration_minutes} minutes</td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold;">Justification:</td>
              <td style="padding: 10px; border: 1px solid #e2e8f0;"><em>"{safe_justification}"</em></td>
            </tr>
          </table>

          <p>Please review and approve or reject this request in the JIT Elevation Console.</p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;" />
          <p style="font-size: 0.85rem; color: #64748b;">This is an automated notification from JIT Policy Elevator Service.</p>
        </div>
      </body>
    </html>
    """

def send_approver_notification(request: ElevationRequest) -> bool:
    """
    Dispatches an email notification to the designated approver when a JIT elevation request is submitted.
    """
    if not request.notify_approver_email:
        logger.info(f"Notification skipped for request #{request.request_id} (notify_approver_email is False).")
        return False

    approver = request.approver_email
    subject = f"[JIT Elevation Pending] Request #{request.request_id} for Project {request.target_project_id}"
    body_html = build_approver_notification_html(request)

    body_text = f"""JIT Elevation Request Pending Approval

Hello {approver},

You have been designated as the approver for a Just-In-Time (JIT) IAM permission elevation request on Google Cloud Platform.

- Request ID: #{request.request_id}
- Requester: {request.requester_email}
- Target Project ID: {request.target_project_id}
- Requested Role: {request.role}
- Duration: {request.duration_minutes} minutes
- Justification: {request.justification}

Please review and approve or reject this request in the JIT Elevation Console.
"""

    success, status, details = dispatch_email(approver, subject, body_html, body_text)
    return success

def send_test_notification(to_email: str) -> Tuple[bool, str, Dict[str, Any]]:
    """Sends a test email to verify SMTP or SendGrid connectivity."""
    subject = "[JIT Policy Elevator] Email Notification Test"
    body_html = f"""
    <html>
      <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #10b981;">✅ JIT Email Notification Verified</h2>
        <p>This is a test notification confirming that email dispatch from JIT Policy Elevator is operational.</p>
        <p><strong>Recipient:</strong> {to_email}</p>
      </body>
    </html>
    """
    body_text = f"JIT Email Notification Verified. This confirms email dispatch is operational for {to_email}."
    return dispatch_email(to_email, subject, body_html, body_text)

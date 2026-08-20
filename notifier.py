import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from models import ElevationRequest

logger = logging.getLogger("jit_policy_elevator.notifier")

def send_approver_notification(request: ElevationRequest) -> bool:
    """
    Dispatches an email notification to the designated approver when a JIT elevation request is submitted.
    """
    if not request.notify_approver_email:
        logger.info(f"Notification skipped for request #{request.request_id} (notify_approver_email is False).")
        return False

    approver = request.approver_email
    subject = f"[JIT Elevation Pending] Request #{request.request_id} for Project {request.target_project_id}"

    body_html = f"""
    <html>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
          <h2 style="color: #2563eb; margin-top: 0;">🛡️ JIT Elevation Request Pending Approval</h2>
          <p>Hello <strong>{approver}</strong>,</p>
          <p>You have been designated as the approver for a Just-In-Time (JIT) IAM permission elevation request on Google Cloud Platform.</p>
          
          <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
            <tr style="background-color: #f8fafc;">
              <td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold;">Request ID:</td>
              <td style="padding: 10px; border: 1px solid #e2e8f0;"><code>#{request.request_id}</code></td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold;">Requester:</td>
              <td style="padding: 10px; border: 1px solid #e2e8f0;">{request.requester_email}</td>
            </tr>
            <tr style="background-color: #f8fafc;">
              <td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold;">Target Project ID:</td>
              <td style="padding: 10px; border: 1px solid #e2e8f0;"><strong>{request.target_project_id}</strong></td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold;">Requested Role:</td>
              <td style="padding: 10px; border: 1px solid #e2e8f0;"><code>{request.role}</code></td>
            </tr>
            <tr style="background-color: #f8fafc;">
              <td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold;">Duration:</td>
              <td style="padding: 10px; border: 1px solid #e2e8f0;">{request.duration_minutes} minutes</td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold;">Justification:</td>
              <td style="padding: 10px; border: 1px solid #e2e8f0;"><em>"{request.justification}"</em></td>
            </tr>
          </table>

          <p>Please review and approve or reject this request in the JIT Elevation Console.</p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;" />
          <p style="font-size: 0.85rem; color: #64748b;">This is an automated notification from JIT Policy Elevator Service.</p>
        </div>
      </body>
    </html>
    """

    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    sender_email = os.environ.get("SMTP_SENDER", "jit-elevator-noreply@altostrat.com")

    if smtp_host and smtp_user:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = sender_email
            msg["To"] = approver
            msg.attach(MIMEText(body_html, "html"))

            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.sendmail(sender_email, [approver], msg.as_string())

            logger.info(f"Email notification successfully sent to approver {approver} for request #{request.request_id} via SMTP.")
            return True
        except Exception as e:
            logger.error(f"Failed to send SMTP email notification to {approver}: {e}")
            return False
    else:
        logger.info(f"SIMULATED EMAIL DISPATCH: Sent approval notification email to '{approver}' for JIT Request #{request.request_id} (Role: {request.role}, Project: {request.target_project_id})")
        return True

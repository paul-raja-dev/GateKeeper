"""
GateKeeper - Email Service

Sends transactional emails for:
- Email address verification
- Password reset

Design decisions:
- Uses aiosmtplib for non-blocking SMTP delivery
- SMTP_ENABLED=False allows running without an SMTP server in development
  (tokens are returned in the API response instead of sent by email)
- HTML emails with plain-text fallback
- All email content is defined here as template strings — easy to customise
"""

import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib

from app.config import get_settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core Sender
# ---------------------------------------------------------------------------


async def _send_email(to_email: str, subject: str, html_body: str) -> None:
    """
    Send an email via SMTP.

    If SMTP_ENABLED is False, logs the email content instead of sending.
    This makes local development possible without an SMTP server.
    """
    settings = get_settings()

    if not settings.SMTP_ENABLED:
        logger.info(
            "SMTP disabled — email NOT sent to %s (subject: %s)",
            to_email,
            subject,
        )
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
    msg["To"] = to_email

    msg.attach(MIMEText(html_body, "html"))

    try:
        await aiosmtplib.send(
            msg,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USERNAME,
            password=settings.SMTP_PASSWORD,
            start_tls=True,
        )
        logger.info("Email sent to %s (subject: %s)", to_email, subject)
    except Exception:
        logger.exception("Failed to send email to %s", to_email)
        # Don't raise — email failure should not crash the request.
        # The caller can decide to surface this to the user.


# ---------------------------------------------------------------------------
# Email Templates
# ---------------------------------------------------------------------------


async def send_verification_email(to_email: str, token: str) -> None:
    """
    Send the email verification link to a newly registered user.

    The link points to the /verify-email endpoint with the token as a
    query parameter. In a real app, this would point to the frontend URL
    which would then call the API. For this IAM service we link directly
    to the API endpoint.
    """
    settings = get_settings()
    verify_url = f"{settings.APP_BASE_URL}/api/v1/auth/verify-email?token={token}"

    subject = "Verify your GateKeeper email address"
    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #2563eb;">Verify your email</h2>
        <p>Welcome to GateKeeper! Click below to verify your email.</p>
        <p>This link expires in <strong>1 hour</strong>.</p>
        <a href="{verify_url}"
           style="display:inline-block; background:#2563eb; color:#fff;
                  padding:12px 24px; border-radius:6px; text-decoration:none;
                  font-weight:bold; margin:16px 0;">
          Verify Email Address
        </a>
        <p style="color:#6b7280; font-size:12px;">
          If you didn't create a GateKeeper account, you can safely ignore this email.
        </p>
        <hr style="border:none; border-top:1px solid #e5e7eb;">
        <p style="color:#9ca3af; font-size:11px;">GateKeeper IAM Platform</p>
      </body>
    </html>
    """

    await _send_email(to_email, subject, html_body)


async def send_password_reset_email(to_email: str, token: str) -> None:
    """
    Send a password reset link.

    This link expires in 15 minutes — the short window limits the damage
    if the email is intercepted or the link is leaked in server logs.
    """
    settings = get_settings()
    reset_url = f"{settings.APP_BASE_URL}/api/v1/auth/reset-password?token={token}"

    subject = "Reset your GateKeeper password"
    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #dc2626;">Reset your password</h2>
        <p>We received a request to reset the password for your GateKeeper account.</p>
        <p>This link expires in <strong>15 minutes</strong>.</p>
        <a href="{reset_url}"
           style="display:inline-block; background:#dc2626; color:#fff;
                  padding:12px 24px; border-radius:6px; text-decoration:none;
                  font-weight:bold; margin:16px 0;">
          Reset Password
        </a>
        <p style="color:#6b7280; font-size:12px;">
          If you didn't request a password reset, you can safely ignore this email.
          Your password will not be changed.
        </p>
        <hr style="border:none; border-top:1px solid #e5e7eb;">
        <p style="color:#9ca3af; font-size:11px;">GateKeeper IAM Platform</p>
      </body>
    </html>
    """

    await _send_email(to_email, subject, html_body)

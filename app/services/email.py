"""Email notification service (supports Mailpit and standard SMTP)."""

import logging
from email.message import EmailMessage
import aiosmtplib
from app.config import get_settings

logger = logging.getLogger("veylor.email")


async def send_email(to_email: str, subject: str, text_content: str, html_content: str) -> bool:
    """Deliver an email via configured SMTP server (e.g. Mailpit for local dev)."""
    settings = get_settings()

    message = EmailMessage()
    message["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(text_content)
    message.add_alternative(html_content, subtype="html")

    try:
        await aiosmtplib.send(
            message,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USERNAME or None,
            password=settings.SMTP_PASSWORD or None,
            use_tls=settings.SMTP_USE_TLS,
            timeout=5.0,
        )
        logger.info("Email delivered successfully to %s: %s", to_email, subject)
        return True
    except Exception as e:
        logger.warning(
            "Could not deliver email via SMTP (%s:%s): %s. (Expected in offline test environments)",
            settings.SMTP_HOST,
            settings.SMTP_PORT,
            str(e),
        )
        return False


async def send_verification_email(to_email: str, verification_token: str) -> bool:
    """Send account email verification link."""
    settings = get_settings()
    verify_url = f"{settings.SSO_ISSUER}/verify-email?token={verification_token}"

    subject = "Verify your Veylor account email"
    text = (
        f"Welcome to Veylor!\n\n"
        f"Please verify your email address by visiting the following link:\n"
        f"{verify_url}\n\n"
        f"This link will expire in {settings.EMAIL_VERIFICATION_TTL_SECONDS // 3600} hours.\n"
        f"If you did not create a Veylor account, you can safely ignore this email."
    )
    html = f"""
    <div style="font-family: sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
        <h2 style="color: #0f172a;">Verify your Veylor account</h2>
        <p style="color: #475569;">Welcome to the Veylor ecosystem! Please confirm your email address below.</p>
        <div style="margin: 28px 0;">
            <a href="{verify_url}" style="background-color: #2563eb; color: #ffffff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 500; display: inline-block;">Verify Email</a>
        </div>
        <p style="color: #64748b; font-size: 13px;">Or copy and paste this link in your browser:<br>{verify_url}</p>
    </div>
    """
    return await send_email(to_email, subject, text, html)


async def send_password_reset_email(to_email: str, reset_token: str) -> bool:
    """Send password reset link."""
    settings = get_settings()
    reset_url = f"{settings.SSO_ISSUER}/reset-password?token={reset_token}"

    subject = "Reset your Veylor account password"
    text = (
        f"A password reset request was received for your Veylor account.\n\n"
        f"Reset your password using the link below:\n"
        f"{reset_url}\n\n"
        f"This link expires in {settings.PASSWORD_RESET_TTL_SECONDS // 60} minutes.\n"
        f"If you did not request a password reset, please secure your account immediately."
    )
    html = f"""
    <div style="font-family: sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
        <h2 style="color: #0f172a;">Reset your Veylor password</h2>
        <p style="color: #475569;">Click the button below to choose a new password for your Veylor account.</p>
        <div style="margin: 28px 0;">
            <a href="{reset_url}" style="background-color: #2563eb; color: #ffffff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 500; display: inline-block;">Reset Password</a>
        </div>
        <p style="color: #64748b; font-size: 13px;">Or copy and paste this link in your browser:<br>{reset_url}</p>
    </div>
    """
    return await send_email(to_email, subject, text, html)

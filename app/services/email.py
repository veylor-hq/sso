"""Email notification service (supports Mailpit and standard SMTP)."""

import logging
from email.message import EmailMessage
import aiosmtplib
from app.config import get_settings

logger = logging.getLogger("veylor.email")


async def send_email(to_email: str, subject: str, text_content: str, html_content: str) -> bool:
    """Deliver an email via configured SMTP server (e.g. Brevo in prod, Mailpit in dev)."""
    settings = get_settings()

    from_header = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
    message = EmailMessage()
    message["From"] = from_header
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(text_content)
    message.add_alternative(html_content, subtype="html")

    # Smart TLS detection based on port and configuration:
    # Port 587 = STARTTLS (upgrade plain connection after EHLO)
    # Port 465 = Implicit TLS (connect directly via SSL)
    # Port 25/1025 = Plaintext SMTP (Mailpit / dev)
    is_starttls = settings.SMTP_STARTTLS and settings.SMTP_PORT == 587
    is_tls = settings.SMTP_USE_TLS and settings.SMTP_PORT == 465

    send_kwargs = {
        "hostname": settings.SMTP_HOST,
        "port": settings.SMTP_PORT,
        "timeout": 10.0,
        "start_tls": is_starttls,
        "use_tls": is_tls,
    }
    if settings.SMTP_USERNAME:
        send_kwargs["username"] = settings.SMTP_USERNAME
    if settings.SMTP_PASSWORD:
        send_kwargs["password"] = settings.SMTP_PASSWORD
    if settings.SMTP_FROM_EMAIL:
        send_kwargs["sender"] = settings.SMTP_FROM_EMAIL

    try:
        await aiosmtplib.send(message, **send_kwargs)
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
    """Send account email verification link styled in Veylor defense aesthetic."""
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
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body style="margin: 0; padding: 32px; background-color: #111111; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #fafafa;">
        <div style="max-width: 520px; margin: 0 auto; background-color: #161616; border: 1px solid #333333; padding: 32px; border-radius: 0px;">
            <div style="display: inline-block; border: 1px solid #333333; background-color: #1a1a1a; padding: 4px 10px; font-size: 11px; font-family: monospace; text-transform: uppercase; letter-spacing: 0.1em; color: #a1a1aa; margin-bottom: 20px;">
                Identity Verification
            </div>
            <h1 style="margin: 0 0 12px 0; font-size: 20px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: #fafafa;">
                Verify Your Account
            </h1>
            <p style="margin: 0 0 24px 0; font-size: 13px; line-height: 1.6; color: #a1a1aa;">
                Welcome to the Veylor ecosystem. Confirm your email address to secure your central Single Sign-On credentials.
            </p>
            <div style="margin: 28px 0;">
                <a href="{verify_url}" style="background-color: #fafafa; color: #111111; padding: 12px 24px; text-decoration: none; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.1em; display: inline-block; border-radius: 0px;">
                    Verify Email &rarr;
                </a>
            </div>
            <p style="margin: 24px 0 0 0; font-size: 11px; font-family: monospace; color: #71717a; line-height: 1.5; word-break: break-all;">
                Or copy and paste this link in your browser:<br>
                <span style="color: #a1a1aa;">{verify_url}</span>
            </p>
            <div style="margin-top: 32px; padding-top: 20px; border-top: 1px solid #262626; font-size: 11px; font-family: monospace; color: #52525b; text-transform: uppercase; letter-spacing: 0.05em;">
                &copy; 2026 Veylor Ecosystem &bull; Central Single Sign-On
            </div>
        </div>
    </body>
    </html>
    """
    return await send_email(to_email, subject, text, html)


async def send_password_reset_email(to_email: str, reset_token: str) -> bool:
    """Send password reset link styled in Veylor defense aesthetic."""
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
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body style="margin: 0; padding: 32px; background-color: #111111; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #fafafa;">
        <div style="max-width: 520px; margin: 0 auto; background-color: #161616; border: 1px solid #333333; padding: 32px; border-radius: 0px;">
            <div style="display: inline-block; border: 1px solid #333333; background-color: #1a1a1a; padding: 4px 10px; font-size: 11px; font-family: monospace; text-transform: uppercase; letter-spacing: 0.1em; color: #a1a1aa; margin-bottom: 20px;">
                Security Alert
            </div>
            <h1 style="margin: 0 0 12px 0; font-size: 20px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: #fafafa;">
                Password Reset
            </h1>
            <p style="margin: 0 0 24px 0; font-size: 13px; line-height: 1.6; color: #a1a1aa;">
                A password reset request was initiated for your Veylor account. If you made this request, proceed below to set a new password.
            </p>
            <div style="margin: 28px 0;">
                <a href="{reset_url}" style="background-color: #fafafa; color: #111111; padding: 12px 24px; text-decoration: none; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.1em; display: inline-block; border-radius: 0px;">
                    Reset Password &rarr;
                </a>
            </div>
            <p style="margin: 24px 0 0 0; font-size: 11px; font-family: monospace; color: #71717a; line-height: 1.5; word-break: break-all;">
                Or copy and paste this link in your browser:<br>
                <span style="color: #a1a1aa;">{reset_url}</span>
            </p>
            <div style="margin-top: 32px; padding-top: 20px; border-top: 1px solid #262626; font-size: 11px; font-family: monospace; color: #52525b; text-transform: uppercase; letter-spacing: 0.05em;">
                &copy; 2026 Veylor Ecosystem &bull; Central Single Sign-On
            </div>
        </div>
    </body>
    </html>
    """
    return await send_email(to_email, subject, text, html)

import os
import ssl
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Union


def send_email(
    to: Union[str, List[str]],
    subject: str,
    body: str,
    html: bool = True,
) -> None:
    """
    Send an email using SMTP (STARTTLS) based on env vars:
      SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_SENDER
    """

    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_sender = os.getenv("SMTP_SENDER", smtp_user)

    if not smtp_user or not smtp_password or not smtp_sender:
        raise RuntimeError(
            "Missing SMTP env vars. Please set SMTP_USER, SMTP_PASSWORD, SMTP_SENDER "
            "(and optionally SMTP_HOST, SMTP_PORT)."
        )

    # normalize recipients
    recipients = [to] if isinstance(to, str) else list(to)
    if not recipients:
        raise ValueError("Recipient list is empty")

    # build email
    msg = MIMEMultipart("alternative")
    msg["From"] = smtp_sender
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject

    if html:
        msg.attach(MIMEText(body, "html", "utf-8"))
    else:
        msg.attach(MIMEText(body, "plain", "utf-8"))

    # send via STARTTLS
    context = ssl.create_default_context()

    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(smtp_user, smtp_password)
        server.sendmail(smtp_sender, recipients, msg.as_string())

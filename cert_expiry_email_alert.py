# cert_expiry_email_alert.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Your SMTP/email configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USER = "your_email@gmail.com"
EMAIL_PASS = "your_app_password"  # Use App Password if using Gmail

def send_expiry_alert(domain, expiry_date, days_remaining, status):
    """
    Sends an expiry alert email for the certificate
    """
    subject = f"[Alert] Certificate Status: {status} for {domain}"
    body = f"""
Dear Recipient,

This is a formal notification to inform you that the current certificate is approaching its expiry date or has expired.

Certificate Name: {domain}
Expiry Date: {expiry_date}
Days Remaining: {days_remaining}

We kindly request that you review the certificate status and ensure that all necessary actions are completed in a timely manner to prevent any potential service interruption.

If the renewal process has already been initiated or completed, please disregard this message.

Sincerely,
Certificate Monitoring & Alert System
Automated Notification
"""

    msg = MIMEMultipart()
    msg["From"] = EMAIL_USER
    msg["To"] = EMAIL_USER  # You can replace with recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, EMAIL_USER, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        raise e

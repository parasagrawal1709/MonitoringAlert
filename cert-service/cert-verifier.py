#!/usr/bin/env python3

import csv
from datetime import datetime, timezone

# ✅ CONFIGURATION
CERT_FILE = '/home/pc/certs.csv'  # CSV file with format: name,expiry_date (YYYY-MM-DD)
DATE_FORMAT = "%Y-%m-%d"          # Matches the format in CSV

# Optional email alerts
SEND_EMAIL_ALERTS = False
EMAIL_FROM = 'your_email@gmail.com'
EMAIL_TO = 'alert_email@gmail.com'
EMAIL_PASSWORD = 'your_app_password'  # Use app password if Gmail

# ----------------------------------------
def calculate_status(expiry_date_str):
    """Check if a certificate is valid or expired."""
    try:
        expiry = datetime.strptime(expiry_date_str, DATE_FORMAT).replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_remaining = (expiry - now).days
        status = "VALID" if days_remaining >= 0 else "EXPIRED"
        return status, days_remaining
    except Exception as e:
        return "ERROR", str(e)

def read_certificates(file_path):
    """Read certificates from CSV."""
    certs = []
    try:
        with open(file_path, newline='') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if len(row) != 2:
                    continue
                cert_name, expiry_date = row
                certs.append((cert_name.strip(), expiry_date.strip()))
    except FileNotFoundError:
        print(f"Error: {file_path} not found!")
    return certs

def update_cert_status():
    """Check all certificates and print their status."""
    certs = read_certificates(CERT_FILE)
    for name, expires_at in certs:
        status, days_remaining = calculate_status(expires_at)
        print(f"{name}: {status}, {days_remaining} days remaining")

# Optional: Email alert function (requires SMTP setup)
def send_email_alert(subject, body):
    if not SEND_EMAIL_ALERTS:
        return
    import smtplib
    from email.message import EmailMessage

    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_FROM, EMAIL_PASSWORD)
            smtp.send_message(msg)
    except Exception as e:
        print("Email sending failed:", e)

# ----------------------------------------
if __name__ == "__main__":
    update_cert_status()
from datetime import datetime, timezone

# Threshold in days for “soon to expire”
EXPIRY_WARNING_DAYS = 30

def calculate_status(expiry_date_str):
    # Handle both full datetime and date-only formats
    try:
        expiry = datetime.strptime(expiry_date_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        expiry = datetime.strptime(expiry_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    delta = expiry - now
    days_remaining = delta.days

    status = "EXPIRED" if days_remaining < 0 else "VALID"
    return status, days_remaining

def update_cert_status():
    # Example certificate list
    certificates = [
        {"name": "example.com", "expires_at": "2026-07-24"},
        {"name": "Security_Communication_Root_CA", "expires_at": "2024-01-01"},
        # Add all your certs here
    ]

    for cert in certificates:
        status, days_remaining = calculate_status(cert["expires_at"])
        # Only log expired or expiring soon certificates
        if status == "EXPIRED" or days_remaining <= EXPIRY_WARNING_DAYS:
            print(f"{cert['name']}: {status}, {days_remaining} days remaining")

if __name__ == "__main__":
    update_cert_status()

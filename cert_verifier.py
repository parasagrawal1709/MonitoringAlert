#!/usr/bin/env python3
import csv
from datetime import datetime, timezone
import smtplib
from email.message import EmailMessage
import os

CERT_FILE = '/home/pc/certs.csv'  # your CSV of certs: name,expiry_date
LOG_FILE = '/home/pc/cert_verifier.log'
ALERT_THRESHOLD_DAYS = 30  # alert if less than 30 days remaining

# Email config
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
EMAIL_FROM = 'your_email@gmail.com'
EMAIL_TO = 'alert_email@gmail.com'
EMAIL_PASSWORD = 'your_app_password'  # use app password for Gmail

def calculate_status(expiry_date_str):
    # handle date with or without time
    try:
        expiry = datetime.strptime(expiry_date_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        expiry = datetime.strptime(expiry_date_str, "%Y-%m-%d")
    expiry = expiry.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    delta_days = (expiry - now).days
    status = "VALID" if delta_days >= 0 else "EXPIRED"
    return status, delta_days

def send_email(subject, body):
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f"Email sending failed: {e}")

def update_cert_status():
    alerts = []
    
    # Rotate log if exists
    if os.path.exists(LOG_FILE):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.rename(LOG_FILE, f"{LOG_FILE}.{timestamp}")

    with open(LOG_FILE, 'w') as log:
        with open(CERT_FILE) as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                name, expires_at = row
                status, days_remaining = calculate_status(expires_at)
                log_line = f"{name}: {status}, {days_remaining} days remaining\n"
                log.write(log_line)
                # add to alerts if expired or close to expiry
                if status == "EXPIRED" or days_remaining <= ALERT_THRESHOLD_DAYS:
                    alerts.append(log_line)
    
    if alerts:
        send_email("Certificate Alert", "".join(alerts))

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

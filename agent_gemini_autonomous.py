# agent_gemini_autonomous.py
import pandas as pd
import datetime
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

# ---------------------------
# 1️⃣ Paths & Config
# ---------------------------
CSV_PATH = "mock_certificate_dataset.csv"  # file in same folder
LOG_PATH = "gemini_agent_log.csv"
GEMINI_API_URL = "https://api.gemini.com/your-endpoint"  # Replace with real endpoint
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")  # Store your key in environment

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USER = os.getenv("ALERT_EMAIL_USER")  # Your email
EMAIL_PASS = os.getenv("ALERT_EMAIL_PASS")  # App password or real password

# ---------------------------
# 2️⃣ Load dataset
# ---------------------------
df = pd.read_csv(CSV_PATH)
print(f"📂 Loaded dataset with {len(df)} certificates")

# ---------------------------
# 3️⃣ Helper: Gemini API call with fallback
# ---------------------------
def call_gemini(cert):
    payload = {
        "domain": cert["domain"],
        "expiry_date": cert["expiry_date"],
        "status": cert["status"]
    }
    headers = {
        "Authorization": f"Bearer {GEMINI_API_KEY}",
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(GEMINI_API_URL, json=payload, headers=headers, timeout=5)
        response.raise_for_status()
        return True, response.json()
    except Exception as e:
        return False, str(e)

# ---------------------------
# 4️⃣ Helper: Determine action
# ---------------------------
def decide_action(expiry_str):
    today = datetime.datetime.utcnow().date()
    expiry_date = datetime.datetime.strptime(expiry_str, "%Y-%m-%d").date()
    days_remaining = (expiry_date - today).days

    if days_remaining < 0:
        return "RENEW", f"Certificate expired {-days_remaining} days ago"
    elif days_remaining <= 2:
        return "ALERT", f"Certificate expires in {days_remaining} days"
    else:
        return "IGNORE", f"expires in {days_remaining} days"

# ---------------------------
# 5️⃣ Helper: Send email alert
# ---------------------------
def send_expiry_email(cert, action, reason):
    msg = MIMEMultipart()
    msg["From"] = EMAIL_USER
    msg["To"] = EMAIL_USER  # Send to yourself for demo
    msg["Subject"] = f"Certificate Alert: {cert['domain']} - {action}"

    body = f"""
Dear Recipient,

This is a formal notification about your certificate:

Certificate Name: {cert['domain']}
Expiry Date: {cert['expiry_date']}
Status: {cert['status']}
Action: {action}
Reason: {reason}

Please review the status and ensure timely action.

Sincerely,
Certificate Monitoring & Alert System
Automated Notification
"""
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        return str(e)

# ---------------------------
# 6️⃣ Process all certificates
# ---------------------------
log_rows = []

for _, cert in df.iterrows():
    action, reason = decide_action(cert["expiry_date"])

    # Call Gemini API
    gemini_success, gemini_resp = call_gemini(cert)

    if not gemini_success:
        gemini_note = f"Gemini ❌ (fallback used)"
    else:
        gemini_note = f"Gemini ✅"

    # Send email only if action is ALERT or RENEW
    if action in ["ALERT", "RENEW"]:
        email_result = send_expiry_email(cert, action, reason)
        if email_result is True:
            email_note = "Email ✅"
        else:
            email_note = f"Email ❌ | {email_result}"
    else:
        email_note = "Email N/A"

    # Print summary per cert
    status_icon = "🟢" if action == "IGNORE" else "⚠️" if action == "ALERT" else "🔴"
    print(f"{status_icon} {cert['domain']} → Action: {action} | Reason: {reason} | {gemini_note} | {email_note}")

    # Log
    log_rows.append({
        "domain": cert["domain"],
        "expiry_date": cert["expiry_date"],
        "status": cert["status"],
        "action": action,
        "reason": reason,
        "gemini_success": gemini_success,
        "email_result": email_note
    })

# ---------------------------
# 7️⃣ Save log
# ---------------------------
pd.DataFrame(log_rows).to_csv(LOG_PATH, index=False)
print(f"\n✅ Agent log saved to {LOG_PATH}")

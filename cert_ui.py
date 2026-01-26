import streamlit as st
import pandas as pd
from datetime import datetime
from io import BytesIO

# ---------------------------
# Config
# ---------------------------
CSV_PATH = "/home/pc/gemini_agent_log.csv"  # Path to Gemini agent log CSV
st.set_page_config(page_title="Certificate Dashboard", layout="wide")

# ---------------------------
# Load Data
# ---------------------------
try:
    df = pd.read_csv(CSV_PATH)
except FileNotFoundError:
    st.error(f"❌ CSV file not found at {CSV_PATH}")
    st.stop()

# Convert expiry_date to datetime and compute days remaining
df["expiry_date"] = pd.to_datetime(df["expiry_date"])
df["days_remaining"] = (df["expiry_date"] - datetime.now()).dt.days

# ---------------------------
# Page Header
# ---------------------------
st.title("🔐 Certificate Monitoring Dashboard")
st.markdown(
    "Monitor SSL certificates. Expired/Expiring certificates can be downloaded."
)

# ---------------------------
# Summary Metrics
# ---------------------------
total = len(df)
expired = len(df[df['status'].str.upper() == 'EXPIRED'])
expiring = len(df[(df['status'].str.upper() != 'EXPIRED') & (df['days_remaining'] <= 30)])
valid = len(df[df['status'].str.upper() == 'VALID'])

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Certificates", total)
col2.metric("Expired", expired)
col3.metric("Expiring Soon (<30 days)", expiring)
col4.metric("Valid", valid)

st.markdown("---")

# ---------------------------
# Certificate Table Header
# ---------------------------
cols = st.columns([3, 2, 2, 2, 2, 2, 2, 2])
headers = ["Domain", "Expiry Date", "Days Remaining", "Status", "Action/Reason", "Gemini", "Email", "Download"]
for col, header in zip(cols, headers):
    col.markdown(f"**{header}**")

# ---------------------------
# Render Table Rows
# ---------------------------
for _, row in df.iterrows():
    cols = st.columns([3, 2, 2, 2, 2, 2, 2, 2])
    cols[0].write(row["domain"])
    cols[1].write(row["expiry_date"].strftime("%Y-%m-%d"))
    cols[2].write(row["days_remaining"])
    cols[3].write(row["status"])
    cols[4].write(row.get("reason", "N/A"))
    cols[5].write(row.get("gemini", "N/A"))
    cols[6].write(row.get("email", "N/A"))

    # Download button only for expired or expiring soon
    if row["status"].upper() == "EXPIRED" or row["days_remaining"] <= 30:
        cert_content = f"-----BEGIN CERTIFICATE-----\nCertificate for {row['domain']}\nStatus: {row['status']}\nExpiry: {row['expiry_date']}\n-----END CERTIFICATE-----"
        cert_bytes = BytesIO(cert_content.encode("utf-8"))
        cols[7].download_button(
            label="⬇️ Download",
            data=cert_bytes,
            file_name=f"{row['domain']}_cert.txt",
            mime="text/plain"
        )
    else:
        cols[7].write("—")

# ---------------------------
# Footer
# ---------------------------
st.markdown("---")
st.caption(f"Dashboard • Last update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} • Powered by Streamlit 🔒")

# ~/cert_dashboard_demo.py

import streamlit as st
import pandas as pd
from datetime import datetime

# --- Page Config ---
st.set_page_config(
    page_title="Cert Dashboard Demo",
    page_icon="🔒",
    layout="wide"
)

# --- Header ---
st.title("🔒 Certificate Verification Dashboard")
st.markdown(
    """
    This is a demo Streamlit dashboard for monitoring SSL certificates.
    ✅ Shows certificate name, validity status, and days remaining.
    """
)

# --- Sample Data (Demo-friendly) ---
data = {
    "Certificate Name": [
        "example.com", "SSL.com Root", "DigiCert Global Root", "GTS_Root_R2"
    ],
    "Expiry Date": [
        "2026-07-24", "2028-12-31", "2027-05-10", "2033-09-15"
    ]
}

df = pd.DataFrame(data)
df["Expiry Date"] = pd.to_datetime(df["Expiry Date"])
df["Days Remaining"] = (df["Expiry Date"] - datetime.now()).dt.days
df["Status"] = df["Days Remaining"].apply(lambda x: "VALID ✅" if x > 0 else "EXPIRED ❌")

# --- Display Data ---
st.subheader("Certificate Status Table")
st.dataframe(df.style.format({
    "Days Remaining": "{:.0f}"
}).highlight_max(subset=["Days Remaining"], color="lightgreen")
  .highlight_min(subset=["Days Remaining"], color="salmon"))

# --- Metrics at a glance ---
st.subheader("Summary Metrics")
col1, col2, col3 = st.columns(3)
col1.metric("Total Certificates", len(df))
col2.metric("Valid Certificates", len(df[df["Status"] == "VALID ✅"]))
col3.metric("Expired Certificates", len(df[df["Status"] == "EXPIRED ❌"]))

# --- Footer ---
st.markdown("---")
st.markdown("Demo Dashboard • Powered by Streamlit 🔒")

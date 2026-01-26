import streamlit as st
import pandas as pd
import streamlit as st
import pandas as pd
from datetime import datetime
from mock_data_certificate import certs_df
import io

st.set_page_config(page_title="Certificate Verification Dashboard", layout="wide")

st.title("🔐 Certificate Verification Dashboard")
st.markdown(
    "This is a demo Streamlit dashboard for monitoring SSL certificates. "
    "Shows certificate name, validity status, and days remaining."
)

# ---- Compute days remaining ----
df = certs_df.copy()
df["expiry_date"] = pd.to_datetime(df["expiry_date"])
df["days_remaining"] = (df["expiry_date"] - datetime.now()).dt.days

# ---- Status color mapping ----
def status_badge(status):
    if status == "VALID":
        return "✅ VALID"
    if status == "EXPIRING_SOON":
        return "⚠️ EXPIRING SOON"
    if status == "EXPIRED":
        return "❌ EXPIRED"
    return status

df["status_display"] = df["status"].apply(status_badge)

st.subheader("📄 Certificate Status Table")

# ---- Table header ----
cols = st.columns([3, 3, 2, 2, 2])
cols[0].markdown("**Certificate Name**")
cols[1].markdown("**Expiry Date**")
cols[2].markdown("**Days Remaining**")
cols[3].markdown("**Status**")
cols[4].markdown("**Action**")

# ---- Render rows ----
for _, row in df.iterrows():
    cols = st.columns([3, 3, 2, 2, 2])
    cols[0].write(row["domain"])
    cols[1].write(row["expiry_date"].strftime("%Y-%m-%d %H:%M:%S"))
    cols[2].write(row["days_remaining"])
    cols[3].write(row["status_display"])

    if row["status"] in ["EXPIRING_SOON", "EXPIRED"]:
        fake_cert = f"""-----BEGIN CERTIFICATE-----
Demo certificate for {row['domain']}
Status: {row['status']}
Expiry: {row['expiry_date']}
-----END CERTIFICATE-----
"""
        cols[4].download_button(
            label="⬇️ Download Cert",
            data=fake_cert,
            file_name=f"{row['domain']}.crt",
            mime="application/x-pem-file"
        )
    else:
        cols[4].write("—")

# ---- Summary metrics ----
st.divider()
st.subheader("📊 Summary Metrics")

c1, c2, c3 = st.columns(3)
c1.metric("Total Certificates", len(df))
c2.metric("Valid Certificates", len(df[df["status"] == "VALID"]))
c3.metric("Expired Certificates", len(df[df["status"] == "EXPIRED"]))

st.markdown("---")
st.caption("Demo Dashboard • Powered by Streamlit 🔒")
from io import BytesIO
from datetime import datetime
from mock_data_certificate import certs_df

# --- Streamlit page config ---
st.set_page_config(page_title="Certificate Dashboard", layout="wide")

st.title("Certificate Dashboard")
st.write("Monitor certificate status and download certificates if expiring soon or expired.")

# --- Helper to color-code status ---
def color_status(val):
    if val == "VALID":
        return 'background-color: #d4edda;'  # green
    elif val == "EXPIRING_SOON":
        return 'background-color: #fff3cd;'  # yellow
    elif val == "EXPIRED":
        return 'background-color: #f8d7da;'  # red
    return ''

# --- Display certificate table with styles ---
st.subheader("Certificates Overview")
styled_df = certs_df.style.applymap(color_status, subset=["status"])
st.dataframe(styled_df, height=300)

# --- Add Download button per certificate ---
st.subheader("Download Certificates")
for idx, row in certs_df.iterrows():
    domain = row['domain']
    status = row['status']
    
    # Only allow download for EXPIRING_SOON or EXPIRED certs
    if status in ["EXPIRING_SOON", "EXPIRED"]:
        cert_content = f"Certificate for {domain}\nStatus: {status}\nExpiry: {row['expiry_date']}"
        cert_bytes = BytesIO(cert_content.encode('utf-8'))
        
        st.download_button(
            label=f"Download {domain} certificate",
            data=cert_bytes,
            file_name=f"{domain}_cert.txt",
            mime="text/plain"
        )

# --- Footer ---
st.markdown("---")
st.markdown(f"Last update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

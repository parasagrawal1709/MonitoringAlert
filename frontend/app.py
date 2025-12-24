import streamlit as st
from api_client import start_agent, stop_agent, simulate_incident, fetch_incidents

st.set_page_config(layout="wide")
st.title("🧠 Agent Automation Demo")

tabs = st.tabs(["Agent Console", "Live Feed & Evidence"])

# ---------------- Agent Console ----------------
with tabs[0]:
    st.header("Agent Console")

    env = st.selectbox("Environment", ["Linux"])
    monitors = st.multiselect(
        "Monitors", ["CPU", "Memory", "Disk", "Process", "Port/Service"]
    )
    keywords = st.text_input("Keywords", "process: java.exe")

    cpu_threshold = st.number_input("CPU Threshold (%)", value=95)
    duration = st.number_input("Duration (seconds)", value=300)

    remediation = st.selectbox(
        "Remediation Rule",
        ["Restart Service", "Kill & Restart Process", "Notify Only"]
    )

    with st.expander("SMTP Settings"):
        st.text_input("SMTP Host")
        st.text_input("Port")
        st.checkbox("TLS/SSL")
        st.text_input("Sender")
        st.text_input("Recipients")

    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("▶ Start Agent"):
            start_agent({"env": env})
            st.success("Agent started")

    with col2:
        if st.button("⚠ Simulate Incident"):
            simulate_incident()
            st.warning("Incident simulated")

    with col3:
        if st.button("⏹ Stop Agent"):
            stop_agent()
            st.info("Agent stopped")

# ---------------- Live Feed ----------------
with tabs[1]:
    st.header("Live Feed & Evidence")

    incidents = fetch_incidents()

    for inc in reversed(incidents):
        st.markdown("### 🚨 Incident")
        st.json(inc)

import streamlit as st
from api_client import start_agent, stop_agent, simulate_incident, fetch_incidents
# --------- ADDITIONAL IMPORTS (safe, no backend dependency) ----------
from datetime import datetime
import json

st.set_page_config(
    page_title="Agent Automation",
    layout="centered",   # 👈 important for login
)

st.markdown("""
<style>
html, body {
    margin: 0;
    height: 100%;
}
                        
.main .block-container {
    padding: 0 !important;
    max-width: 100% !important;
}
            
/* Center the login container */
.login-wrapper {
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100%;
}

/* Login card */
.login-card {
    width: 380px;
    padding: 2.5rem;
    border-radius: 14px;
    background: #0f1117;
    box-shadow: 0 8px 30px rgba(0,0,0,0.4);
}

/* Title */
.login-card h1 {
    text-align: center;
    margin-bottom: 1.5rem;
}

/* Input spacing */
.login-card .stTextInput {
    margin-bottom: 1rem;
}

/* Button full width */
.login-card button {
    width: 100%;
    border-radius: 8px;
}
</style>
""", unsafe_allow_html=True)
# ---------------- LOGIN CONFIG (UI-only demo) ----------------
USERS = {
    "admin@example.com": {
        "password": "admin123",
        "access": "write"
    },
    "viewer@example.com": {
        "password": "viewer123",
        "access": "read"
    }
}

# Initialize session
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user_email = None
    st.session_state.access_level = None


def login_page():
    st.markdown('<div class="login-wrapper"><div class="login-card">', unsafe_allow_html=True)

    st.markdown("## 🔐 Login")

    email = st.text_input("Email", placeholder="Email address or phone number")
    password = st.text_input("Password", type="password", placeholder="Password")

    if st.button("Log in"):
        user = USERS.get(email)
        if user and user["password"] == password:
            st.session_state.logged_in = True
            st.session_state.user_email = email
            st.session_state.access_level = user["access"]
            st.success("Login successful 🚀")
            st.rerun()
        else:
            st.error("Invalid email or password")

    st.markdown(
        "<p style='text-align:center; margin-top:1rem; color:#4da3ff;'>Forgotten password?</p>",
        unsafe_allow_html=True
    )

    st.markdown('</div></div>', unsafe_allow_html=True)




# st.set_page_config(layout="wide")
def main_app():
    st.title("🧠 Agent Automation Demo")

    st.caption(
        f"Logged in as **{st.session_state.user_email}** "
        f"({st.session_state.access_level.upper()} access)"
    )

    tabs = st.tabs(["Agent Console", "Live Feed &amp; Evidence"])

    # ---------------- Agent Console ----------------
    with tabs[0]:
        st.header("Agent Console")

        env = st.selectbox("Environment", ["Linux"])
        monitors = st.multiselect(
            "Monitors", ["CPU", "Memory", "Disk", "Process", "Port/Service", "All Monitoring Logs"]
        )
        keywords = st.text_input("Keywords", "process: java.exe")

        cpu_threshold = st.number_input("CPU Threshold (%)", value=95)
        duration = st.number_input("Duration (seconds)", value=300)

        remediation = st.selectbox(
            "Remediation Rule",
            ["Restart Service", "Kill &amp; Restart Process", "Notify Only", "Vulnerability Mitigation via Agentic Flow"]
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

        # ===================== ADD-ON: AUTOSYS + DEPLOYMENTS (UI ONLY) =====================
        st.divider()
        st.subheader("🧷 Additional Integrations (UI-only)")

        integ_tabs = st.tabs(["🔁 AutoSys", "🚀 Deployments", "📦 Preset / Summary","🗑️ Deletions"])

        # -------- AutoSys Section --------
        with integ_tabs[0]:
            st.markdown("### 🔁 AutoSys Monitoring (Additional Fields)")
            a1, a2, a3 = st.columns(3)

            with a1:
                autosys_enabled = st.checkbox("Enable AutoSys Monitoring", value=False)
                autosys_host = st.text_input("AutoSys Scheduler Host", value="")
                autosys_instance = st.text_input("AutoSys Instance / Cell (optional)", value="")
            with a2:
                autosys_job_filter = st.text_input("Job Name / Pattern", value="*")
                autosys_box_filter = st.text_input("Box Name (optional)", value="")
                autosys_lookback_hrs = st.number_input("Lookback Window (hours)", value=24, min_value=1)
            with a3:
                autosys_status = st.multiselect(
                    "Job Status Filter",
                    ["SUCCESS", "FAILURE", "RUNNING", "ON_HOLD", "TERMINATED", "INACTIVE", "UNKNOWN"],
                    default=["FAILURE", "TERMINATED"]
                )
                autosys_collect_output = st.checkbox("Collect Job Output (Evidence)", value=True)
                autosys_collect_alarm = st.checkbox("Collect Alarm Details", value=True)

            with st.expander("Advanced AutoSys Settings"):
                autosys_cli_cmd = st.text_input("AutoSys CLI Command Template (optional)", value="autorep -J {job} -r -q")
                autosys_alarm_cmd = st.text_input("Alarm Query Template (optional)", value="autostatus -J {job}")
                autosys_tags = st.text_input("Tags (comma-separated)", value="batch,autosys")

            st.caption("Tip: These fields are UI-only until wired into your backend agent/API payload.")

        # -------- Deployments Section --------
        with integ_tabs[1]:
            st.markdown("### 🚀 Deployment Tracking (Additional Fields)")
            d1, d2, d3 = st.columns(3)

            with d1:
                deploy_enabled = st.checkbox("Enable Deployment Tracking", value=False)
                deploy_tool = st.selectbox(
                    "Deployment Tool",
                    ["Azure DevOps", "Jenkins", "Argo CD", "GitHub Actions", "GitLab CI", "Spinnaker", "Other"],
                    index=0
                )
                deploy_env = st.selectbox("Deployment Environment", ["Dev", "QA", "UAT", "Prod"], index=1)
            with d2:
                service_name = st.text_input("Service / App Name", value="")
                repo_name = st.text_input("Repo (optional)", value="")
                pipeline_name = st.text_input("Pipeline / Workflow Name (optional)", value="")
            with d3:
                version = st.text_input("Version / Build / Image Tag", value="")
                rollback_strategy = st.selectbox(
                    "Rollback Strategy",
                    ["None", "Auto Rollback on Failure", "Manual Rollback Only", "Blue/Green Switchback", "Canary Rollback"],
                    index=1
                )
                change_ticket = st.text_input("Change Ticket / CRQ (optional)", value="")

            with st.expander("Deployment Evidence Collection"):
                collect_deploy_logs = st.checkbox("Collect Deployment Logs", value=True)
                collect_deploy_metrics = st.checkbox("Collect Post-deploy Metrics", value=True)
                collect_deploy_events = st.checkbox("Collect Cluster/Infra Events", value=False)

            st.caption("Tip: Use this to correlate incidents with deployment activity in your live feed.")

        # -------- Summary + Preset Download/Upload --------
        with integ_tabs[2]:
            st.markdown("### 📦 Configuration Summary & Presets")
            s1, s2, s3 = st.columns(3)
            with s1:
                st.markdown("**Agent Core**")
                st.write({"env": env, "monitors": monitors, "keywords": keywords})
            with s2:
                st.markdown("**AutoSys**")
                st.write({
                    "enabled": autosys_enabled,
                    "host": autosys_host,
                    "instance": autosys_instance,
                    "job_filter": autosys_job_filter,
                    "box_filter": autosys_box_filter,
                    "lookback_hours": autosys_lookback_hrs,
                    "status_filter": autosys_status,
                    "collect_output": autosys_collect_output,
                    "collect_alarm": autosys_collect_alarm,
                })
            with s3:
                st.markdown("**Deployments**")
                st.write({
                    "enabled": deploy_enabled,
                    "tool": deploy_tool,
                    "environment": deploy_env,
                    "service": service_name,
                    "repo": repo_name,
                    "pipeline": pipeline_name,
                    "version": version,
                    "rollback_strategy": rollback_strategy,
                    "change_ticket": change_ticket,
                    "collect_logs": collect_deploy_logs,
                    "collect_metrics": collect_deploy_metrics,
                    "collect_events": collect_deploy_events,
                })

            preset_name = st.text_input("Preset Name", value="default")

            preset_payload = {
                "agent": {
                    "env": env,
                    "monitors": monitors,
                    "keywords": keywords,
                    "cpu_threshold": cpu_threshold,
                    "duration": duration,
                    "remediation": remediation,
                },
                "autosys": {
                    "enabled": autosys_enabled,
                    "host": autosys_host,
                    "instance": autosys_instance,
                    "job_filter": autosys_job_filter,
                    "box_filter": autosys_box_filter,
                    "lookback_hours": autosys_lookback_hrs,
                    "status_filter": autosys_status,
                    "collect_output": autosys_collect_output,
                    "collect_alarm": autosys_collect_alarm,
                },
                "deployments": {
                    "enabled": deploy_enabled,
                    "tool": deploy_tool,
                    "environment": deploy_env,
                    "service": service_name,
                    "repo": repo_name,
                    "pipeline": pipeline_name,
                    "version": version,
                    "rollback_strategy": rollback_strategy,
                    "change_ticket": change_ticket,
                    "collect_logs": collect_deploy_logs,
                    "collect_metrics": collect_deploy_metrics,
                    "collect_events": collect_deploy_events,
                },
                "meta": {"saved_at": datetime.utcnow().isoformat() + "Z"},
            }

            p1, p2 = st.columns(2)
            with p1:
                st.download_button(
                    "⬇️ Download Preset JSON",
                    data=json.dumps(preset_payload, indent=2),
                    file_name=f"{preset_name}.json",
                    mime="application/json"
                )
            with p2:
                uploaded = st.file_uploader("⬆️ Upload Preset JSON", type=["json"])
                if uploaded:
                    st.info("Preset uploaded (UI-only). You can parse & apply values later if needed.")
        
        # -------- Deletions Section --------
        with integ_tabs[3]:
            st.markdown("### 🗑️ Deletion & Retention Settings (UI-only)")

            d1, d2 = st.columns(2)

            with d1:
                disk_threshold = st.slider(
                    "Disk Threshold (%)",
                    min_value=0,
                    max_value=100,
                    value=80,
                    help="Trigger deletion when disk usage crosses this threshold"
                )

                retention_days = st.selectbox(
                    "Retention Period",
                    ["1 day", "2 days", "3 days", "4 days", "5 days"],
                    index=2
                )

                webhook_url = st.text_input(
                    "Webhook URL (optional)",
                    placeholder="https://hooks.example.com/..."
                )

            with d2:
                alert_email = st.text_input(
                    "Alert Email ID",
                    placeholder="alerts@example.com"
                )

                llm_model = st.selectbox(
                    "LLM Model",
                    ["OpenAI", "Gemini"],
                    index=0
                )

                confluence_url = st.text_input(
                    "Confluence Page URL",
                    placeholder="https://confluence.company.com/..."
                )

            st.caption(
                "ℹ️ These settings are UI-only. Wire them into your backend deletion / cleanup agent when ready."
            )

        # ===================== END ADD-ON =====================


    # ---------------- Live Feed ----------------
    with tabs[1]:
        st.header("Live Feed &amp; Evidence")

        try:
            incidents = fetch_incidents()
        except Exception as e:
            st.warning("⚠ Backend not running. Showing empty incident list.")
            incidents = []

        for inc in reversed(incidents):
            st.markdown("### 🚨 Incident")
            st.json(inc)

        # ===================== ADD-ON: AUTOSYS + DEPLOYMENTS LIVE PANELS =====================
        st.divider()
        st.subheader("📡 Correlation Panels: AutoSys + Deployments (UI-only)")

        # session_state stores for demo entries (does not affect backend)
        if "autosys_events" not in st.session_state:
            st.session_state.autosys_events = []
        if "deployment_events" not in st.session_state:
            st.session_state.deployment_events = []

        top1, top2, top3, top4 = st.columns(4)
        with top1:
            st.metric("Incidents", len(incidents) if isinstance(incidents, list) else 0)
        with top2:
            st.metric("AutoSys Events (UI)", len(st.session_state.autosys_events))
        with top3:
            st.metric("Deployments (UI)", len(st.session_state.deployment_events))
        with top4:
            if st.button("🔄 Refresh Page"):
                st.rerun()

        left, right = st.columns([1, 1])

        # -------- AutoSys Live Panel --------
        with left:
            st.markdown("### 🔁 AutoSys Evidence")
            with st.expander("Add AutoSys Event (Demo / UI-only)", expanded=False):
                job = st.text_input("Job Name", value="example_job", key="as_job")
                box = st.text_input("Box", value="", key="as_box")
                status = st.selectbox("Status", ["FAILURE", "SUCCESS", "RUNNING", "TERMINATED", "ON_HOLD"], key="as_status")
                run_id = st.text_input("Run ID (optional)", value="", key="as_runid")
                message = st.text_area("Message / Error", value="Job failed due to non-zero exit code", key="as_msg")
                if st.button("➕ Add AutoSys Event", key="as_add"):
                    st.session_state.autosys_events.append({
                        "time": datetime.utcnow().isoformat() + "Z",
                        "job": job,
                        "box": box,
                        "status": status,
                        "run_id": run_id,
                        "message": message,
                    })
                    st.success("AutoSys event added (UI-only).")

            # Filters
            f1, f2 = st.columns(2)
            with f1:
                as_status_filter = st.multiselect(
                    "Filter Status",
                    ["FAILURE", "SUCCESS", "RUNNING", "TERMINATED", "ON_HOLD"],
                    default=["FAILURE", "TERMINATED"],
                    key="as_filter_status"
                )
            with f2:
                as_search = st.text_input("Search (job/message)", value="", key="as_search")

            def autosys_match(e):
                if as_status_filter and e.get("status") not in as_status_filter:
                    return False
                if as_search.strip():
                    blob = (str(e.get("job", "")) + " " + str(e.get("message", ""))).lower()
                    if as_search.lower() not in blob:
                        return False
                return True

            filtered_as = [e for e in st.session_state.autosys_events if autosys_match(e)]

            if filtered_as:
                st.dataframe(filtered_as, use_container_width=True, hide_index=True)
                st.download_button(
                    "⬇️ Download AutoSys Evidence (JSON)",
                    data=json.dumps(filtered_as, indent=2),
                    file_name="autosys_evidence.json",
                    mime="application/json"
                )
            else:
                st.info("No AutoSys events yet (or none match filters).")

        # -------- Deployments Live Panel --------
        with right:
            st.markdown("### 🚀 Deployment Evidence")
            with st.expander("Add Deployment Event (Demo / UI-only)", expanded=False):
                tool = st.selectbox("Tool", ["Azure DevOps", "Jenkins", "Argo CD", "GitHub Actions", "GitLab CI", "Other"], key="dep_tool")
                env2 = st.selectbox("Environment", ["Dev", "QA", "UAT", "Prod"], index=1, key="dep_env")
                service = st.text_input("Service", value="example-service", key="dep_service")
                version2 = st.text_input("Version/Build", value="1.0.0", key="dep_ver")
                result = st.selectbox("Result", ["SUCCESS", "FAILED", "IN_PROGRESS"], key="dep_result")
                link = st.text_input("Pipeline/Run Link (optional)", value="", key="dep_link")
                notes = st.text_area("Notes", value="Deployment triggered before incident spike", key="dep_notes")
                if st.button("➕ Add Deployment Event", key="dep_add"):
                    st.session_state.deployment_events.append({
                        "time": datetime.utcnow().isoformat() + "Z",
                        "tool": tool,
                        "environment": env2,
                        "service": service,
                        "version": version2,
                        "result": result,
                        "link": link,
                        "notes": notes,
                    })
                    st.success("Deployment event added (UI-only).")

            # Filters
            d1, d2, d3 = st.columns(3)
            with d1:
                dep_env_filter = st.selectbox("Filter Env", ["All", "Dev", "QA", "UAT", "Prod"], index=0, key="dep_filter_env")
            with d2:
                dep_result_filter = st.multiselect("Filter Result", ["SUCCESS", "FAILED", "IN_PROGRESS"], default=["FAILED"], key="dep_filter_res")
            with d3:
                dep_search = st.text_input("Search (service/version)", value="", key="dep_search")

            def dep_match(e):
                if dep_env_filter != "All" and e.get("environment") != dep_env_filter:
                    return False
                if dep_result_filter and e.get("result") not in dep_result_filter:
                    return False
                if dep_search.strip():
                    blob = (str(e.get("service", "")) + " " + str(e.get("version", ""))).lower()
                    if dep_search.lower() not in blob:
                        return False
                return True

            filtered_dep = [e for e in st.session_state.deployment_events if dep_match(e)]

            if filtered_dep:
                st.dataframe(filtered_dep, use_container_width=True, hide_index=True)
                st.download_button(
                    "⬇️ Download Deployment Evidence (JSON)",
                    data=json.dumps(filtered_dep, indent=2),
                    file_name="deployment_evidence.json",
                    mime="application/json"
                )
            else:
                st.info("No deployment events yet (or none match filters).")

        # -------- Optional correlation helper (UI-only) --------
        st.divider()
        st.subheader("🧠 Quick Correlation Helper (UI-only)")

        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### AutoSys ↔ Incident Keywords")
            st.write("If you see failures in specific batch jobs, try adding job name into **Keywords** on the console.")
            st.code("process: java.exe OR job: example_job", language="text")

        with c2:
            st.markdown("#### Deployments ↔ Incident Timing")
            st.write("Compare deployment timestamps with incident spike time; add build/version to evidence notes.")
            st.code("deployment.version: 1.0.0", language="text")
        # ===================== END ADD-ON =====================

if not st.session_state.logged_in:
    login_page()
else:
    main_app()


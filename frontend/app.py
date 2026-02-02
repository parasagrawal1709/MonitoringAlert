

import random
import streamlit as st
import pandas as pd

from api_client import (
    # ✅ SAFE wrappers (return ok, data, err)
    start_agent_safe,
    stop_agent_safe,
    simulate_incident_safe,
    # ✅ friend-compatible fetch (returns list)
    fetch_incidents,
    # ✅ health (returns ok_healthy, data, err)
    backend_health_status,
)

# --------- ADDITIONAL IMPORTS (safe, no backend dependency) ----------
from datetime import datetime, timezone
import json
import time as pytime

# --------- IMPORTS (for running local agent.py) ----------
import os
import sys
import time
import subprocess
from pathlib import Path


# =========================================================
# Streamlit Page Config (MUST be first Streamlit call)
# =========================================================
st.set_page_config(
    page_title="Agent Automation",
    layout="centered",
)


# =========================================================
# Helper Functions (friend's)
# =========================================================
def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def generate_random_tags():
    tag_pool = [
        "deploy",
        "hotfix",
        "canary",
        "blue-green",
        "rollback-ready",
        "prod-safe",
        "infra-change",
        "config-update",
        "zero-downtime",
        "observability",
        "slo-impact",
        "customer-facing",
    ]
    return random.sample(tag_pool, k=random.randint(2, 5))


def external_search_fallback(query):
    return (
        "🔍 I couldn’t find this in UI data or the vulnerability KB.\n\n"
        "This will be fetched via Google / Web Search in the next phase.\n\n"
        f"**Query:** {query}"
    )


def generate_commit_hash(length=40):
    return "".join(random.choices("0123456789abcdef", k=length))


@st.cache_data
def load_vulnerability_kb(EXCEL_URL):
    try:
        df = pd.read_excel(EXCEL_URL)
        df.columns = [c.lower() for c in df.columns]
        return df
    except Exception:
        return None


def chatbot_answer_engine(user_query, ui_context, vuln_df=None):
    query = user_query.lower()

    # -------- CERTIFICATES --------
    if "certificate" in query:
        certs = ui_context.get("certificates", [])
        if not certs:
            return "No certificate data found."

        if "expired" in query:
            expired = [c for c in certs if c.get("status") == "expired"]
            return expired if expired else "No expired certificates."

        if "renewed" in query or "valid" in query:
            valid = [c for c in certs if c.get("status") == "valid"]
            return valid if valid else "No valid certificates."

        return certs

    # -------- DEPLOYMENTS --------
    if "deployment" in query or "server" in query:
        return ui_context.get("deployments", "No deployment info available.")

    # -------- DISK ISSUES --------
    if "disk" in query or "space" in query:
        return ui_context.get("disk_issues", "No disk issues recorded.")

    # ---------- EXCEL KB LOOKUP ----------
    if vuln_df is not None:
        matches = vuln_df[vuln_df.apply(lambda row: query in str(row).lower(), axis=1)]
        if not matches.empty:
            return matches.head(3).to_dict(orient="records")

    return "NOT_FOUND"


def format_bot_response(answer):
    if isinstance(answer, str):
        return answer

    if isinstance(answer, list):
        formatted = ""
        for item in answer:
            if "issue" in item:
                formatted += (
                    f"🛑 **Disk Space Alert**\n"
                    f"- **Server:** {item.get('server')}\n"
                    f"- **Time:** {item.get('date')}\n"
                    f"- **Issue:** {item.get('issue')}\n"
                    f"- **Steps:**\n"
                )
                for step in item.get("steps", []):
                    formatted += f" • {step}\n"
                formatted += "\n"

            elif "expiry" in item:
                formatted += (
                    f"🔐 **Certificate:** {item.get('name')}\n"
                    f"- Status: {item.get('status')}\n"
                    f"- Expiry: {item.get('expiry')}\n\n"
                )

            elif "version" in item:
                formatted += (
                    f"🚀 **Deployment**\n"
                    f"- Server: {item.get('server')}\n"
                    f"- Version: {item.get('version')}\n"
                    f"- Time: {item.get('time')}\n\n"
                )

            else:
                formatted += "🛡 **Vulnerability Info**\n"
                for k, v in item.items():
                    formatted += f"- {k}: {v}\n"
                formatted += "\n"

        return formatted if formatted else "No relevant data found."

    return str(answer)


# =========================================================
# Local Agent (agent.py) runner helpers (your version)
# =========================================================
def _project_root() -> Path:
    # frontend/app.py -> frontend -> project root
    return Path(__file__).resolve().parent.parent


def _backend_dir() -> Path:
    return _project_root() / "backend"


def _agent_py_path() -> Path:
    return _backend_dir() / "agent.py"


def _agent_log_path() -> Path:
    return _backend_dir() / "agent_run.log"


def _agent_is_running() -> bool:
    p = st.session_state.get("agent_proc")
    return p is not None and p.poll() is None


def _start_local_agent():
    """
    Starts backend/agent.py in background.
    Ensures cwd=backend so .env is found by load_dotenv().
    Writes stdout/stderr to backend/agent_run.log.
    """
    if _agent_is_running():
        p = st.session_state.agent_proc
        return True, {"pid": p.pid, "log": str(st.session_state.agent_log_path)}, None

    agent_py = _agent_py_path()
    backend_cwd = _backend_dir()

    if not backend_cwd.exists():
        return False, None, f"Backend folder not found: {backend_cwd}"
    if not agent_py.exists():
        return False, None, f"agent.py not found: {agent_py}"

    log_path = _agent_log_path()

    try:
        logf = open(log_path, "a", encoding="utf-8")
        env = os.environ.copy()

        p = subprocess.Popen(
            [sys.executable, "-u", str(agent_py.name)],
            cwd=str(backend_cwd),
            stdout=logf,
            stderr=logf,
            env=env,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        )

        st.session_state.agent_proc = p
        st.session_state.agent_log_path = str(log_path)

        time.sleep(1.0)
        if p.poll() is not None:
            return False, {"log": str(log_path)}, f"Agent exited immediately. Check log: {log_path}"

        return True, {"pid": p.pid, "log": str(log_path)}, None

    except Exception as e:
        return False, None, str(e)


def _stop_local_agent():
    """Stops the background agent process if running."""
    p = st.session_state.get("agent_proc")
    if p is None:
        return True, None, "Agent was not running."

    try:
        if p.poll() is None:
            p.terminate()
            time.sleep(0.5)

        st.session_state.agent_proc = None
        return True, None, None

    except Exception as e:
        return False, None, str(e)


# =========================================================
# Backend Health UI helpers (your version)
# =========================================================
if "backend_health_snapshot" not in st.session_state:
    st.session_state.backend_health_snapshot = None


def _refresh_backend_health():
    ok_h, data_h, err_h = backend_health_status(timeout=(2, 6))
    st.session_state.backend_health_snapshot = {
        "ok": ok_h,
        "data": data_h,
        "err": err_h,
        "ts": datetime.utcnow().isoformat() + "Z",
    }
    return ok_h, data_h, err_h


def _render_backend_status_box():
    snap = st.session_state.get("backend_health_snapshot")

    if not snap:
        ok_h, data_h, err_h = _refresh_backend_health()
    else:
        ok_h, data_h, err_h = snap["ok"], snap["data"], snap["err"]

    if not isinstance(data_h, dict):
        st.warning("Backend status unknown")
        return

    reachable = bool(data_h.get("reachable"))
    healthy = bool(data_h.get("healthy"))
    code = data_h.get("status_code")
    payload = data_h.get("payload") or {}

    if not reachable:
        st.error("Backend UNREACHABLE")
        if err_h:
            st.caption(err_h)
        return

    if healthy:
        st.success("Backend HEALTHY (200)")
        return

    st.warning(f"Backend DOWN / UNHEALTHY ({code})")
    if isinstance(payload, dict) and payload.get("reason"):
        st.caption(f"Reason: {payload.get('reason')}")
    elif isinstance(payload, dict) and payload.get("raw"):
        st.caption(str(payload.get("raw"))[:250])
    else:
        st.caption(str(payload)[:250])


def _coerce_incidents_response():
    """
    Supports both:
      A) fetch_incidents() -> list
      B) fetch_incidents() -> (ok, list, err)
    """
    try:
        res = fetch_incidents()
        if isinstance(res, tuple) and len(res) == 3:
            ok, incidents, err = res
            if not ok:
                return False, [], err
            return True, incidents if isinstance(incidents, list) else [], None

        if isinstance(res, list):
            return True, res, None

        return False, [], "Unexpected incidents response type."

    except Exception as e:
        return False, [], str(e)


# =========================================================
# CSS (combined: bubble chat + login card)
# =========================================================
st.markdown(
    """
<style>
html, body { margin: 0; height: 100%; }
.main .block-container { padding: 0 !important; max-width: 100% !important; }

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
.login-card h1 { text-align: center; margin-bottom: 1.5rem; }

/* Input spacing */
.login-card .stTextInput { margin-bottom: 1rem; }

/* Button full width */
.login-card button { width: 100%; border-radius: 8px; }

/* Chat container spacing */
section[data-testid="stChatMessage"] { padding: 0.6rem 1rem; }

/* User bubble */
div[data-testid="stChatMessage"][aria-label="Chat message from user"] {
  background: linear-gradient(135deg, #4f7cff, #6c8cff);
  color: white;
  border-radius: 14px;
  margin-left: 20%;
}

/* Assistant bubble */
div[data-testid="stChatMessage"][aria-label="Chat message from assistant"] {
  background: #1e1e26;
  color: #eaeaf0;
  border-radius: 14px;
  margin-right: 20%;
}

/* Input bar */
textarea { border-radius: 12px !important; }
</style>
""",
    unsafe_allow_html=True,
)


# =========================================================
# LOGIN CONFIG (union of both)
# =========================================================
USERS = {
    "admin@example.com": {"password": "admin123", "access": "write"},
    "viewer@example.com": {"password": "viewer123", "access": "read"},
    "viewer_ey@example.com": {"password": "viewerey123", "access": "write"},
    "root@example.com": {"password": "root123", "access": "write"},
}

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user_email = None
    st.session_state.access_level = None

# Local agent state
if "agent_proc" not in st.session_state:
    st.session_state.agent_proc = None
if "agent_log_path" not in st.session_state:
    st.session_state.agent_log_path = None


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
        unsafe_allow_html=True,
    )
    st.markdown("</div></div>", unsafe_allow_html=True)


# =========================================================
# Main App
# =========================================================
def main_app():
    st.title("🧠 Agent Automation Demo")
    st.caption(
        f"Logged in as **{st.session_state.user_email}** "
        f"({st.session_state.access_level.upper()} access)"
    )

    # ---------------- Excel Vulnerability KB ----------------
    EXCEL_URL = "https://raw.githubusercontent.com/abhigyanpal1/sre-agent-kb-demo/main/CWE_Knowledge_Base.xlsx"
    if "vuln_df" not in st.session_state:
        st.session_state.vuln_df = load_vulnerability_kb(EXCEL_URL)

    # ✅ CENTRAL UI DATA STORE
    if "ui_state" not in st.session_state:
        st.session_state.ui_state = {
            "certificates": [
                {"name": "ui-cert", "status": "valid", "expiry": "2026-01-10"},
                {"name": "api-cert", "status": "expired", "expiry": "2025-01-01"},
            ],
            "deployments": [
                {"server": "prod-server-1", "version": "1.0.3", "time": "2026-01-20"}
            ],
            "disk_issues": [
                {
                    "server": "prod-server-1",
                    "date": "2026-01-22 14:30",
                    "issue": "Disk usage 92%",
                    "steps": ["Check /var/log size", "Rotate logs", "Clean temp files"],
                }
            ],
        }

    tabs = st.tabs(["Agent Console", "Live Feed & Evidence", "Ops Chatbot"])

    # =========================================================
    # Tab 0: Agent Console
    # =========================================================
    with tabs[0]:
        st.header("Agent Console")

        env = st.selectbox("Environment", ["Linux"])
        monitors = st.multiselect(
            "Monitors",
            ["CPU", "Memory", "Disk", "Process", "Port/Service", "All Monitoring Logs"],
        )
        keywords = st.text_input("Keywords", "process: java.exe")
        cpu_threshold = st.number_input("CPU Threshold (%)", value=95)
        duration = st.number_input("Duration (seconds)", value=300)
        remediation = st.selectbox(
            "Remediation Rule",
            [
                "Restart Service",
                "Kill & Restart Process",
                "Notify Only",
                "Vulnerability Mitigation via Agentic Flow",
            ],
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
                # 1) Start LOCAL agent.py
                ok_local, data_local, err_local = _start_local_agent()
                if not ok_local:
                    st.error(f"Failed to start local agent.py: {err_local}")
                    if data_local and data_local.get("log"):
                        st.caption(f"Check log: {data_local['log']}")
                else:
                    st.success(f"Local agent.py started (PID: {data_local.get('pid')})")
                    if data_local.get("log"):
                        st.caption(f"Agent log: {data_local['log']}")

                # 2) Backend start (SAFE wrapper)
                ok, data, err = start_agent_safe({"env": env})
                if ok:
                    st.success("Backend start invoked")
                else:
                    st.error(f"Backend start failed: {err}")

                _refresh_backend_health()

        with col2:
            if st.button("⚠ Simulate Incident"):
                ok, data, err = simulate_incident_safe()
                if ok:
                    st.warning("Incident simulated")
                else:
                    st.error(f"Failed to simulate incident: {err}")

                _refresh_backend_health()

        with col3:
            if st.button("⏹ Stop Agent"):
                # 1) Stop LOCAL agent.py
                ok_local, _, err_local = _stop_local_agent()
                if ok_local:
                    st.info("Local agent.py stopped")
                else:
                    st.error(f"Failed to stop local agent.py: {err_local}")

                # 2) Backend stop (SAFE wrapper)
                ok, data, err = stop_agent_safe()
                if ok:
                    st.info("Backend stop invoked")
                else:
                    st.error(f"Backend stop failed: {err}")

                _refresh_backend_health()

        # ✅ Backend status panel
        st.divider()
        _render_backend_status_box()
        if st.session_state.get("agent_log_path"):
            st.caption(f"Agent log: {st.session_state.agent_log_path}")

        # ===================== ADD-ON: AUTOSYS + DEPLOYMENTS (UI ONLY) =====================
        st.divider()
        st.subheader("🧷 Additional Integrations (UI-only)")
        integ_tabs = st.tabs(["🔁 AutoSys", "🚀 Deployments", "📦 Preset / Summary", "🗑️ Deletions"])

        # ---------------- AutoSys Section ----------------
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
                    default=["FAILURE", "TERMINATED"],
                )
                autosys_collect_output = st.checkbox("Collect Job Output (Evidence)", value=True)
                autosys_collect_alarm = st.checkbox("Collect Alarm Details", value=True)

            with st.expander("Advanced AutoSys Settings"):
                st.text_input("AutoSys CLI Command Template (optional)", value="autorep -J {job} -r -q")
                st.text_input("Alarm Query Template (optional)", value="autostatus -J {job}")
                st.text_input("Tags (comma-separated)", value="batch,autosys")

            st.caption("Tip: These fields are UI-only until wired into your backend agent/API payload.")

        # ---------------- Deployments Section (simulated tracker) ----------------
        if "deploy_logs" not in st.session_state:
            st.session_state.deploy_logs = []
        if "deploy_tags" not in st.session_state:
            st.session_state.deploy_tags = []
        if "deploy_version" not in st.session_state:
            st.session_state.deploy_version = ""

        with integ_tabs[1]:
            st.markdown("### 🚀 Deployment Tracking (Additional Fields)")

            d1, d2, d3 = st.columns(3)
            with d1:
                deploy_enabled = st.checkbox("Enable Deployment Tracking", value=False)
                deploy_tool = st.selectbox(
                    "Deployment Tool",
                    ["Azure DevOps", "Jenkins", "Argo CD", "GitHub Actions", "GitLab CI", "Spinnaker", "Other"],
                    index=0,
                )
                deploy_env = st.selectbox("Deployment Environment", ["Dev", "QA", "UAT", "Prod"], index=1)

            with d2:
                service_name = st.text_input("Service / App Name", value="")
                repo_name = st.text_input("Repo (optional)", value="")
                pipeline_name = st.text_input("Pipeline / Workflow Name (optional)", value="")

            with d3:
                version = st.text_input("Version / Build / Image Tag", value=st.session_state.deploy_version)
                rollback_strategy = st.selectbox(
                    "Rollback Strategy",
                    [
                        "None",
                        "Auto Rollback on Failure",
                        "Manual Rollback Only",
                        "Blue/Green Switchback",
                        "Canary Rollback",
                    ],
                    index=1,
                )
                change_ticket = st.text_input("Change Ticket / CRQ (optional)", value="")

            with st.expander("Deployment Evidence Collection"):
                collect_deploy_logs = st.checkbox("Collect Deployment Logs", value=True)
                collect_deploy_metrics = st.checkbox("Collect Post-deploy Metrics", value=True)
                collect_deploy_events = st.checkbox("Collect Cluster/Infra Events", value=False)

            st.caption("Tip: Use this to correlate incidents with deployment activity in your live feed.")
            st.divider()

            track_deploy = st.button("🚀 Track Deployment", use_container_width=True, disabled=not deploy_enabled)

            if track_deploy:
                st.session_state.deploy_logs = []
                st.session_state.deploy_tags = []
                if not st.session_state.deploy_version:
                    st.session_state.deploy_version = generate_commit_hash()

                st.session_state.deploy_logs.append(
                    f"{utc_now()} | DEPLOY_START | "
                    f"service={service_name or 'unknown'} | env={deploy_env} | "
                    f"tool={deploy_tool} | commit={st.session_state.deploy_version}"
                )

                with st.spinner("Deployment in progress..."):
                    pytime.sleep(30)

                st.session_state.deploy_logs.append(
                    f"{utc_now()} | DEPLOY_SUCCESS | "
                    f"service={service_name or 'unknown'} | commit={st.session_state.deploy_version} | "
                    f"rollback={rollback_strategy}"
                )

                st.session_state.deploy_tags = generate_random_tags()

            if st.session_state.deploy_logs:
                st.markdown("### 📡 Deployment Activity Feed")
                for log in st.session_state.deploy_logs:
                    st.code(log, language="text")

            if st.session_state.deploy_tags:
                st.markdown("### 🏷 Auto-generated Deployment Tags")
                st.multiselect(
                    "Tags",
                    options=st.session_state.deploy_tags,
                    default=st.session_state.deploy_tags,
                    disabled=True,
                )

        # ---------------- Summary + Preset Download/Upload ----------------
        with integ_tabs[2]:
            st.markdown("### 📦 Configuration Summary & Presets")
            s1, s2, s3 = st.columns(3)

            with s1:
                st.markdown("**Agent Core**")
                st.write({"env": env, "monitors": monitors, "keywords": keywords})

            with s2:
                st.markdown("**AutoSys**")
                st.write(
                    {
                        "enabled": autosys_enabled,
                        "host": autosys_host,
                        "instance": autosys_instance,
                        "job_filter": autosys_job_filter,
                        "box_filter": autosys_box_filter,
                        "lookback_hours": autosys_lookback_hrs,
                        "status_filter": autosys_status,
                        "collect_output": autosys_collect_output,
                        "collect_alarm": autosys_collect_alarm,
                    }
                )

            with s3:
                st.markdown("**Deployments**")
                st.write(
                    {
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
                    }
                )

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
                    mime="application/json",
                )
            with p2:
                uploaded = st.file_uploader("⬆️ Upload Preset JSON", type=["json"])
                if uploaded:
                    st.info("Preset uploaded (UI-only). You can parse & apply values later if needed.")

        # ---------------- Deletions: Intelligent + Legacy UI-only ----------------
        with integ_tabs[3]:
            st.markdown("### 🗑️ Intelligent Deletion & Retention Engine")

            if "cleanup_logs" not in st.session_state:
                st.session_state.cleanup_logs = []
            if "cleanup_running" not in st.session_state:
                st.session_state.cleanup_running = False

            c1, c2, c3 = st.columns(3)
            with c1:
                disk_threshold = st.slider("Disk Usage Threshold (%)", 50, 95, 80)
                retention_days = st.selectbox("Retention Policy", ["1 day", "3 days", "7 days", "14 days"], index=1)
            with c2:
                target_dbs = st.multiselect(
                    "Target Databases",
                    ["MongoDB (27017)", "PostgreSQL (5432)", "MySQL (3306)"],
                    default=["PostgreSQL (5432)", "MySQL (3306)"],
                )
                ai_mode = st.selectbox("Cleanup Mode", ["Rule-based", "Agentic AI (Risk-aware)", "Hybrid (Recommended)"], index=2)
            with c3:
                st.text_input("Alert Email (optional)")
                st.text_input("Webhook (optional)")

            st.divider()
            trigger_cleanup = st.button("🚀 Execute Intelligent Cleanup", use_container_width=True, disabled=st.session_state.cleanup_running)

            if trigger_cleanup:
                st.session_state.cleanup_logs = []
                st.session_state.cleanup_running = True
                retention_val = int(retention_days.split()[0])

                def log(msg):
                    st.session_state.cleanup_logs.append(f"{utc_now()} | {msg}")

                with st.spinner("Agent initializing cleanup strategy..."):
                    pytime.sleep(1.5)
                log("AGENT_INIT | policy_loaded=true | ai_mode=" + ai_mode)

                with st.spinner("Scanning databases & filesystem..."):
                    pytime.sleep(2)
                log(f"SCAN_START | disk_threshold={disk_threshold} | retention={retention_val}d")

                if "MongoDB (27017)" in target_dbs:
                    log("SCAN_DB | mongodb:27017 | collections_scanned=214 | stale_docs=19k")
                if "PostgreSQL (5432)" in target_dbs:
                    log("SCAN_DB | postgres:5432 | temp_tables=42 | old_indexes=11")
                if "MySQL (3306)" in target_dbs:
                    log("SCAN_DB | mysql:3306 | tmp_tables=31 | orphan_rows=8k")

                log("SCAN_FS | /tmp | files=3.1GB | candidates=1.4GB")
                log("SCAN_FS | /var/tmp | cache_entries=842 | size=620MB")

                with st.spinner("Agent evaluating deletion risk & compliance..."):
                    pytime.sleep(2)
                log("AI_EVAL | retention_compliant=true | risk_score=LOW")
                log("AI_DECISION | delete_safe=true | requires_approval=false")

                with st.spinner("Executing cleanup operations..."):
                    pytime.sleep(3)
                log("DELETE_START | phase=databases")

                if "PostgreSQL (5432)" in target_dbs:
                    log("DELETE_DB | postgres | temp_tables_dropped=38")
                    log("DELETE_DB | postgres | indexes_rebuilt=6")
                if "MySQL (3306)" in target_dbs:
                    log("DELETE_DB | mysql | tmp_tables_purged=29")
                    log("DELETE_DB | mysql | orphan_rows_deleted=7.6k")
                if "MongoDB (27017)" in target_dbs:
                    log("DELETE_DB | mongodb | ttl_collections_cleaned=17")
                    log("DELETE_DB | mongodb | archived_docs_removed=14k")

                log("DELETE_FS | /tmp | reclaimed=1.2GB")
                log("DELETE_FS | /var/tmp | reclaimed=540MB")

                with st.spinner("Verifying system health post-cleanup..."):
                    pytime.sleep(1.5)
                log("VERIFY | disk_usage_after=61%")
                log("VERIFY | db_latency=normal | error_rate=0")
                log("CLEANUP_COMPLETE | status=SUCCESS | agent_confidence=0.94")

                st.session_state.cleanup_running = False
                st.success("✅ Intelligent cleanup completed successfully")

            if st.session_state.cleanup_logs:
                st.markdown("### 📡 Cleanup Activity Feed")
                for entry in st.session_state.cleanup_logs[-20:]:
                    st.code(entry, language="text")

            with st.expander("🧰 Legacy Deletion & Retention Settings (UI-only)"):
                dd1, dd2 = st.columns(2)
                with dd1:
                    st.slider("Disk Threshold (%)", 0, 100, 80, key="legacy_disk_threshold")
                    st.selectbox("Retention Period", ["1 day", "2 days", "3 days", "4 days", "5 days"], index=2, key="legacy_retention_days")
                    st.text_input("Webhook URL (optional)", placeholder="https://hooks.example.com/...", key="legacy_webhook")
                with dd2:
                    st.text_input("Alert Email ID", placeholder="alerts@example.com", key="legacy_alert_email")
                    st.selectbox("LLM Model", ["OpenAI", "Gemini"], index=0, key="legacy_llm")
                    st.text_input("Confluence Page URL", placeholder="https://confluence.company.com/...", key="legacy_confluence")

    # =========================================================
    # Tab 1: Live Feed & Evidence
    # =========================================================
    with tabs[1]:
        st.header("Live Feed & Evidence")

        ok_inc, incidents, err_inc = _coerce_incidents_response()
        if not ok_inc:
            st.warning(f"⚠ Backend error: {err_inc}")
            incidents = []

        for inc in reversed(incidents):
            st.markdown("### 🚨 Incident")
            st.json(inc)

        st.divider()
        st.subheader("Backend Status (Live)")
        if st.button("🔄 Refresh Backend Status"):
            _refresh_backend_health()
        _render_backend_status_box()

        st.divider()
        st.subheader("📡 Correlation Panels: AutoSys + Deployments (UI-only)")

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
                _refresh_backend_health()
                st.rerun()

        left, right = st.columns([1, 1])

        with left:
            st.markdown("### 🔁 AutoSys Evidence")
            with st.expander("Add AutoSys Event (Demo / UI-only)", expanded=False):
                job = st.text_input("Job Name", value="example_job", key="as_job")
                box = st.text_input("Box", value="", key="as_box")
                status = st.selectbox("Status", ["FAILURE", "SUCCESS", "RUNNING", "TERMINATED", "ON_HOLD"], key="as_status")
                run_id = st.text_input("Run ID (optional)", value="", key="as_runid")
                message = st.text_area("Message / Error", value="Job failed due to non-zero exit code", key="as_msg")

                if st.button("➕ Add AutoSys Event", key="as_add"):
                    st.session_state.autosys_events.append(
                        {"time": datetime.utcnow().isoformat() + "Z", "job": job, "box": box, "status": status, "run_id": run_id, "message": message}
                    )
                    st.success("AutoSys event added (UI-only).")

            f1, f2 = st.columns(2)
            with f1:
                as_status_filter = st.multiselect("Filter Status", ["FAILURE", "SUCCESS", "RUNNING", "TERMINATED", "ON_HOLD"], default=["FAILURE", "TERMINATED"], key="as_filter_status")
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
                st.download_button("⬇️ Download AutoSys Evidence (JSON)", data=json.dumps(filtered_as, indent=2), file_name="autosys_evidence.json", mime="application/json")
            else:
                st.info("No AutoSys events yet (or none match filters).")

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
                    st.session_state.deployment_events.append(
                        {"time": datetime.utcnow().isoformat() + "Z", "tool": tool, "environment": env2, "service": service, "version": version2, "result": result, "link": link, "notes": notes}
                    )
                    st.success("Deployment event added (UI-only).")

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
                st.download_button("⬇️ Download Deployment Evidence (JSON)", data=json.dumps(filtered_dep, indent=2), file_name="deployment_evidence.json", mime="application/json")
            else:
                st.info("No deployment events yet (or none match filters).")

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

    # =========================================================
    # Tab 2: Ops Chatbot
    # =========================================================
    with tabs[2]:
        st.header("💬 Ops Chatbot")

        if "messages" not in st.session_state:
            st.session_state.messages = []

        if not st.session_state.messages:
            st.markdown("### 💡 Try asking")
            suggestions = [
                "Which certificates are expired?",
                "Any disk issues today?",
                "What was the last deployment?",
                "Show vulnerabilities related to log",
            ]
            for q in suggestions:
                if st.button(q, use_container_width=True):
                    st.session_state.messages.append({"role": "user", "content": q})
                    raw_answer = chatbot_answer_engine(q, st.session_state.ui_state, st.session_state.vuln_df)
                    if raw_answer == "NOT_FOUND":
                        raw_answer = external_search_fallback(q)
                    formatted_answer = format_bot_response(raw_answer)
                    st.session_state.messages.append({"role": "assistant", "content": formatted_answer})
                    st.rerun()

        for msg in st.session_state.messages:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

        user_query = st.chat_input("Ask me anything about ops…")
        if user_query:
            st.session_state.messages.append({"role": "user", "content": user_query})

            with st.chat_message("assistant"):
                with st.spinner("Thinking…"):
                    raw_answer = chatbot_answer_engine(user_query, st.session_state.ui_state, st.session_state.vuln_df)
                    if raw_answer == "NOT_FOUND":
                        raw_answer = external_search_fallback(user_query)
                    formatted_answer = format_bot_response(raw_answer)

            st.session_state.messages.append({"role": "assistant", "content": formatted_answer})
            st.rerun()


# =========================================================
# Entry
# =========================================================
if not st.session_state.logged_in:
    login_page()
else:
    main_app()

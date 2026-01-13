# agent.py
from dotenv import load_dotenv
load_dotenv()

import os
import requests

from vulnerability_map import VULNERABILITY_MAP
from config import AgentConfig
from monitors.windows_monitors import (
    cpu_high_for,
    disk_usage_pct,
    top_cpu_processes,
)
from actions.windows_actions import clear_temp, try_backend_recover
from templates.email_template import build_email
from email_tool import send_email

# ✅ Gemini diagnosis + email drafting
from llm.gemini_client import diagnose_and_draft

# ✅ NEW: KB loader (Excel from GitHub raw or any direct URL)
from kb.kb_loader import load_kb, lookup_vuln


print(">>> RUNNING agent.py from:", __file__, flush=True)


def check_backend_health(base_url: str) -> dict:
    """
    Checks GET {base_url}/health
    Returns: {"ok": bool, "status_code": int|None, "details": str}
    """
    try:
        r = requests.get(f"{base_url}/health", timeout=3)
        if r.status_code == 200:
            return {"ok": True, "status_code": 200, "details": r.text}
        return {"ok": False, "status_code": r.status_code, "details": r.text}
    except Exception as e:
        return {"ok": False, "status_code": None, "details": f"Unreachable: {e}"}


def get_vuln_mapping_fallback(incident_type: str) -> dict:
    """
    Old fallback: uses local python dict mapping.
    """
    if incident_type in VULNERABILITY_MAP:
        return VULNERABILITY_MAP[incident_type]

    if "Unknown Incident" in VULNERABILITY_MAP:
        return VULNERABILITY_MAP["Unknown Incident"]

    return {
        "cwe": "CWE-1059",
        "title": "Insufficient Technical Impact Assessment",
        "description": "Unable to classify incident type with available evidence.",
        "example_cves": [],
    }


def decide_and_act(cfg: AgentConfig):
    """
    Returns:
      incident, attempts, status, next_steps, evidence
    """
    incident = None
    attempts = []
    next_steps = []
    status = "blocked"
    evidence = {}

    # -------------------------
    # Scenario 1: Backend URL Unhealthy -> attempt self-heal
    # -------------------------
    backend_url = getattr(cfg, "backend_url", None)
    backend_host = getattr(cfg, "backend_host", "127.0.0.1")
    backend_port = getattr(cfg, "backend_port", 8000)
    allow_backend_self_heal = getattr(cfg, "allow_backend_self_heal", False)

    if backend_url:
        health_before = check_backend_health(backend_url)
        evidence["backend_health_before"] = health_before

        if not health_before["ok"]:
            incident = {
                "type": "Backend URL Unhealthy",
                "details": (
                    f"GET {backend_url}/health failed or returned non-200. "
                    f"Details: {health_before}"
                ),
                "severity": "HIGH",
            }

            if allow_backend_self_heal:
                attempts.append(try_backend_recover(backend_url, backend_host, backend_port))

            health_after = check_backend_health(backend_url)
            evidence["backend_health_after"] = health_after

            if health_after["ok"]:
                status = "resolved"
                next_steps = [
                    f"If this repeats, verify the backend process is running and port {backend_port} is open.",
                    "Check Windows Firewall rules if URL is unreachable from other machines.",
                    "Add this check to a scheduled run (Task Scheduler) for periodic monitoring.",
                ]
            else:
                status = "blocked"
                next_steps = [
                    "Confirm backend_app.py exists and uvicorn is installed.",
                    "Try starting manually: py -3.11 -m uvicorn backend_app:app --host 0.0.0.0 --port 8000",
                    "Check if another process is already using the port.",
                ]

            return incident, attempts, status, next_steps, evidence

    # -------------------------
    # Scenario 2: CPU Spike (demo)
    # -------------------------
    if cpu_high_for(cfg.cpu_duration_seconds, cfg.cpu_threshold_pct):
        tops = top_cpu_processes(5)
        incident = {
            "type": "CPU Spike",
            "details": (
                f"CPU > {cfg.cpu_threshold_pct}% for {cfg.cpu_duration_seconds}s. "
                f"Top processes: {tops}"
            ),
            "severity": "HIGH",
        }
        status = "blocked"  # safe demo: no killing processes
        next_steps = [
            "Check Task Manager / Resource Monitor for top CPU processes.",
            "If a known service is misbehaving, restart that service (approved).",
            "Check recent deployments / scheduled tasks that could cause spikes.",
        ]
        return incident, attempts, status, next_steps, evidence

    # -------------------------
    # Scenario 3: Disk Usage High
    # -------------------------
    disk_pct = disk_usage_pct("C:\\")
    if disk_pct >= cfg.disk_threshold_pct:
        incident = {
            "type": "Disk Usage High",
            "details": f"C: drive usage is {disk_pct}%, threshold is {cfg.disk_threshold_pct}%",
            "severity": "MEDIUM",
        }

        evidence["disk_before"] = disk_pct

        if getattr(cfg, "allow_clear_temp", False):
            attempts.append(clear_temp())

        disk_after = disk_usage_pct("C:\\")
        evidence["disk_after"] = disk_after

        if disk_after < cfg.disk_threshold_pct:
            status = "resolved"
            next_steps = [
                "If disk fills again quickly, check large folders (Downloads, Logs, AppData).",
                "Add log rotation / cleanup policy.",
            ]
        else:
            status = "blocked"
            next_steps = [
                "Identify largest directories (WinDirStat / Storage settings).",
                "Archive non-critical files or increase disk size.",
            ]

        return incident, attempts, status, next_steps, evidence

    # -------------------------
    # No incident
    # -------------------------
    incident = {
        "type": "No Incident",
        "details": "No threshold breach detected.",
        "severity": "INFO",
    }
    status = "resolved"
    next_steps = ["No action required."]
    return incident, attempts, status, next_steps, evidence


def main():
    cfg = AgentConfig()

    # -------------------------
    # ✅ KB Config (from ENV)
    # -------------------------
    # Example:
    # KB_URL=https://raw.githubusercontent.com/<user>/<repo>/main/CWE_Knowledge_Base.xlsx
    kb_url = os.getenv("KB_URL", "").strip()
    kb_refresh = os.getenv("KB_REFRESH", "false").strip().lower() in ("1", "true", "yes")
    kb_cache_dir = os.getenv("KB_CACHE_DIR", ".kb_cache").strip() or ".kb_cache"
    kb_filename = os.getenv("KB_FILENAME", "CWE_Knowledge_Base.xlsx").strip() or "CWE_Knowledge_Base.xlsx"

    kb_mapping = {}
    kb_status = {"enabled": False, "ok": False, "error": None, "source": None}

    if kb_url:
        kb_status["enabled"] = True
        kb_res = load_kb(
            kb_url=kb_url,
            cache_dir=kb_cache_dir,
            cache_filename=kb_filename,
            refresh=kb_refresh,
        )
        kb_status["ok"] = kb_res.ok
        kb_status["error"] = kb_res.error
        kb_status["source"] = kb_res.source
        kb_mapping = kb_res.mapping if kb_res.ok else {}

    print("\n========== SRE AI Agent Execution ==========", flush=True)
    print(f"Target Host       : {cfg.host_label}", flush=True)
    print(f"Backend URL       : {getattr(cfg, 'backend_url', 'NOT SET')}", flush=True)
    print(f"CPU Threshold     : {cfg.cpu_threshold_pct}% for {cfg.cpu_duration_seconds}s", flush=True)
    print(f"Disk Threshold    : {cfg.disk_threshold_pct}% (C:)", flush=True)
    print("--------------------------------------------", flush=True)

    if kb_status["enabled"]:
        print("\n[KB Status]", flush=True)
        if kb_status["ok"]:
            print(f"- KB loaded OK from: {kb_status['source']}", flush=True)
        else:
            print(f"- KB load FAILED: {kb_status['error']}", flush=True)

    print("\n[Detection + Remediation]", flush=True)
    incident, attempts, status, next_steps, evidence = decide_and_act(cfg)

    # ✅ Pick vuln mapping: KB first, else fallback python map
    if kb_mapping:
        vuln = lookup_vuln(incident.get("type", "Unknown Incident"), kb_mapping)
        vuln_source = "KB"
    else:
        vuln = get_vuln_mapping_fallback(incident.get("type", "Unknown Incident"))
        vuln_source = "LOCAL_MAP"

    print("\n[Incident Summary]", flush=True)
    print(f"Incident Type     : {incident.get('type')}", flush=True)
    print(f"Severity          : {incident.get('severity')}", flush=True)
    print(f"Details           : {incident.get('details')}", flush=True)

    print("\n[Vulnerability Mapping - from {}]".format(vuln_source), flush=True)
    print(f"CWE Code          : {vuln.get('cwe', 'N/A')}", flush=True)
    print(f"CWE Title         : {vuln.get('title', 'N/A')}", flush=True)
    print(f"CWE Meaning       : {vuln.get('description', 'N/A')}", flush=True)
    if vuln.get("example_cves"):
        print(f"Example CVEs      : {', '.join(vuln['example_cves'][:5])}", flush=True)

    print("\n[Actions Taken]", flush=True)
    if attempts:
        for a in attempts:
            print(f"- {a}", flush=True)
    else:
        print("- None (policy / safety block or not required)", flush=True)

    print("\n[Final Status]", flush=True)
    print(status.upper(), flush=True)

    print("\n[Next Steps / Guidance]", flush=True)
    for step in next_steps:
        print(f"- {step}", flush=True)

    # ---------------------------------------------------------
    # Gemini diagnosis + email drafting (with fallback)
    # ---------------------------------------------------------
    print("\n[LLM Diagnosis + Email Drafting]", flush=True)

    subject = None
    body_html = None

    try:
        draft = diagnose_and_draft(
            incident=incident,
            evidence=evidence,
            attempts=attempts,
            status=status,
            next_steps=next_steps,
            vulnerability=vuln,  # ✅ now coming from KB (or fallback)
            style="concise",
        )

        subject = draft.get("email_subject")
        body_html = draft.get("email_body_html")

        print("\n[LLM Diagnosis]", flush=True)
        print(draft.get("diagnosis", "(no diagnosis text returned)"), flush=True)

        if not subject or not body_html or len(body_html.strip()) < 50:
            raise RuntimeError("Gemini returned empty/invalid subject or email body.")

    except Exception:
        import traceback

        print("Gemini drafting failed -> falling back to template.", flush=True)
        traceback.print_exc()

        subject, body_html = build_email(
            subject_prefix="[SRE-AI]",
            host=cfg.host_label,
            incident=incident,
            attempts=attempts,
            status=status,
            next_steps=next_steps,
            vuln=vuln,
        )

    print("\n[Notification]", flush=True)
    print("Sending email...", flush=True)
    send_email(cfg.to_email, subject, body_html, html=True)
    print("Email sent successfully.", flush=True)

    print("\n========== Execution Completed ==========\n", flush=True)


if __name__ == "__main__":
    main()

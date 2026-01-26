# agent.py
from dotenv import load_dotenv
load_dotenv()

import json
from datetime import datetime
import os
import time
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

# ✅ KB loader
from kb.kb_loader import load_kb, lookup_vuln

print(">>> RUNNING agent.py from:", __file__, flush=True)


# -------------------------
# Backend helpers
# -------------------------
def _verify_ssl_flag() -> bool:
    return os.getenv("VERIFY_SSL", "true").strip().lower() in ("1", "true", "yes")


def _demo_headers() -> dict:
    token = os.getenv("DEMO_TOKEN", "").strip()
    return {"X-Demo-Token": token} if token else {}


def check_backend_health(base_url: str) -> dict:
    try:
        verify_ssl = _verify_ssl_flag()
        r = requests.get(f"{base_url}/health", timeout=5, verify=verify_ssl)
        if r.status_code == 200:
            return {"ok": True, "status_code": 200, "details": r.text}
        return {"ok": False, "status_code": r.status_code, "details": r.text}
    except Exception as e:
        return {"ok": False, "status_code": None, "details": f"Unreachable: {e}"}


def get_remote_cpu_metrics(base_url: str) -> dict:
    try:
        verify_ssl = _verify_ssl_flag()
        r = requests.get(f"{base_url}/metrics/cpu", timeout=5, verify=verify_ssl)
        if r.status_code == 200:
            return {"ok": True, "status_code": 200, "data": r.json()}
        return {"ok": False, "status_code": r.status_code, "details": r.text}
    except Exception as e:
        return {"ok": False, "status_code": None, "details": f"Unreachable: {e}"}


def get_remote_disk_metrics(base_url: str) -> dict:
    try:
        verify_ssl = _verify_ssl_flag()
        r = requests.get(f"{base_url}/metrics/disk", timeout=5, verify=verify_ssl)
        if r.status_code == 200:
            return {"ok": True, "status_code": 200, "data": r.json()}
        return {"ok": False, "status_code": r.status_code, "details": r.text}
    except Exception as e:
        return {"ok": False, "status_code": None, "details": f"Unreachable: {e}"}


def trigger_remote_cpu_burn(base_url: str, seconds: int, workers: int) -> dict:
    try:
        verify_ssl = _verify_ssl_flag()
        r = requests.post(
            f"{base_url}/simulate/cpu",
            params={"seconds": int(seconds), "workers": int(workers)},
            headers=_demo_headers(),
            timeout=15,
            verify=verify_ssl,
        )
        if r.status_code == 200:
            return {"ok": True, "status_code": 200, "data": r.json()}
        return {"ok": False, "status_code": r.status_code, "details": r.text}
    except Exception as e:
        return {"ok": False, "status_code": None, "details": f"Unreachable: {e}"}


def trigger_remote_disk_fill(base_url: str, mb: int) -> dict:
    try:
        verify_ssl = _verify_ssl_flag()
        r = requests.post(
            f"{base_url}/simulate/disk_fill",
            params={"mb": int(mb)},
            headers=_demo_headers(),
            timeout=30,
            verify=verify_ssl,
        )
        if r.status_code == 200:
            return {"ok": True, "status_code": 200, "data": r.json()}
        return {"ok": False, "status_code": r.status_code, "details": r.text}
    except Exception as e:
        return {"ok": False, "status_code": None, "details": f"Unreachable: {e}"}


def trigger_remote_disk_cleanup(base_url: str) -> dict:
    try:
        verify_ssl = _verify_ssl_flag()
        r = requests.post(
            f"{base_url}/simulate/disk_cleanup",
            headers=_demo_headers(),
            timeout=30,
            verify=verify_ssl,
        )
        if r.status_code == 200:
            return {"ok": True, "status_code": 200, "data": r.json()}
        return {"ok": False, "status_code": r.status_code, "details": r.text}
    except Exception as e:
        return {"ok": False, "status_code": None, "details": f"Unreachable: {e}"}


def dedupe_keep_order(items: list) -> list:
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# -------------------------
# Multi-incident helpers
# -------------------------
def add_issue(issues: list, issue_type: str, severity: str, details: str, issue_evidence: dict = None):
    issues.append({
        "type": issue_type,
        "severity": severity,
        "details": details,
        "evidence": issue_evidence or {},
    })


def severity_rank(sev: str) -> int:
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return order.get((sev or "INFO").upper(), 0)


def overall_severity(issues: list) -> str:
    if not issues:
        return "INFO"
    return max(issues, key=lambda x: severity_rank(x.get("severity", "INFO"))).get("severity", "INFO")


def combine_details(issues: list) -> str:
    lines = []
    for i, it in enumerate(issues, start=1):
        lines.append(f"{i}) [{it.get('severity')}] {it.get('type')}: {it.get('details')}")
    return "\n".join(lines) if lines else "No issues."


# -------------------------
# Persistence
# -------------------------
def persist_run(payload: dict):
    os.makedirs("runs", exist_ok=True)
    payload["timestamp"] = datetime.utcnow().isoformat() + "Z"
    with open("runs/latest_incident.json", "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def get_vuln_mapping_fallback(incident_type: str) -> dict:
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
    ✅ FIXES INCLUDED:
    1) "Remediation Attempts" will ONLY contain real remediation actions (self-heal, disk cleanup etc.).
       Simulation actions (cpu_burn, disk_fill) will be stored in evidence["simulations"] instead.
    2) If only 1 issue, incident type becomes that issue (not "Multiple Issues Detected").
    3) If disk is high, agent can run disk_cleanup AND verify disk decreased on Render.
    """
    issues = []
    remediation_attempts = []     # ✅ only remediation actions
    next_steps = []
    evidence = {}
    simulations = {}             # ✅ simulation actions tracked here

    backend_url = getattr(cfg, "backend_url", None)
    backend_host = getattr(cfg, "backend_host", "127.0.0.1")
    backend_port = getattr(cfg, "backend_port", 8000)
    allow_backend_self_heal = getattr(cfg, "allow_backend_self_heal", False)

    # -------------------------
    # Demo knobs (env)
    # -------------------------
    demo_trigger_cpu_burn = os.getenv("DEMO_TRIGGER_REMOTE_CPU_BURN", "false").lower() in ("1", "true", "yes")
    burn_seconds = int(os.getenv("REMOTE_CPU_BURN_SECONDS", "15"))
    burn_workers = int(os.getenv("REMOTE_CPU_BURN_WORKERS", "2"))
    remote_cpu_threshold = float(os.getenv("REMOTE_CPU_THRESHOLD", "85.0"))

    demo_trigger_disk_fill = os.getenv("DEMO_TRIGGER_REMOTE_DISK_FILL", "false").lower() in ("1", "true", "yes")
    remote_disk_fill_mb = int(os.getenv("REMOTE_DISK_FILL_MB", "100"))
    remote_disk_threshold = float(os.getenv("REMOTE_DISK_THRESHOLD", "80.0"))

    # ✅ remediation toggle
    auto_cleanup_disk = os.getenv("AUTO_CLEANUP_REMOTE_DISK", "true").lower() in ("1", "true", "yes")

    post_trigger_wait = float(os.getenv("POST_TRIGGER_WAIT_SECONDS", "2.0"))

    # -------------------------
    # A) Backend health
    # -------------------------
    if backend_url:
        health = check_backend_health(backend_url)
        evidence["backend_health"] = health

        if (health.get("status_code") is None) and (not health.get("ok")):
            add_issue(
                issues,
                issue_type="Backend URL Unhealthy",
                severity="HIGH",
                details=f"Backend not reachable. /health failed: {health}",
                issue_evidence={"backend_health": health},
            )
            if allow_backend_self_heal:
                # ✅ remediation attempt (real)
                res = try_backend_recover(backend_url, backend_host, backend_port)
                remediation_attempts.append(res)
                evidence["backend_health_after"] = check_backend_health(backend_url)

        elif (not health.get("ok")) and (health.get("status_code") is not None):
            add_issue(
                issues,
                issue_type="Health Degraded",
                severity="MEDIUM",
                details=f"/health returned {health.get('status_code')}. Response: {health.get('details')}",
                issue_evidence={"backend_health": health},
            )

    # -------------------------
    # B) Simulation actions (NOT remediation)
    # -------------------------
    if backend_url:
        if demo_trigger_cpu_burn:
            simulations["remote_cpu_burn"] = trigger_remote_cpu_burn(backend_url, burn_seconds, burn_workers)

        if demo_trigger_disk_fill:
            simulations["remote_disk_fill"] = trigger_remote_disk_fill(backend_url, remote_disk_fill_mb)

        if demo_trigger_cpu_burn or demo_trigger_disk_fill:
            time.sleep(max(0.0, post_trigger_wait))

    evidence["simulations"] = simulations

    # -------------------------
    # C) Remote detection (CPU + Disk) -> shown in DETAILS
    # -------------------------
    if backend_url:
        # CPU detection (simple: current reading; you can extend to "5 min" later)
        remote_cpu = get_remote_cpu_metrics(backend_url)
        evidence["remote_cpu_metrics"] = remote_cpu

        if remote_cpu.get("ok") and isinstance(remote_cpu.get("data"), dict):
            cpu_pct = float(remote_cpu["data"].get("cpu_percent", 0.0))
            if cpu_pct >= remote_cpu_threshold:
                add_issue(
                    issues,
                    issue_type="CPU Spike",
                    severity="HIGH",
                    details=f"Remote CPU is {cpu_pct}% (threshold {remote_cpu_threshold}%). Metrics: {remote_cpu['data']}",
                    issue_evidence={"remote_cpu_metrics": remote_cpu},
                )
                next_steps.extend([
                    "Check Render logs for CPU-heavy endpoints during the spike.",
                    "Reduce worker/process count if configured too high.",
                    "Add rate-limits/guardrails on heavy demo endpoints.",
                ])

        # Disk detection
        remote_disk_before = get_remote_disk_metrics(backend_url)
        evidence["remote_disk_metrics_before"] = remote_disk_before

        if remote_disk_before.get("ok") and isinstance(remote_disk_before.get("data"), dict):
            used_pct = float(remote_disk_before["data"].get("used_percent", 0.0))
            if used_pct >= remote_disk_threshold:
                add_issue(
                    issues,
                    issue_type="Disk Usage High",
                    severity="MEDIUM",
                    details=f"Remote disk usage is {used_pct}% (threshold {remote_disk_threshold}%). Metrics: {remote_disk_before['data']}",
                    issue_evidence={"remote_disk_metrics_before": remote_disk_before},
                )
                next_steps.extend([
                    "Run /simulate/disk_cleanup to remove demo disk files.",
                    "Confirm disk usage drops by checking /metrics/disk again.",
                    "Add log rotation / retention limits to avoid growth.",
                ])

                # ✅ remediation: cleanup + verify
                if auto_cleanup_disk:
                    cleanup_res = trigger_remote_disk_cleanup(backend_url)
                    remediation_attempts.append({"action": "remote_disk_cleanup", "result": cleanup_res})
                    time.sleep(2.0)

                    remote_disk_after = get_remote_disk_metrics(backend_url)
                    evidence["remote_disk_metrics_after_cleanup"] = remote_disk_after

                    if remote_disk_after.get("ok") and isinstance(remote_disk_after.get("data"), dict):
                        used_after = float(remote_disk_after["data"].get("used_percent", 0.0))
                        if used_after < remote_disk_threshold:
                            next_steps.append("Disk cleanup succeeded; usage dropped below threshold.")
                        else:
                            next_steps.append(
                                "Disk cleanup ran, but usage is still above threshold. "
                                "This indicates disk usage is not only from demo files (check logs/build cache)."
                            )
                    else:
                        next_steps.append("Cleanup ran, but disk metrics re-check failed; verify backend is reachable.")

    # -------------------------
    # D) Local checks (optional)
    # -------------------------
    if cpu_high_for(cfg.cpu_duration_seconds, cfg.cpu_threshold_pct):
        tops = top_cpu_processes(5)
        add_issue(
            issues,
            issue_type="CPU Spike",
            severity="HIGH",
            details=f"Local CPU > {cfg.cpu_threshold_pct}% for {cfg.cpu_duration_seconds}s. Top processes: {tops}",
            issue_evidence={"top_cpu_processes": tops},
        )

    disk_pct = disk_usage_pct("C:\\")
    evidence["local_disk_pct"] = disk_pct
    if disk_pct >= cfg.disk_threshold_pct:
        add_issue(
            issues,
            issue_type="Disk Usage High",
            severity="MEDIUM",
            details=f"Local C: drive usage is {disk_pct}%, threshold is {cfg.disk_threshold_pct}%",
            issue_evidence={"disk_before": disk_pct},
        )
        if getattr(cfg, "allow_clear_temp", False):
            remediation_attempts.append(clear_temp())
        evidence["local_disk_after"] = disk_usage_pct("C:\\")

    # -------------------------
    # Final incident formatting (FIXED)
    # -------------------------
    if not issues:
        incident = {
            "type": "No Incident",
            "details": "No threshold breach detected.",
            "severity": "INFO",
            "issues": [],
        }
        status = "resolved"
        next_steps = ["No action required."]
    else:
        sev = overall_severity(issues)

        if len(issues) == 1:
            # ✅ If only one issue, do NOT call it "Multiple Issues"
            only = issues[0]
            incident = {
                "type": only["type"],
                "details": f"1 issue detected.\n\n{combine_details(issues)}",
                "severity": sev,
                "issues": issues,
            }
        else:
            incident = {
                "type": "Multiple Issues Detected",
                "details": f"{len(issues)} issue(s) detected. Highest severity: {sev}.\n\n{combine_details(issues)}",
                "severity": sev,
                "issues": issues,
            }

        status = "blocked"
        next_steps = dedupe_keep_order(next_steps) or ["Review the issues list and address highest severity first."]

    return incident, remediation_attempts, status, next_steps, evidence


def main():
    cfg = AgentConfig()

    # KB config
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
    print(f"VERIFY_SSL        : {_verify_ssl_flag()}", flush=True)
    print("--------------------------------------------", flush=True)

    if kb_status["enabled"]:
        print("\n[KB Status]", flush=True)
        if kb_status["ok"]:
            print(f"- KB loaded OK from: {kb_status['source']}", flush=True)
        else:
            print(f"- KB load FAILED: {kb_status['error']}", flush=True)

    print("\n[Detection + Remediation]", flush=True)
    incident, attempts, status, next_steps, evidence = decide_and_act(cfg)

    # vuln mapping: if multiple issues, pick highest severity issue type
    incident_type_for_mapping = incident.get("type", "Unknown Incident")
    if incident_type_for_mapping == "Multiple Issues Detected" and incident.get("issues"):
        top_issue = max(incident["issues"], key=lambda x: severity_rank(x.get("severity", "INFO")))
        incident_type_for_mapping = top_issue.get("type", incident_type_for_mapping)

    if kb_mapping:
        vuln = lookup_vuln(incident_type_for_mapping, kb_mapping)
        vuln_source = "KB"
    else:
        vuln = get_vuln_mapping_fallback(incident_type_for_mapping)
        vuln_source = "LOCAL_MAP"

    print("\n[Incident Summary]", flush=True)
    print(f"Incident Type     : {incident.get('type')}", flush=True)
    print(f"Severity          : {incident.get('severity')}", flush=True)
    print(f"Details           : {incident.get('details')}", flush=True)

    # Gemini draft + email fallback
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
            vulnerability=vuln,
            style="concise",
        )
        subject = draft.get("email_subject")
        body_html = draft.get("email_body_html")
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

    persist_run({
        "incident": incident,
        "status": status,
        "evidence": evidence,
        "attempts": attempts,
        "next_steps": next_steps,
        "vulnerability": vuln,
        "email_subject": subject,
        "email_body_html": body_html,
    })

    print("\n========== Execution Completed ==========\n", flush=True)


if __name__ == "__main__":
    main()

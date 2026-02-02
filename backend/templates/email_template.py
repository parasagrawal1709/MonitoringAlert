# templates/email_template.py

from typing import Any, Dict, List, Optional, Tuple


def _escape_html(s: Any) -> str:
    """Basic HTML escape for safe email rendering."""
    if s is None:
        return ""
    s = str(s)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _badge(text: str, tone: str = "gray") -> str:
    """Small badge pill."""
    colors = {
        "green": ("#0f5132", "#d1e7dd", "#badbcc"),
        "red": ("#842029", "#f8d7da", "#f5c2c7"),
        "yellow": ("#664d03", "#fff3cd", "#ffecb5"),
        "blue": ("#084298", "#cfe2ff", "#b6d4fe"),
        "gray": ("#41464b", "#e2e3e5", "#d3d6d8"),
    }
    fg, bg, border = colors.get(tone, colors["gray"])
    return f"""
    <span style="
        display:inline-block;
        padding:2px 10px;
        border-radius:999px;
        font-size:12px;
        color:{fg};
        background:{bg};
        border:1px solid {border};
        line-height:18px;
        vertical-align:middle;
    ">{_escape_html(text)}</span>
    """


def _table_row(label: str, value: str) -> str:
    return f"""
    <tr>
      <td style="padding:10px 12px; border:1px solid #e5e7eb; width:180px; color:#111827; background:#f9fafb;">
        <strong>{_escape_html(label)}</strong>
      </td>
      <td style="padding:10px 12px; border:1px solid #e5e7eb; color:#111827;">
        {value}
      </td>
    </tr>
    """


# -------------------------
# Human-friendly renderers
# -------------------------

def _incident_story(incident: Dict[str, Any], status: str) -> Dict[str, str]:
    """
    Converts raw incident type/details into demo-friendly, human-readable text.
    Returns:
      {
        "what_happened": "...",
        "what_agent_did": "...",
        "outcome": "..."
      }
    """
    itype = (incident.get("type") or "Unknown").strip()
    raw_details = (incident.get("details") or "").strip()
    status_u = (status or "").upper()

    # Defaults (safe generic)
    what_happened = "The monitoring agent detected an issue based on configured checks."
    what_agent_did = "The agent evaluated safe remediation options (policy-safe actions only)."
    outcome = "The incident was reported for visibility."

    # More specific stories
    if itype.lower() in ("backend url unhealthy", "backend service unavailable", "health degraded"):
        what_happened = (
            "The backend service did not respond as expected to health checks, "
            "indicating a temporary availability issue."
        )
        if status_u == "RESOLVED":
            what_agent_did = "The agent triggered an automated recovery action to restore service availability."
            outcome = "The backend recovered successfully and returned to a healthy state."
        elif status_u == "BLOCKED":
            what_agent_did = "The agent attempted recovery, but the service still appears unavailable."
            outcome = "Manual investigation may be required to restore normal operation."
        else:
            what_agent_did = "The agent recorded the service degradation and raised an alert."
            outcome = "The service state will continue to be monitored."

    elif itype.lower() == "cpu spike":
        what_happened = "CPU usage exceeded the configured threshold, indicating a potential spike or workload surge."
        what_agent_did = "The agent collected evidence and raised an alert (no destructive actions were taken in demo mode)."
        outcome = "Please review the top CPU-consuming processes and recent changes/deployments."

    elif itype.lower() in ("disk usage high", "disk space high"):
        what_happened = "Disk usage crossed the configured threshold, indicating low free space."
        if status_u == "RESOLVED":
            what_agent_did = "The agent performed a safe cleanup action to reclaim space."
            outcome = "Disk usage dropped below the threshold and the system returned to normal."
        elif status_u == "BLOCKED":
            what_agent_did = "The agent attempted cleanup, but disk usage is still above the threshold."
            outcome = "Further cleanup or capacity expansion may be required."
        else:
            what_agent_did = "The agent raised an alert and captured disk usage evidence."
            outcome = "Please review large directories and apply retention/log rotation policies."

    elif itype.lower() == "no incident":
        what_happened = "No monitored thresholds were breached during this run."
        what_agent_did = "No action was required."
        outcome = "System appears stable based on current monitoring signals."

    # If raw_details contains something non-technical you still want, append lightly (optional)
    # But avoid dumping URLs/JSON/logs.
    # We only append if it's short and not obviously technical.
    if raw_details and len(raw_details) <= 120 and all(x not in raw_details.lower() for x in ("http", "https", "{", "}", "status_code", "/health", "/simulate")):
        what_happened = f"{what_happened} ({raw_details})"

    return {
        "what_happened": what_happened,
        "what_agent_did": what_agent_did,
        "outcome": outcome,
    }


def _humanize_attempt(a: Any) -> str:
    """
    Turns remediation attempt objects (strings/dicts) into human sentences.
    """
    if a is None:
        return ""

    # If attempt is already a plain string
    if isinstance(a, str):
        s = a.strip()
        # Avoid showing raw endpoints if present
        if "/simulate/" in s or "/health" in s or "status=" in s or "HTTP" in s:
            return "A remediation action was executed (technical details suppressed for readability)."
        return s

    if isinstance(a, dict):
        action = str(a.get("action", "remediation")).replace("_", " ").strip().lower()
        ok = a.get("ok", None)

        # Action-specific phrasing
        if "backend" in action and "heal" in action:
            if ok is True:
                return "Auto-recovery was triggered and the backend service was brought back online."
            if ok is False:
                return "Auto-recovery was attempted, but the backend service could not be restored automatically."
            return "Auto-recovery was evaluated for the backend service."

        if "disk" in action and "clean" in action:
            if ok is True:
                return "Disk cleanup was executed successfully."
            if ok is False:
                return "Disk cleanup was attempted but did not complete successfully."
            return "Disk cleanup was evaluated."

        # Generic
        if ok is True:
            return f"Remediation action executed successfully ({action})."
        if ok is False:
            return f"Remediation action attempted but did not succeed ({action})."
        return f"Remediation action recorded ({action})."

    # Fallback
    return "A remediation action was recorded."


def _render_attempts(attempts: List[Any], status: str) -> str:
    if not attempts:
        # If resolved with no attempts, still keep it readable
        if (status or "").upper() == "RESOLVED":
            return "<p style='margin:0;color:#374151;'>No remediation was required.</p>"
        return "<p style='margin:0;color:#6b7280;'>No remediation actions were executed.</p>"

    items = []
    for a in attempts:
        msg = _humanize_attempt(a)
        if msg:
            items.append(f"<li style='margin:6px 0;'>{_escape_html(msg)}</li>")
    if not items:
        return "<p style='margin:0;color:#6b7280;'>No remediation actions were executed.</p>"
    return "<ul style='margin:0; padding-left:18px;'>" + "".join(items) + "</ul>"


def _render_steps(steps: List[str]) -> str:
    if not steps:
        return "<p style='margin:0;color:#6b7280;'>No next steps provided.</p>"

    items = []
    for s in steps:
        # Keep steps readable; they are usually already human-ish.
        items.append(f"<li style='margin:6px 0;'>{_escape_html(s)}</li>")
    return "<ul style='margin:0; padding-left:18px;'>" + "".join(items) + "</ul>"


def _render_cwe_table(vuln: Optional[Dict[str, Any]]) -> str:
    """
    Render CWE mapping in a clean HTML table.
    Expected shape:
      {
        "cwe": "CWE-400",
        "title": "...",
        "description": "...",
        "example_cves": ["CVE-....", ...]
      }
    """
    if not vuln:
        return ""

    cwe = _escape_html(vuln.get("cwe", "N/A"))
    title = _escape_html(vuln.get("title", "N/A"))
    desc = _escape_html(vuln.get("description", "N/A"))
    cves = vuln.get("example_cves") or []

    cve_html = (
        "<span style='color:#6b7280;'>Not provided</span>"
        if not cves
        else "<div style='display:flex; flex-wrap:wrap; gap:6px;'>" +
             "".join([_badge(cv, "blue") for cv in cves[:8]]) +
             "</div>"
    )

    return f"""
    <div style="margin-top:16px; padding:14px; border:1px solid #e5e7eb; border-radius:12px; background:#ffffff;">
      <div style="display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:10px;">
        <div style="font-size:14px; font-weight:700; color:#111827;">
          Vulnerability Mapping (CWE)
        </div>
        {_badge(cwe, "gray")}
      </div>

      <table style="border-collapse:collapse; width:100%; font-size:13px;">
        {_table_row("CWE Title", f"<span style='font-weight:600;'>{title}</span>")}
        {_table_row("Meaning", f"<span style='color:#374151;'>{desc}</span>")}
        {_table_row("Example CVEs", cve_html)}
      </table>

      <p style="margin:10px 0 0; font-size:12px; color:#6b7280;">
        Note: CWE mapping is used for standard classification. CVEs shown are examples/references (not necessarily present on this host).
      </p>
    </div>
    """


def build_email(
    subject_prefix: str,
    host: str,
    incident: Dict[str, Any],
    attempts: List[Any],
    status: str,
    next_steps: List[str],
    vuln: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    """
    Returns (subject, html_body)

    Updated to be demo-friendly:
    - No raw URLs / status codes / JSON blobs in "Details"
    - Remediation attempts are human-readable summaries
    """
    incident_type = incident.get("type", "Unknown")
    severity = incident.get("severity", "INFO")

    # status badge tone
    status_upper = (status or "").upper()
    if status_upper == "RESOLVED":
        status_badge = _badge("RESOLVED", "green")
    elif status_upper == "BLOCKED":
        status_badge = _badge("BLOCKED", "red")
    else:
        status_badge = _badge(status_upper or "UNKNOWN", "gray")

    # severity badge tone
    sev = (severity or "").upper()
    if sev in ("HIGH", "CRITICAL"):
        sev_badge = _badge(sev, "red")
    elif sev in ("MEDIUM", "WARN", "WARNING"):
        sev_badge = _badge(sev, "yellow")
    else:
        sev_badge = _badge(sev or "INFO", "gray")

    subject = f"{subject_prefix} {incident_type} | {host} | {status_upper}"

    cwe_block = _render_cwe_table(vuln)

    story = _incident_story(incident, status=status)

    # Human-readable "Details" block (replaces raw logs)
    details_html = f"""
    <div style="color:#374151;">
      <div style="margin:0 0 8px;"><strong>What happened:</strong> {_escape_html(story["what_happened"])}</div>
      <div style="margin:0 0 8px;"><strong>What the agent did:</strong> {_escape_html(story["what_agent_did"])}</div>
      <div style="margin:0;"><strong>Outcome:</strong> {_escape_html(story["outcome"])}</div>
    </div>
    """

    body = f"""
    <div style="font-family:Segoe UI, Arial, sans-serif; color:#111827; line-height:1.45; max-width:760px;">
      <div style="padding:16px 18px; border:1px solid #e5e7eb; border-radius:14px; background:#ffffff;">
        <div style="display:flex; justify-content:space-between; gap:12px; align-items:flex-start; flex-wrap:wrap;">
          <div>
            <div style="font-size:16px; font-weight:800; margin-bottom:2px;">
              SRE AI Agent Report
            </div>
            <div style="font-size:13px; color:#6b7280;">
              Host: <strong style="color:#111827;">{_escape_html(host)}</strong>
            </div>
          </div>
          <div style="display:flex; gap:8px; align-items:center;">
            {sev_badge}
            {status_badge}
          </div>
        </div>

        <hr style="border:none; border-top:1px solid #e5e7eb; margin:14px 0;" />

        <table style="border-collapse:collapse; width:100%; font-size:13px;">
          {_table_row("Incident Type", f"<strong>{_escape_html(incident_type)}</strong>")}
          {_table_row("Severity", sev_badge)}
          {_table_row("Summary", details_html)}
        </table>

        <div style="margin-top:16px; padding:14px; border:1px solid #e5e7eb; border-radius:12px; background:#f9fafb;">
          <div style="font-size:13px; font-weight:700; margin-bottom:8px;">
            Remediation Performed
          </div>
          {_render_attempts(attempts, status=status)}
        </div>

        <div style="margin-top:16px; padding:14px; border:1px solid #e5e7eb; border-radius:12px; background:#f9fafb;">
          <div style="font-size:13px; font-weight:700; margin-bottom:8px;">
            Recommended Next Steps
          </div>
          {_render_steps(next_steps)}
        </div>

        {cwe_block}

        <hr style="border:none; border-top:1px solid #e5e7eb; margin:16px 0 10px;" />
        <div style="font-size:12px; color:#6b7280;">
          This message was generated by the demo SRE AI agent (policy-safe actions only).
        </div>
      </div>
    </div>
    """

    return subject, body

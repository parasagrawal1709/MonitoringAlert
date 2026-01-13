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


def _render_attempts(attempts: List[Any]) -> str:
    if not attempts:
        return "<p style='margin:0;color:#6b7280;'>None</p>"

    items = []
    for a in attempts:
        items.append(f"<li style='margin:6px 0;'>{_escape_html(a)}</li>")
    return "<ul style='margin:0; padding-left:18px;'>" + "".join(items) + "</ul>"


def _render_steps(steps: List[str]) -> str:
    if not steps:
        return "<p style='margin:0;color:#6b7280;'>No next steps provided.</p>"

    items = []
    for s in steps:
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
    vuln: Optional[Dict[str, Any]] = None,  # ✅ NEW
) -> Tuple[str, str]:
    """
    Returns (subject, html_body)

    vuln is optional. If provided, it will render a CWE mapping table.
    """
    incident_type = incident.get("type", "Unknown")
    severity = incident.get("severity", "INFO")
    details = incident.get("details", "")

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
          {_table_row("Details", f"<div style='white-space:pre-wrap; color:#374151;'>{_escape_html(details)}</div>")}
        </table>

        <div style="margin-top:16px; padding:14px; border:1px solid #e5e7eb; border-radius:12px; background:#f9fafb;">
          <div style="font-size:13px; font-weight:700; margin-bottom:8px;">
            Remediation Attempts
          </div>
          {_render_attempts(attempts)}
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

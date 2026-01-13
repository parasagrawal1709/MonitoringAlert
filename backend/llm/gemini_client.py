# llm/gemini_client.py
import os
import json
import re
import html
from typing import Any, Dict, List, Optional

from google import genai


def _severity_badge(severity: str) -> str:
    sev = (severity or "INFO").upper()
    # Simple, email-safe colors
    colors = {
        "CRITICAL": ("#7f1d1d", "#fee2e2"),
        "HIGH": ("#9a3412", "#ffedd5"),
        "MEDIUM": ("#92400e", "#fef3c7"),
        "LOW": ("#1d4ed8", "#dbeafe"),
        "INFO": ("#374151", "#f3f4f6"),
    }
    fg, bg = colors.get(sev, colors["INFO"])
    return (
        f"<span style='display:inline-block;padding:4px 10px;border-radius:999px;"
        f"font-weight:600;font-size:12px;background:{bg};color:{fg};border:1px solid {fg};'>"
        f"{html.escape(sev)}"
        f"</span>"
    )


def _status_badge(status: str) -> str:
    st = (status or "blocked").upper()
    colors = {
        "RESOLVED": ("#065f46", "#d1fae5"),
        "BLOCKED": ("#7c2d12", "#ffedd5"),
        "OPEN": ("#1f2937", "#e5e7eb"),
    }
    fg, bg = colors.get(st, colors["OPEN"])
    return (
        f"<span style='display:inline-block;padding:4px 10px;border-radius:999px;"
        f"font-weight:600;font-size:12px;background:{bg};color:{fg};border:1px solid {fg};'>"
        f"{html.escape(st)}"
        f"</span>"
    )


def _escape_json_safe(obj: Any) -> str:
    """Compact JSON for embedding into prompt safely."""
    try:
        return json.dumps(obj, ensure_ascii=False, indent=2, default=str)
    except Exception:
        return str(obj)


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    """
    Tries to extract a JSON object from Gemini output.
    Handles common cases:
    - pure JSON
    - JSON wrapped in ```json ... ```
    - extra text around JSON
    """
    if not text:
        return None

    # Remove code fences
    cleaned = re.sub(r"```(?:json)?\s*", "", text, flags=re.IGNORECASE).replace("```", "").strip()

    # First try direct parse
    try:
        return json.loads(cleaned)
    except Exception:
        pass

    # Try to find the first {...} block
    m = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if not m:
        return None

    candidate = m.group(0)
    try:
        return json.loads(candidate)
    except Exception:
        return None


def _build_fallback_html(
    incident: Dict[str, Any],
    evidence: Dict[str, Any],
    attempts: List[Any],
    status: str,
    next_steps: List[str],
    vulnerability: Optional[Dict[str, Any]] = None,
) -> str:
    inc_type = incident.get("type", "Incident")
    details = incident.get("details", "")
    severity = incident.get("severity", "INFO")

    # Evidence rows
    ev_rows = ""
    if evidence:
        for k, v in evidence.items():
            ev_rows += (
                "<tr>"
                f"<td style='padding:8px;border:1px solid #e5e7eb;font-weight:600;background:#f9fafb;'>{html.escape(str(k))}</td>"
                f"<td style='padding:8px;border:1px solid #e5e7eb;white-space:pre-wrap;'>{html.escape(_escape_json_safe(v))}</td>"
                "</tr>"
            )
    else:
        ev_rows = (
            "<tr>"
            "<td style='padding:8px;border:1px solid #e5e7eb;' colspan='2'>No evidence collected</td>"
            "</tr>"
        )

    # Attempts rows
    attempt_items = ""
    if attempts:
        for a in attempts:
            attempt_items += f"<li style='margin:4px 0;'>{html.escape(str(a))}</li>"
    else:
        attempt_items = "<li style='margin:4px 0;'>None (policy/safety block or not required)</li>"

    # Next steps
    ns_items = ""
    if next_steps:
        for s in next_steps:
            ns_items += f"<li style='margin:4px 0;'>{html.escape(str(s))}</li>"
    else:
        ns_items = "<li style='margin:4px 0;'>No next steps</li>"

    # Vulnerability mapping table
    vuln_html = ""
    if vulnerability:
        cwe = vulnerability.get("cwe", "N/A")
        title = vulnerability.get("title", "N/A")
        desc = vulnerability.get("description", "N/A")
        cves = vulnerability.get("example_cves", []) or []
        cve_text = ", ".join([str(x) for x in cves[:5]]) if cves else "N/A"

        vuln_html = f"""
        <h3 style="margin:18px 0 8px 0;font-family:Segoe UI,Arial;">Vulnerability Mapping</h3>
        <table style="border-collapse:collapse;width:100%;font-family:Segoe UI,Arial;font-size:13px;">
          <tr>
            <td style="padding:8px;border:1px solid #e5e7eb;font-weight:600;background:#f9fafb;width:220px;">CWE</td>
            <td style="padding:8px;border:1px solid #e5e7eb;">{html.escape(str(cwe))}</td>
          </tr>
          <tr>
            <td style="padding:8px;border:1px solid #e5e7eb;font-weight:600;background:#f9fafb;">Title</td>
            <td style="padding:8px;border:1px solid #e5e7eb;">{html.escape(str(title))}</td>
          </tr>
          <tr>
            <td style="padding:8px;border:1px solid #e5e7eb;font-weight:600;background:#f9fafb;">Meaning</td>
            <td style="padding:8px;border:1px solid #e5e7eb;white-space:pre-wrap;">{html.escape(str(desc))}</td>
          </tr>
          <tr>
            <td style="padding:8px;border:1px solid #e5e7eb;font-weight:600;background:#f9fafb;">Example CVEs (ref)</td>
            <td style="padding:8px;border:1px solid #e5e7eb;">{html.escape(str(cve_text))}</td>
          </tr>
        </table>
        """

    html_body = f"""
    <html>
      <body style="font-family:Segoe UI,Arial; color:#111827; line-height:1.4;">
        <h2 style="margin:0 0 10px 0;">SRE Alert</h2>

        <table style="border-collapse:collapse;width:100%;font-size:13px;">
          <tr>
            <td style="padding:8px;border:1px solid #e5e7eb;font-weight:600;background:#f9fafb;width:220px;">Incident Type</td>
            <td style="padding:8px;border:1px solid #e5e7eb;">{html.escape(str(inc_type))}</td>
          </tr>
          <tr>
            <td style="padding:8px;border:1px solid #e5e7eb;font-weight:600;background:#f9fafb;">Severity</td>
            <td style="padding:8px;border:1px solid #e5e7eb;">{_severity_badge(severity)}</td>
          </tr>
          <tr>
            <td style="padding:8px;border:1px solid #e5e7eb;font-weight:600;background:#f9fafb;">Final Status</td>
            <td style="padding:8px;border:1px solid #e5e7eb;">{_status_badge(status)}</td>
          </tr>
          <tr>
            <td style="padding:8px;border:1px solid #e5e7eb;font-weight:600;background:#f9fafb;">Details</td>
            <td style="padding:8px;border:1px solid #e5e7eb;white-space:pre-wrap;">{html.escape(str(details))}</td>
          </tr>
        </table>

        <h3 style="margin:18px 0 8px 0;">Evidence</h3>
        <table style="border-collapse:collapse;width:100%;font-size:12.5px;">
          {ev_rows}
        </table>

        <h3 style="margin:18px 0 8px 0;">Actions Attempted</h3>
        <ul style="margin:0;padding-left:18px;">
          {attempt_items}
        </ul>

        <h3 style="margin:18px 0 8px 0;">Next Steps</h3>
        <ul style="margin:0;padding-left:18px;">
          {ns_items}
        </ul>

        {vuln_html}

        <p style="margin-top:18px;color:#6b7280;font-size:12px;">
          Generated by SRE-AI Agent (demo).
        </p>
      </body>
    </html>
    """
    return html_body


def diagnose_and_draft(
    incident: Dict[str, Any],
    evidence: Dict[str, Any],
    attempts: List[Any],
    status: str,
    next_steps: List[str],
    vulnerability: Dict[str, Any] | None = None,
    style: str = "concise",
) -> Dict[str, str]:
    """
    Returns dict:
      - email_subject
      - email_body_html (CLEAN HTML, same tabular format, severity color badges, includes CWE mapping)
      - diagnosis (1-2 lines)
    """
    api_key = os.getenv("GOOGLE_API_KEY")
    model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

    if not api_key:
        raise RuntimeError("GOOGLE_API_KEY is not set")

    client = genai.Client(api_key=api_key)

    # Precompute badges so Gemini doesn't invent random colors/HTML
    severity = incident.get("severity", "INFO")
    inc_type = incident.get("type", "Incident")

    # We will FORCE Gemini to output strict JSON only (no markdown, no code fences)
    prompt = f"""
You are an SRE assistant.

You MUST return ONLY valid JSON (no markdown, no triple backticks, no extra text).

Goal:
- Generate a short diagnosis (1-2 lines)
- Generate HTML email body in the EXACT TABLE-BASED FORMAT described below
- Include severity badge and status badge (use the exact HTML snippets provided)
- Include Vulnerability Mapping section as an HTML table (CWE, Title, Meaning, Example CVEs) if vulnerability is provided

STYLE: {style}

INPUT DATA (use these facts only; do not hallucinate):
incident = { _escape_json_safe(incident) }
evidence = { _escape_json_safe(evidence) }
attempts = { _escape_json_safe(attempts) }
status = { _escape_json_safe(status) }
next_steps = { _escape_json_safe(next_steps) }
vulnerability = { _escape_json_safe(vulnerability) }

BADGE HTML (use exactly as-is):
severity_badge_html = {json.dumps(_severity_badge(severity))}
status_badge_html   = {json.dumps(_status_badge(status))}

EMAIL HTML RULES:
- Must be valid HTML (no <pre>, no JSON printed in email)
- Use <table> sections:
  1) Summary table with Incident Type, Severity(badge), Final Status(badge), Details
  2) Evidence table (key/value)
  3) Actions Attempted as <ul>
  4) Next Steps as <ul>
  5) Vulnerability Mapping table (only if vulnerability not null)
- Keep it email-safe: inline CSS only; avoid external links/scripts.

Return STRICT JSON with keys:
{{
  "email_subject": "...",
  "email_body_html": "...",
  "diagnosis": "..."
}}
"""

    resp = client.models.generate_content(model=model, contents=prompt)
    raw = (resp.text or "").strip()

    parsed = _extract_json(raw)

    # If Gemini output isn't valid JSON, fall back to our deterministic HTML template
    if not parsed or "email_body_html" not in parsed:
        fallback_subject = f"[SRE-AI] {inc_type} - {str(status).upper()}"
        fallback_html = _build_fallback_html(
            incident=incident,
            evidence=evidence,
            attempts=attempts,
            status=status,
            next_steps=next_steps,
            vulnerability=vulnerability,
        )
        return {
            "email_subject": fallback_subject,
            "email_body_html": fallback_html,
            "diagnosis": f"{inc_type}: {str(status).upper()} (Gemini output could not be parsed as JSON).",
        }

    # Clean + safe defaults if keys missing
    email_subject = parsed.get("email_subject") or f"[SRE-AI] {inc_type} - {str(status).upper()}"
    email_body_html = parsed.get("email_body_html") or _build_fallback_html(
        incident=incident,
        evidence=evidence,
        attempts=attempts,
        status=status,
        next_steps=next_steps,
        vulnerability=vulnerability,
    )
    diagnosis = parsed.get("diagnosis") or ""

    # Final guard: if model accidentally returns markdown fences, strip them
    email_body_html = re.sub(r"```.*?```", "", email_body_html, flags=re.DOTALL).strip()
    email_body_html = email_body_html.replace("```", "").strip()

    return {
        "email_subject": email_subject,
        "email_body_html": email_body_html,
        "diagnosis": diagnosis[:600],
    }

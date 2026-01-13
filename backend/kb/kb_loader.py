# kb/kb_loader.py
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests

try:
    import pandas as pd
except Exception as e:
    raise RuntimeError(
        "pandas is required for KB Excel loading. Please install: pip install pandas openpyxl"
    ) from e


@dataclass
class KBResult:
    ok: bool
    mapping: Dict[str, Dict[str, Any]]
    error: Optional[str] = None
    source: Optional[str] = None  # local path used


def _normalize_col(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").strip().lower())


def _first_match_col(cols: List[str], candidates: List[str]) -> Optional[str]:
    norm_to_real = {_normalize_col(c): c for c in cols}
    for cand in candidates:
        key = _normalize_col(cand)
        if key in norm_to_real:
            return norm_to_real[key]
    return None


def _parse_csv_like_list(val: Any) -> List[str]:
    if val is None:
        return []
    s = str(val).strip()
    if not s:
        return []
    parts = re.split(r"[,\n;|]+", s)
    return [p.strip() for p in parts if p.strip()]


def _guess_sheet(excel: pd.ExcelFile) -> str:
    # Prefer CWE_Mapping if present, else first sheet
    for name in excel.sheet_names:
        if _normalize_col(name) in ("cwemapping", "cwe", "vulnerabilitymapping", "kb"):
            return name
    return excel.sheet_names[0]


def download_file(url: str, dest_path: str, timeout: int = 30) -> None:
    # Works for GitHub raw (public) and general direct-download URLs
    headers = {
        "User-Agent": "sre-agent-kb-loader/1.0",
        "Accept": "*/*",
    }
    with requests.get(url, headers=headers, stream=True, timeout=timeout) as r:
        r.raise_for_status()
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with open(dest_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 64):
                if chunk:
                    f.write(chunk)


def load_kb_from_excel(
    excel_path: str,
) -> Dict[str, Dict[str, Any]]:
    """
    Reads the Excel file and returns a mapping:
      incident_type -> {cwe, title, description, example_cves, keywords, ...}

    The loader tries to be forgiving about column names.
    """
    xls = pd.ExcelFile(excel_path)
    sheet = _guess_sheet(xls)
    df = pd.read_excel(xls, sheet_name=sheet)

    # Drop completely empty rows
    df = df.dropna(how="all")

    # Column detection (flexible)
    cols = list(df.columns)

    col_incident = _first_match_col(
        cols,
        [
            "Incident Type",
            "Incident Types",
            "Incident",
            "Signal Type",
            "Type",
        ],
    )
    col_keywords = _first_match_col(
        cols,
        [
            "Keywords",
            "Keyword",
            "Match Keywords",
            "Matching Keywords",
        ],
    )
    col_cwe = _first_match_col(cols, ["CWE Code", "CWE", "CWE-ID", "CWE ID"])
    col_title = _first_match_col(cols, ["CWE Title", "Title", "CWE Name", "Name"])
    col_desc = _first_match_col(
        cols,
        [
            "Description",
            "Meaning",
            "CWE Meaning",
            "Details",
            "Summary",
        ],
    )
    col_cves = _first_match_col(
        cols,
        [
            "Example CVEs",
            "CVEs",
            "CVE Examples",
        ],
    )

    # Hard requirement for mapping usefulness: at least CWE code + title/desc
    if not col_cwe:
        raise RuntimeError(
            f"Could not find a CWE Code column in sheet '{sheet}'. Columns seen: {cols}"
        )

    # Build incident mapping
    mapping: Dict[str, Dict[str, Any]] = {}

    for _, row in df.iterrows():
        cwe_code = str(row.get(col_cwe, "")).strip()
        if not cwe_code or cwe_code.lower() == "nan":
            continue

        title = str(row.get(col_title, "")).strip() if col_title else ""
        desc = str(row.get(col_desc, "")).strip() if col_desc else ""
        cves = _parse_csv_like_list(row.get(col_cves)) if col_cves else []
        keywords = _parse_csv_like_list(row.get(col_keywords)) if col_keywords else []

        # Incident types can be a single value or list-like
        incidents: List[str] = []
        if col_incident:
            incidents = _parse_csv_like_list(row.get(col_incident))
        # If no explicit incident types, we still store under a generic key
        if not incidents:
            incidents = ["Unknown Incident"]

        for inc in incidents:
            inc_key = str(inc).strip() if inc else "Unknown Incident"
            if not inc_key:
                inc_key = "Unknown Incident"

            mapping[inc_key] = {
                "cwe": cwe_code,
                "title": title or "N/A",
                "description": desc or "N/A",
                "example_cves": cves,
                "keywords": keywords,
                "source": f"{os.path.basename(excel_path)}::{sheet}",
            }

    # Ensure a fallback exists
    if "Unknown Incident" not in mapping:
        mapping["Unknown Incident"] = {
            "cwe": "CWE-1059",
            "title": "Insufficient Technical Impact Assessment",
            "description": "Unable to classify incident type with available evidence.",
            "example_cves": [],
            "keywords": [],
            "source": f"{os.path.basename(excel_path)}::{sheet}",
        }

    return mapping


def load_kb(
    kb_url: str,
    cache_dir: str = ".kb_cache",
    cache_filename: str = "CWE_Knowledge_Base.xlsx",
    refresh: bool = False,
) -> KBResult:
    """
    Downloads KB from kb_url into cache (unless cached), then loads mapping.

    - refresh=False: use cached file if present
    - refresh=True : always re-download
    """
    try:
        os.makedirs(cache_dir, exist_ok=True)
        local_path = os.path.join(cache_dir, cache_filename)

        if refresh or not os.path.exists(local_path):
            download_file(kb_url, local_path)

        mapping = load_kb_from_excel(local_path)
        return KBResult(ok=True, mapping=mapping, source=local_path)

    except Exception as e:
        return KBResult(ok=False, mapping={}, error=str(e), source=None)


def lookup_vuln(
    incident_type: str,
    kb_mapping: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Exact match first; else Unknown Incident.
    """
    if incident_type in kb_mapping:
        return kb_mapping[incident_type]
    if "Unknown Incident" in kb_mapping:
        return kb_mapping["Unknown Incident"]
    return {
        "cwe": "CWE-1059",
        "title": "KB Unavailable / Lookup Failed",
        "description": "Unable to map incident to CWE (KB missing fallback).",
        "example_cves": [],
        "keywords": [],
    }

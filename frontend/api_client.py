# frontend/api_client.py
import os
import requests
from typing import Any, Dict, List, Optional, Tuple, Union

# ============================================================
# ✅ URL + SSL settings (Your version)
# ============================================================

# Default: Render backend (deployed service)
DEFAULT_BACKEND_URL = "https://sre-agent-backend.onrender.com"

# Allow local override via env
# Example: BACKEND_URL="http://localhost:8000"
BACKEND_URL = os.getenv("BACKEND_URL", DEFAULT_BACKEND_URL).rstrip("/")

# Timeouts (connect, read)
DEFAULT_TIMEOUT = (
    float(os.getenv("HTTP_CONNECT_TIMEOUT", "5")),
    float(os.getenv("HTTP_READ_TIMEOUT", "25")),
)

# SSL verify toggle (demo-only convenience)
def _bool_env(name: str, default: str = "true") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "y")

VERIFY_SSL = _bool_env("VERIFY_SSL", "true")


# ============================================================
# ✅ Helpers (Your version)
# ============================================================

def _normalize_err(e: Exception) -> str:
    msg = str(e)
    if isinstance(e, requests.exceptions.SSLError):
        return (
            "SSL certificate verification failed. "
            "If you're on a restricted corporate network, set VERIFY_SSL=false (demo only). "
            f"Details: {msg}"
        )
    return msg


def _safe_json(resp: requests.Response) -> Dict[str, Any]:
    try:
        return resp.json()
    except Exception:
        return {"raw": resp.text}


def _request_safe(
    method: str,
    path: str,
    params=None,
    json_body=None,
    timeout=None,
) -> Tuple[bool, Union[Dict[str, Any], List[Any], None], Optional[str]]:
    """
    Safe request wrapper:
    Returns: (ok: bool, data: dict|list|None, err: str|None)
    """
    url = f"{BACKEND_URL}{path}"
    try:
        resp = requests.request(
            method=method,
            url=url,
            params=params,
            json=json_body,
            timeout=timeout or DEFAULT_TIMEOUT,
            verify=VERIFY_SSL,
        )

        # non-2xx treated as controlled failure
        if not (200 <= resp.status_code < 300):
            data = _safe_json(resp)
            return False, data, f"HTTP {resp.status_code}: {data}"

        # success: JSON if possible
        ct = (resp.headers.get("content-type") or "").lower()
        if "application/json" in ct:
            return True, resp.json(), None
        return True, {"raw": resp.text}, None

    except requests.exceptions.RequestException as e:
        return False, None, _normalize_err(e)


def _get_safe(path: str, params=None, timeout=None):
    return _request_safe("GET", path, params=params, timeout=timeout)


def _post_safe(path: str, params=None, json_body=None, timeout=None):
    return _request_safe("POST", path, params=params, json_body=json_body, timeout=timeout)


# ============================================================
# ✅ Public API used by Streamlit apps (Merged compatibility)
# ============================================================
# Key idea:
# - Keep "friend-style" functions returning requests.Response
#   so their app doesn't break.
# - ALSO expose *_safe variants returning (ok, data, err)
#   so your app doesn't break.
#
# This gives you backward compatibility BOTH ways.
# ============================================================

def start_agent(payload) -> requests.Response:
    """
    Friend-compatible: returns requests.Response
    """
    # higher timeout for cold-start
    return requests.post(
        f"{BACKEND_URL}/agent/start",
        json=payload,
        timeout=(5, 30),
        verify=VERIFY_SSL,
    )


def start_agent_safe(payload):
    """
    Your-style: returns (ok, data, err)
    """
    return _post_safe("/agent/start", json_body=payload, timeout=(5, 30))


def stop_agent() -> requests.Response:
    """
    Friend-compatible: returns requests.Response
    """
    return requests.post(
        f"{BACKEND_URL}/agent/stop",
        timeout=(5, 30),
        verify=VERIFY_SSL,
    )


def stop_agent_safe():
    """
    Your-style: returns (ok, data, err)
    """
    return _post_safe("/agent/stop", timeout=(5, 30))


def simulate_incident() -> requests.Response:
    """
    Friend-compatible: returns requests.Response
    """
    return requests.post(
        f"{BACKEND_URL}/agent/simulate",
        timeout=(5, 45),
        verify=VERIFY_SSL,
    )


def simulate_incident_safe():
    """
    Your-style: returns (ok, data, err)
    """
    return _post_safe("/agent/simulate", timeout=(5, 45))


def fetch_incidents() -> List[Dict[str, Any]]:
    """
    Friend-compatible behavior:
    - returns list always
    - never throws
    """
    try:
        resp = requests.get(
            f"{BACKEND_URL}/incidents",
            timeout=(5, 30),
            verify=VERIFY_SSL,
        )
        data = resp.json()
        return data if isinstance(data, list) else []
    except requests.exceptions.RequestException:
        return []
    except Exception:
        return []


def fetch_incidents_safe():
    """
    Your-style: returns (ok, list, err)
    """
    ok, data, err = _get_safe("/incidents", timeout=(5, 30))
    if not ok:
        return False, [], err
    return True, data if isinstance(data, list) else [], None


def backend_health_status(timeout=(2, 6)):
    """
    Your version (kept intact):
    Returns: (ok_healthy: bool, data: dict, err: str|None)
    """
    url = f"{BACKEND_URL}/health"

    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=VERIFY_SSL,
        )

        ct = (resp.headers.get("content-type") or "").lower()
        payload = _safe_json(resp) if "application/json" in ct else {"raw": resp.text}

        data = {
            "reachable": True,
            "healthy": (resp.status_code == 200),
            "status_code": resp.status_code,
            "payload": payload,
            "url": url,
        }

        if resp.status_code == 200:
            return True, data, None

        return False, data, f"HTTP {resp.status_code}"

    except requests.exceptions.RequestException as e:
        err = _normalize_err(e)
        data = {
            "reachable": False,
            "healthy": False,
            "status_code": None,
            "payload": {"error": err},
            "url": url,
        }
        return False, data, err

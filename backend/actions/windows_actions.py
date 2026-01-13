# actions/windows_actions.py
import os
import shutil
import subprocess
from pathlib import Path
import subprocess
import sys
import time
import requests


def clear_temp():
    """
    Safely clears user temp folder (demo-safe).
    """
    temp = Path(os.environ.get("TEMP", r"C:\Windows\Temp"))
    removed = 0
    failed = 0

    for item in temp.glob("*"):
        try:
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=False)
            else:
                item.unlink(missing_ok=True)
            removed += 1
        except Exception:
            failed += 1

    return {"action": "clear_temp", "removed": removed, "failed": failed, "temp": str(temp)}

def restart_service(service_name: str):
    """
    Restarts a Windows service using PowerShell.
    """
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command",
        f"Restart-Service -Name '{service_name}' -Force"
    ]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "action": "restart_service",
        "service": service_name,
        "returncode": p.returncode,
        "stdout": p.stdout.strip(),
        "stderr": p.stderr.strip(),
    }



def try_backend_recover(backend_url: str, host: str, port: int) -> dict:
    """
    Best-effort remediation:
    1) If backend is reachable but returns 503 -> call /simulate/service_up
    2) If backend is not reachable -> start uvicorn backend_app:app
    """
    result = {"action": "backend_self_heal", "ok": False, "details": ""}

    # Case A: backend reachable but unhealthy
    try:
        r = requests.get(f"{backend_url}/health", timeout=3)
        if r.status_code == 503:
            try:
                up = requests.post(f"{backend_url}/simulate/service_up", timeout=3)
                result["ok"] = up.status_code < 400
                result["details"] = f"Called /simulate/service_up (status={up.status_code})"
                return result
            except Exception as e:
                result["details"] = f"Backend reachable but failed to call /simulate/service_up: {e}"
                return result
        elif r.status_code == 200:
            result["ok"] = True
            result["details"] = "Backend already healthy (200 on /health). No action needed."
            return result
        else:
            result["details"] = f"Backend returned unexpected status on /health: {r.status_code}"
            return result
    except Exception:
        # Case B: backend not reachable -> try start it
        pass

    # Start uvicorn backend in background (Windows)
    try:
        python_exe = sys.executable
        cmd = [
            python_exe, "-m", "uvicorn",
            "backend_app:app",
            "--host", host,
            "--port", str(port)
        ]

        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200

        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        )

        time.sleep(2)

        # Re-check health
        r2 = requests.get(f"{backend_url}/health", timeout=3)
        if r2.status_code == 200:
            result["ok"] = True
            result["details"] = f"Started backend via uvicorn and health is OK (port {port})."
        else:
            result["details"] = f"Started backend but /health still not OK (status={r2.status_code})."
        return result

    except Exception as e:
        result["details"] = f"Failed to start backend: {e}"
        return result

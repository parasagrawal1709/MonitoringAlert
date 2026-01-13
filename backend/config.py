# config.py
import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

@dataclass
class AgentConfig:
    # Labels
    host_label: str = os.getenv("HOST_LABEL", "windows-demo-host")

    # Email
    to_email: str = os.getenv("TO_EMAIL", "abhigyanpal98@gmail.com")

    # URL backend
    backend_url: str = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")
    backend_host: str = os.getenv("BACKEND_HOST", "127.0.0.1")
    backend_port: int = int(os.getenv("BACKEND_PORT", "8000"))

    # Thresholds 
    cpu_threshold_pct: float = float(os.getenv("CPU_THRESHOLD_PCT", "20.0"))
    cpu_duration_seconds: int = int(os.getenv("CPU_DURATION_SECONDS", "3"))
    disk_threshold_pct: float = float(os.getenv("DISK_THRESHOLD_PCT", "20.0"))

    # Safe actions allowed (demo policy)
    allow_kill_process: bool = False
    allow_clear_temp: bool = True
    allow_restart_service: bool = True

    # URL remediation policy
    allow_backend_self_heal: bool = True

import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

@dataclass
class AgentConfig:
    # Labels
    host_label: str = os.getenv("HOST_LABEL", "render-sre-demo")

    # Email
    to_email: str = os.getenv("TO_EMAIL", "abhigyanpal98@gmail.com")

    # Backend (public)
    backend_url: str = os.getenv(
        "BACKEND_URL",
        "https://sre-agent-backend.onrender.com"
    )

    # Local backend (unused in demo)
    backend_host: str = os.getenv("BACKEND_HOST", "127.0.0.1")
    backend_port: int = int(os.getenv("BACKEND_PORT", "8002"))

    # Local thresholds (effectively disabled)
    cpu_threshold_pct: float = float(os.getenv("CPU_THRESHOLD_PCT", "90.0"))
    cpu_duration_seconds: int = int(os.getenv("CPU_DURATION_SECONDS", "10"))
    disk_threshold_pct: float = float(os.getenv("DISK_THRESHOLD_PCT", "95.0"))

    # Demo-safe actions
    allow_kill_process: bool = False
    allow_clear_temp: bool = False
    allow_restart_service: bool = False

    # No auto self-heal during demo
    allow_backend_self_heal: bool = True

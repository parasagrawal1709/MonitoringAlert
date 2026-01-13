import time
import psutil

def cpu_high_for(duration_seconds: int, threshold_pct: float) -> bool:
    """
    Returns True if CPU stays above threshold for duration_seconds.
    psutil is a cross-platform library for retrieving information on running processes and system utilization (CPU, memory, disks, network, sensors) in Python. Supported platforms:

        - Linux
        - Windows
        - macOS
        - FreeBSD
        - OpenBSD
        - NetBSD
        - Sun Solaris
        - AIX
    """
    print(f"[Monitor] Checking CPU > {threshold_pct}% for {duration_seconds}s")

    start = time.time()
    while time.time() - start < duration_seconds:
        cpu = psutil.cpu_percent(interval=1)
        print(f"[Monitor] CPU usage: {cpu}%")

        if cpu < threshold_pct:
            return False

    return True

def disk_usage_pct(drive: str = "C:\\") -> float:
    usage = psutil.disk_usage(drive)
    return usage.percent

def top_cpu_processes(n: int = 5):
    procs = []
    for p in psutil.process_iter(attrs=["pid", "name"]):
        try:
            cpu = p.cpu_percent(interval=0.1)
            procs.append((cpu, p.info["pid"], p.info["name"]))
        except Exception:
            continue
    procs.sort(reverse=True, key=lambda x: x[0])
    return procs[:n]

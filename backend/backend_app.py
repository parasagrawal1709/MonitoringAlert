# backend_app.py
import os
import time
import threading
from fastapi import FastAPI
from fastapi.responses import JSONResponse
import multiprocessing as mp

def burn_cpu_worker(seconds: int):
    """Top-level function so multiprocessing can pickle it on Windows."""
    end = time.time() + seconds
    x = 0
    while time.time() < end:
        # Heavier math to spike CPU more
        x = (x * 3 + 7) % 1000003
        x = (x * 13 + 17) % 10000019
        x = (x ^ 0xABCDEF) % 10000079


app = FastAPI(title="SRE Demo Backend")

SERVICE_DOWN = False
SERVICE_DOWN_REASON = "Maintenance mode"


@app.get("/health")
def health():
    if SERVICE_DOWN:
        return JSONResponse(status_code=503, content={"status": "DOWN", "reason": SERVICE_DOWN_REASON})
    return {"status": "OK"}


@app.post("/simulate/service_down")
def simulate_service_down(reason: str = "Simulated outage"):
    global SERVICE_DOWN, SERVICE_DOWN_REASON
    SERVICE_DOWN = True
    SERVICE_DOWN_REASON = reason
    return {"ok": True, "message": "Service now returns 503 on /health", "reason": reason}


@app.post("/simulate/service_up")
def simulate_service_up():
    global SERVICE_DOWN
    SERVICE_DOWN = False
    return {"ok": True, "message": "Service restored (200 on /health)"}




@app.post("/simulate/cpu")
def simulate_cpu(seconds: int = 15, workers: int = 4):
    """
    Strong CPU spike on Windows:
    - Uses multiprocessing with a TOP-LEVEL worker function (picklable).
    - workers controls how many CPU-burning processes to run.
    """

    def start_processes(s: int, n: int):
        n = max(1, int(n))
        procs = []
        for _ in range(n):
            p = mp.Process(target=burn_cpu_worker, args=(s,), daemon=True)
            p.start()
            procs.append(p)

        # Optional: wait so processes end cleanly (still background thread)
        for p in procs:
            p.join()

    threading.Thread(target=start_processes, args=(seconds, workers), daemon=True).start()
    return {"ok": True, "message": f"CPU burn started for ~{seconds}s with {workers} worker processes"}

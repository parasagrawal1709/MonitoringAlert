import requests

# ================= Agent / Incident APIs =================

BASE_URL = "http://localhost:8000"

def start_agent(payload):
    return requests.post(f"{BASE_URL}/agent/start", json=payload)

def stop_agent():
    return requests.post(f"{BASE_URL}/agent/stop")

def simulate_incident():
    return requests.post(f"{BASE_URL}/agent/simulate")

def fetch_incidents():
    return requests.get(f"{BASE_URL}/incidents").json()


# ================= Microservice Log APIs =================

SERVICE_LOG_ENDPOINTS = {
    "User Service": "http://localhost:9081/logs",
    "Order Service": "http://localhost:9082/logs",
    "Product Service": "http://localhost:9083/logs",
    "Notification Service": "http://localhost:9084/logs",
}

def fetch_logs():
    logs = {}
    for service, url in SERVICE_LOG_ENDPOINTS.items():
        try:
            logs[service] = requests.get(url, timeout=1).json()
        except Exception:
            logs[service] = ["Service not running"]
    return logs

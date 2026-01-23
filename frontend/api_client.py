import requests

# ---------------- Agent APIs ----------------
BASE_URL = "http://localhost:8501"  # Streamlit (demo-safe)

def start_agent(payload):
    return requests.post(f"{BASE_URL}/agent/start", json=payload)

def stop_agent():
    return requests.post(f"{BASE_URL}/agent/stop")

def simulate_incident():
    return requests.post(f"{BASE_URL}/agent/simulate")

def fetch_incidents():
    try:
        res = requests.get(f"{BASE_URL}/incidents", timeout=3)

        # Streamlit or backend not returning JSON
        if res.status_code != 200 or not res.text.strip():
            return []

        return res.json()

    except requests.exceptions.JSONDecodeError:
        return []

    except Exception:
        return []


# ---------------- Log Fetching (MICROSERVICES) ----------------
SERVICES = {
    "User Service": "http://localhost:9081/actuator/logfile",
    "Order Service": "http://localhost:9082/actuator/logfile",
    "Product Service": "http://localhost:9083/actuator/logfile",
    "Notification Service": "http://localhost:9084/actuator/logfile",
}

def fetch_logs():
    logs = {}
    for service, url in SERVICES.items():
        try:
            res = requests.get(url, timeout=3)
            logs[service] = (
                res.text if res.status_code == 200 else f"HTTP {res.status_code}"
            )
        except Exception as e:
            logs[service] = f"Error: {str(e)}"
    return logs

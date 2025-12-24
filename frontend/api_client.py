import requests

BASE_URL = "http://localhost:8000"

def start_agent(payload):
    return requests.post(f"{BASE_URL}/agent/start", json=payload)

def stop_agent():
    return requests.post(f"{BASE_URL}/agent/stop")

def simulate_incident():
    return requests.post(f"{BASE_URL}/agent/simulate")

def fetch_incidents():
    return requests.get(f"{BASE_URL}/incidents").json()

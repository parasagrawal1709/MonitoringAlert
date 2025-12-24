from fastapi import FastAPI
from agent.agent_manager import start_agent, stop_agent, simulate_incident
from services.storage import INCIDENTS

app = FastAPI(title="Agent Automation API")

@app.post("/agent/start")
def start(payload: dict):
    start_agent(payload)
    return {"status": "Agent started"}

@app.post("/agent/stop")
def stop():
    stop_agent()
    return {"status": "Agent stopped"}

@app.post("/agent/simulate")
def simulate():
    simulate_incident()
    return {"status": "Incident simulated"}

@app.get("/incidents")
def get_incidents():
    return INCIDENTS

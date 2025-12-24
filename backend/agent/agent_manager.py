from datetime import datetime
from services.storage import INCIDENTS, AGENT_RUNNING
from agent.detector import detect_cpu_issue
from agent.remediator import remediate
from agent.notifier import send_email

def start_agent(config):
    global AGENT_RUNNING
    AGENT_RUNNING = True

def stop_agent():
    global AGENT_RUNNING
    AGENT_RUNNING = False

def simulate_incident():
    incident = detect_cpu_issue()
    action, exit_code = remediate(incident)
    email_status = send_email(incident)

    INCIDENTS.append({
        "host": "linux-server-01",
        "type": "CPU 100%",
        "severity": "Critical",
        "detected_at": datetime.now(),
        "decision": "Auto Remediation",
        "remediation": action,
        "exit_code": exit_code,
        "email_sent": email_status
    })

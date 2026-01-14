import requests

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
            response = requests.get(url, timeout=3)

            if response.status_code == 200:
                logs[service] = response.text
            else:
                logs[service] = (
                    f"Failed to fetch logs "
                    f"(HTTP {response.status_code})"
                )

        except requests.exceptions.ConnectionError:
            logs[service] = "Service not reachable"
        except requests.exceptions.Timeout:
            logs[service] = "Request timed out"
        except Exception as e:
            logs[service] = f"Error: {str(e)}"

    return logs

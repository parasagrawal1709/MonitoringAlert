import requests

def check_backend_health(url: str, timeout: int = 3) -> str:
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200:
            return "UP (200 OK)"
        else:
            return f"DOWN ({r.status_code})"
    except Exception as e:
        return f"UNREACHABLE ({str(e)})"

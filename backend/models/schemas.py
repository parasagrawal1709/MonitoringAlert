from pydantic import BaseModel
from datetime import datetime

class Incident(BaseModel):
    host: str
    type: str
    severity: str
    detected_at: datetime
    decision: str
    remediation: str
    exit_code: int
    email_sent: bool

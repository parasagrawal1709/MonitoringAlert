import pandas as pd
from datetime import datetime, timedelta

now = datetime.now()

data = [
    {
        "domain": "example.com",
        "expiry_date": now + timedelta(days=30),
        "status": "VALID"
    },
    {
        "domain": "expired.com",
        "expiry_date": now - timedelta(days=5),
        "status": "EXPIRED"
    },
    {
        "domain": "soon-to-expire.com",
        "expiry_date": now + timedelta(days=3),
        "status": "EXPIRING_SOON"
    },
    {
        "domain": "longvalid.com",
        "expiry_date": now + timedelta(days=400),
        "status": "VALID"
    }
]

certs_df = pd.DataFrame(data)
import pandas as pd
from datetime import datetime, timedelta

# Create mock certificate data
certs_df = pd.DataFrame([
    {"domain": "example.com", "expiry_date": datetime.now() + timedelta(days=30)},
    {"domain": "expired.com", "expiry_date": datetime.now() - timedelta(days=1)},
    {"domain": "soon-to-expire.com", "expiry_date": datetime.now() + timedelta(days=3)},
    {"domain": "longvalid.com", "expiry_date": datetime.now() + timedelta(days=365)},
])

# Add a column to check expiry status
def get_status(expiry):
    now = datetime.now()
    if expiry < now:
        return "EXPIRED"
    elif expiry < now + timedelta(days=7):
        return "EXPIRING_SOON"
    else:
        return "VALID"

certs_df["status"] = certs_df["expiry_date"].apply(get_status)

from fastapi import FastAPI, HTTPException
import sqlite3
from datetime import datetime

app = FastAPI(title="Certificate Verifier API")

DB_PATH = "certs.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def enrich_cert(row):
    cert = dict(row)

    if cert.get("expires_at"):
        exp = datetime.fromisoformat(cert["expires_at"].replace(" ", "T"))
        now = datetime.utcnow()
        days_remaining = (exp - now).days

        cert["days_remaining"] = days_remaining
        cert["status"] = "EXPIRED" if days_remaining < 0 else "VALID"
    else:
        cert["days_remaining"] = None
        cert["status"] = "UNKNOWN"

    return cert


@app.get("/certs")
def get_all_certs():
    conn = get_db()
    rows = conn.execute("SELECT * FROM certificates").fetchall()
    conn.close()
    return [enrich_cert(row) for row in rows]


@app.get("/certs/{cert_id}")
def get_cert_by_id(cert_id: int):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM certificates WHERE id = ?", (cert_id,)
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Certificate not found")

    return enrich_cert(row)


@app.get("/certs/expired")
def get_expired_certs():
    conn = get_db()
    rows = conn.execute("SELECT * FROM certificates").fetchall()
    conn.close()

    return [enrich_cert(r) for r in rows if enrich_cert(r)["status"] == "EXPIRED"]


@app.get("/certs/valid")
def get_valid_certs():
    conn = get_db()
    rows = conn.execute("SELECT * FROM certificates").fetchall()
    conn.close()

    return [enrich_cert(r) for r in rows if enrich_cert(r)["status"] == "VALID"]


@app.get("/certs/expiring")
def get_expiring_certs(days: int = 30):
    conn = get_db()
    rows = conn.execute("SELECT * FROM certificates").fetchall()
    conn.close()

    expiring = []
    for row in rows:
        cert = enrich_cert(row)
        if cert["status"] == "VALID" and cert["days_remaining"] <= days:
            expiring.append(cert)

    return expiring
from fastapi import FastAPI
import sqlite3

DB_PATH = "certs.db"

app = FastAPI(title="Certificate Control Plane")
from fastapi import FastAPI, HTTPException
import sqlite3
from datetime import datetime

app = FastAPI(title="Certificate Verifier API")

DB_PATH = "certs.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def calculate_days_remaining(expires_at: str) -> int:
    exp = datetime.fromisoformat(expires_at.replace(" ", "T"))
    return (exp - datetime.utcnow()).days


@app.get("/certs")
def get_all_certs():
    conn = get_db()
    rows = conn.execute("SELECT * FROM certificates").fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.get("/certs/{cert_id}")
def get_cert_by_id(cert_id: int):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM certificates WHERE id = ?", (cert_id,)
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Certificate not found")

    return dict(row)


@app.get("/certs/expired")
def get_expired_certs():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM certificates WHERE status = 'EXPIRED'"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.get("/certs/valid")
def get_valid_certs():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM certificates WHERE status = 'VALID'"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.get("/certs/expiring")
def get_expiring_certs(days: int = 30):
    conn = get_db()
    rows = conn.execute("SELECT * FROM certificates").fetchall()
    conn.close()

    expiring = []
    for row in rows:
        if row["expires_at"]:
            remaining = calculate_days_remaining(row["expires_at"])
            if 0 <= remaining <= days:
                cert = dict(row)
                cert["days_remaining"] = remaining
                expiring.append(cert)

    return expiring

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.get("/")
def root():
    return {"status": "running"}

@app.get("/certs")
def list_certs():
    conn = get_db()
    rows = conn.execute("SELECT * FROM certificates").fetchall()
    conn.close()
    return [dict(row) for row in rows]

@app.get("/health")
def health():
    return {"status": "ok"}

from fastapi import FastAPI
app = FastAPI()

@app.get("/certs")
def get_certs():
    return {"message": "FastAPI running"}

@app.get("/health")
def health():
    return {"status": "ok"}

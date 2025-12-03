from fastapi import FastAPI, HTTPException
import os

from app.crypto_utils import load_private_key, decrypt_seed
from app.totp_utils import generate_totp_code, verify_totp_code

app = FastAPI()

DATA_PATH = "/data/seed.txt"
PRIVATE_KEY_PATH = "/app/student_private.pem"


@app.post("/decrypt-seed")
def decrypt_seed_route(payload: dict):
    if "encrypted_seed" not in payload:
        raise HTTPException(status_code=400, detail="Missing encrypted seed")

    encrypted_seed_b64 = payload["encrypted_seed"]

    try:
        private_key = load_private_key(PRIVATE_KEY_PATH)
        seed_hex = decrypt_seed(encrypted_seed_b64, private_key)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Save seed to persistent volume
    os.makedirs("/data", exist_ok=True)
    with open(DATA_PATH, "w") as f:
        f.write(seed_hex)

    return {"status": "ok"}


@app.get("/generate-2fa")
def generate_2fa():
    if not os.path.exists(DATA_PATH):
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    seed_hex = open(DATA_PATH).read().strip()
    code, seconds = generate_totp_code(seed_hex)

    return {"code": code, "valid_for": seconds}


@app.post("/verify-2fa")
def verify_2fa(payload: dict):
    if "code" not in payload:
        raise HTTPException(status_code=400, detail="Missing code")

    if not os.path.exists(DATA_PATH):
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    seed_hex = open(DATA_PATH).read().strip()
    code = payload["code"]

    valid = verify_totp_code(seed_hex, code)

    return {"valid": valid}

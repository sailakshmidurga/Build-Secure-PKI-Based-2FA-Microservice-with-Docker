#!/usr/bin/env python3
import os
from datetime import datetime, timezone
from app.totp_utils import generate_totp_code

SEED_PATH = "/data/seed.txt"
LOG_PATH = "/cron/last_code.txt"

def main():
    if not os.path.exists(SEED_PATH):
        print("Seed not available", flush=True)
        return

    seed_hex = open(SEED_PATH).read().strip()
    code, _ = generate_totp_code(seed_hex)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    line = f"{timestamp} - 2FA Code: {code}\n"

    with open(LOG_PATH, "a") as f:
        f.write(line)

if __name__ == "__main__":
    main()

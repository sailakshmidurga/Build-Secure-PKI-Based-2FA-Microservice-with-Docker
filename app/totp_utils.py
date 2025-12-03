import base64
import hashlib
import hmac
import time


def hex_seed_to_base32(hex_seed: str) -> str:
    """Convert 64 hex chars → bytes → base32 string."""
    seed_bytes = bytes.fromhex(hex_seed)
    return base64.b32encode(seed_bytes).decode("utf-8")


def generate_totp_code(hex_seed: str) -> (str, int):
    """
    Generate a 6-digit TOTP code using:
    - SHA-1
    - 30s period
    - base32-encoded seed
    Returns: (code, seconds_remaining)
    """

    base32_seed = hex_seed_to_base32(hex_seed)
    key = base64.b32decode(base32_seed)

    period = 30
    current_time = int(time.time())
    counter = current_time // period
    time_remaining = period - (current_time % period)

    # Convert counter to 8-byte big-endian
    counter_bytes = counter.to_bytes(8, "big")

    # HMAC-SHA1
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    # Dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    code_int = (
        ((hmac_hash[offset] & 0x7F) << 24)
        | ((hmac_hash[offset + 1] & 0xFF) << 16)
        | ((hmac_hash[offset + 2] & 0xFF) << 8)
        | (hmac_hash[offset + 3] & 0xFF)
    )

    code = str(code_int % 1_000_000).zfill(6)
    return code, time_remaining


def verify_totp_code(hex_seed: str, code: str, tolerance_periods: int = 1) -> bool:
    """Verify TOTP in ± 1 window (period=30s)."""

    if not code.isdigit() or len(code) != 6:
        return False

    for offset in range(-tolerance_periods, tolerance_periods + 1):
        t = int(time.time()) + (offset * 30)
        counter = t // 30

        base32_seed = hex_seed_to_base32(hex_seed)
        key = base64.b32decode(base32_seed)
        counter_bytes = counter.to_bytes(8, "big")

        hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        dynamic_offset = hmac_hash[-1] & 0x0F

        truncated = (
            ((hmac_hash[dynamic_offset] & 0x7F) << 24)
            | ((hmac_hash[dynamic_offset + 1] & 0xFF) << 16)
            | ((hmac_hash[dynamic_offset + 2] & 0xFF) << 8)
            | (hmac_hash[dynamic_offset + 3] & 0xFF)
        )

        candidate = str(truncated % 1_000_000).zfill(6)

        if candidate == code:
            return True

    return False

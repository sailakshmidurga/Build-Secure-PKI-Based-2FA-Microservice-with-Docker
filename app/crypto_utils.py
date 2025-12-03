import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


def load_private_key(path: str):
    """Load student private key (PEM format)."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
        )


def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64 encrypted seed using RSA/OAEP (SHA-256).
    Returns 64-hex-character seed.
    """

    # 1. Base64 decode ---------------------------------------------------------
    try:
        ciphertext = base64.b64decode(encrypted_seed_b64)
    except Exception:
        raise ValueError("Invalid base64 encrypted seed")

    # 2. RSA-OAEP decrypt ------------------------------------------------------
    try:
        seed_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception:
        raise ValueError("RSA decryption failed")

    # 3. Convert to UTF-8 text -------------------------------------------------
    try:
        seed_hex = seed_bytes.decode("utf-8")
    except Exception:
        raise ValueError("Seed is not UTF-8 decodable")

    # 4. Validate 64 hex characters -------------------------------------------
    if len(seed_hex) != 64:
        raise ValueError("Seed must be 64 hex characters")

    allowed = "0123456789abcdef"
    if any(c not in allowed for c in seed_hex):
        raise ValueError("Seed must be lowercase hexadecimal")

    # 5. Done -----------------------------------------------------------------
    return seed_hex

from cryptography.fernet import Fernet
import os

KEY_FILE = "data/key.key"

# Generate and save encryption key (if not already present)
def generate_key() -> None:
    """Generate a new key and save it to KEY_FILE."""
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        os.makedirs("data", exist_ok=True)
        with open(KEY_FILE, "wb") as f:
            f.write(key)

# Load encryption key from file (auto-generate if missing)
def load_key() -> bytes:
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, "rb") as f:
        return f.read()

# Encrypt plain text string
def encrypt(data: str) -> bytes:
    """Encrypt a string using Fernet."""
    key = load_key()
    f = Fernet(key)
    return f.encrypt(data.encode())

# Decrypt encrypted text
def decrypt(token: bytes) -> str:
    """Decrypt bytes to original string."""
    key = load_key()
    f = Fernet(key)
    try:
        return f.decrypt(token).decode()
    except Exception:
        return "[DECRYPTION FAILED]"

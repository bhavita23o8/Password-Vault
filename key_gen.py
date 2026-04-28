from cryptography.fernet import Fernet
import os

KEY_FILE = "data/key.key"

def generate_key():
    """Generate a new key only if it does not exist."""
    os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
    
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        print(f"Key generated and saved to {KEY_FILE}")
        return key
    else:
        print(f"Key already exists at {KEY_FILE}")
        return None

if __name__ == "__main__":
    generate_key()

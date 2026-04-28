import requests
import hashlib

# API URL for Have I Been Pwned (HIBP) "Pwned Passwords"
PWNED_PASSWORD_API = "https://api.pwnedpasswords.com/range/"

# API URL for "Breached Accounts"
PWNED_EMAIL_API = "https://haveibeenpwned.com/api/v3/breachedaccount/"

def check_password_breach(password: str) -> int:
    """
    Check if the password has been exposed in a data breach.
    Returns number of times seen in breaches (0 = safe).
    Uses k-anonymity model so the password is never fully sent.
    """
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        response = requests.get(PWNED_PASSWORD_API + prefix, timeout=5)
        response.raise_for_status()
        hashes = (line.split(":") for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)  # Number of breaches
        return 0
    except Exception as e:
        print(f"[DEBUG] Password breach check error: {e}")
        return -1  # -1 = check failed


def check_email_breach(email: str, api_key: str, user_agent: str = "PasswordVaultApp") -> list:
    """
    Check if an email/username has been involved in a breach.
    Returns a list of breach names (empty list if none).
    """
    headers = {
        "hibp-api-key": api_key,
        "User-Agent": user_agent
    }
    try:
        response = requests.get(PWNED_EMAIL_API + email, headers=headers, timeout=5)
        if response.status_code == 404:
            return []  # No breach found
        response.raise_for_status()
        breaches = response.json()
        return [breach["Name"] for breach in breaches]
    except Exception as e:
        print(f"[DEBUG] Email breach check error: {e}")
        return []

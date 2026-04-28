import re
import requests

# Common phishing-related keywords
PHISHING_KEYWORDS = [
    "free-login", "bonus", "offer", "secure-update", "verify-now",
    "bank-alert", "account-locked", "login-reset"
]

def is_phishing_url_basic(url: str, debug: bool = False) -> bool:
    """Basic pattern-based phishing check"""
    url = url.strip().lower()

    # Keyword-based detection
    for keyword in PHISHING_KEYWORDS:
        if keyword in url:
            if debug:
                print(f"[DEBUG] Keyword match: {keyword}")
            return True

    # Suspicious domain pattern
    if re.search(r"(login|secure|update)[0-9]*\.(com\.ru|xyz|top|tk|ml|ga|cf)", url):
        if debug:
            print("[DEBUG] Suspicious TLD/domain pattern")
        return True

    # Too many hyphens or subdomains
    if url.count("-") > 5 or url.count(".") > 6:
        if debug:
            print("[DEBUG] Too many hyphens or subdomains")
        return True

    return False


def is_phishing_url_google(url: str, api_key: str, debug: bool = False) -> bool:
    """Check URL using Google Safe Browsing API"""
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    headers = {'Content-Type': 'application/json'}
    payload = {
        "client": {"clientId": "PasswordVault", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(f"{endpoint}?key={api_key}", json=payload, headers=headers, timeout=5)
        response.raise_for_status()
        result = response.json()
        if "matches" in result:
            if debug:
                print(f"[DEBUG] Google Safe Browsing flagged: {url}")
            return True
        return False
    except Exception as e:
        if debug:
            print(f"[DEBUG] Google Safe Browsing API error: {e}")
        return False  # Fail-safe: assume safe if API unavailable


def is_phishing_url(url: str, api_key: str = None, debug: bool = False) -> bool:
    """Combined phishing URL check"""
    if is_phishing_url_basic(url, debug=debug):
        return True
    if api_key and is_phishing_url_google(url, api_key, debug=debug):
        return True
    return False

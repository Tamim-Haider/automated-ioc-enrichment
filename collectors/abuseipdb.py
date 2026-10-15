
import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")
BASE_URL = "https://api.abuseipdb.com/api/v2/check"
REQUEST_TIMEOUT = 15


def check_ip(ip):
    if not API_KEY:
        return {
            "error": "missing_api_key",
            "message": "AbuseIPDB API key is not configured."
        }

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            BASE_URL,
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT
        )
    except requests.Timeout:
        return {
            "error": "timeout",
            "message": "AbuseIPDB request timed out."
        }
    except requests.RequestException as exc:
        return {
            "error": "request_failed",
            "message": str(exc)
        }

    if response.status_code != 200:
        return {
            "error": response.status_code,
            "message": response.text
        }

    try:
        return response.json()
    except ValueError:
        return {
            "error": "invalid_json",
            "message": "AbuseIPDB returned an invalid JSON response."
        }

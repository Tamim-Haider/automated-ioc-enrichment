
import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"
REQUEST_TIMEOUT = 15


def check_ip(ip):
    if not API_KEY:
        return {
            "error": "missing_api_key",
            "message": "VirusTotal API key is not configured."
        }

    url = f"{BASE_URL}/{ip}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
    except requests.Timeout:
        return {
            "error": "timeout",
            "message": "VirusTotal request timed out."
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
            "message": "VirusTotal returned an invalid JSON response."
        }

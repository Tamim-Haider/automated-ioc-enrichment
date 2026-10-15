
import requests

from utils.validator import validate_ip


FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
REQUEST_TIMEOUT = 30


def fetch_malicious_ips():
    try:
        response = requests.get(
            FEODO_URL,
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()

    except requests.Timeout:
        print("Error: Feodo Tracker request timed out.")
        return []

    except requests.RequestException as exc:
        print(f"Error: Unable to retrieve Feodo Tracker feed: {exc}")
        return []

    ips = []

    for line in response.text.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if validate_ip(line):
            ips.append(line)

    return list(dict.fromkeys(ips))

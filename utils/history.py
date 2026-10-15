import json
import os
from datetime import datetime


HISTORY_FILE = "output/scan_history.json"


def save_scan(result, source="manual"):

    history = []

    if os.path.exists(HISTORY_FILE):

        try:
            with open(HISTORY_FILE, "r") as file:
                history = json.load(file)

        except json.JSONDecodeError:
            history = []

    scan_record = {
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "ip": result.get("ip"),
        "status": result.get("status"),
        "source": source,
        "risk_score": result.get(
            "risk", {}
        ).get(
            "score",
            0
        ),
        "risk_level": result.get(
            "risk", {}
        ).get(
            "level",
            "UNKNOWN"
        )
    }

    history.insert(0, scan_record)

    with open(HISTORY_FILE, "w") as file:

        json.dump(
            history,
            file,
            indent=4
        )


def load_history():

    if not os.path.exists(HISTORY_FILE):
        return []

    try:

        with open(HISTORY_FILE, "r") as file:
            return json.load(file)

    except json.JSONDecodeError:

        return []

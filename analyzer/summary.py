def generate_summary(results):

    total = len(results)

    low = 0
    medium = 0
    high = 0
    critical = 0
    invalid = 0

    for result in results:

        if result.get("status") == "invalid":

            invalid += 1
            continue

        level = result.get(
            "risk",
            {}
        ).get(
            "level",
            "UNKNOWN"
        )

        if level == "LOW":
            low += 1

        elif level == "MEDIUM":
            medium += 1

        elif level == "HIGH":
            high += 1

        elif level == "CRITICAL":
            critical += 1

    return {
        "total_iocs": total,
        "low": low,
        "medium": medium,
        "high": high,
        "critical": critical,
        "invalid": invalid
    }

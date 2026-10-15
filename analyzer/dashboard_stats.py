def generate_dashboard_stats(results):

    total_iocs = len(results)

    low = 0
    medium = 0
    high = 0
    critical = 0
    invalid = 0
    unsupported = 0

    vt_malicious = 0
    vt_suspicious = 0
    abuse_reports = 0

    for result in results:

        status = result.get("status")

        if status == "invalid":
            invalid += 1
            continue

        if status == "unsupported":
            unsupported += 1
            continue

        risk = result.get("risk", {})

        level = risk.get(
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

        virustotal = result.get(
            "virustotal",
            {}
        )

        abuseipdb = result.get(
            "abuseipdb",
            {}
        )

        vt_malicious += virustotal.get(
            "malicious",
            0
        )

        vt_suspicious += virustotal.get(
            "suspicious",
            0
        )

        abuse_reports += abuseipdb.get(
            "total_reports",
            0
        )

    return {
        "total_iocs": total_iocs,
        "low": low,
        "medium": medium,
        "high": high,
        "critical": critical,
        "invalid": invalid,
        "unsupported": unsupported,
        "vt_malicious": vt_malicious,
        "vt_suspicious": vt_suspicious,
        "abuse_reports": abuse_reports
    }

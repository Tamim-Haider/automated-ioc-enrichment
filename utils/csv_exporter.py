
import csv
import os


def export_to_csv(results, filename):
    os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)

    fieldnames = [
        "ip",
        "ioc_type",
        "source",
        "status",
        "risk_score",
        "risk_level",
        "vt_malicious",
        "vt_suspicious",
        "vt_reputation",
        "abuse_confidence",
        "abuse_reports",
        "country",
        "asn",
        "as_owner",
    ]

    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for result in results:
            vt = result.get("virustotal") or {}
            abuse = result.get("abuseipdb") or {}
            risk = result.get("risk") or {}

            writer.writerow({
                "ip": result.get("ip", result.get("ioc", "")),
                "ioc_type": result.get("ioc_type", "UNKNOWN"),
                "source": result.get("source", "Unknown"),
                "status": result.get("status", "unknown"),
                "risk_score": risk.get("score", ""),
                "risk_level": risk.get("level", ""),
                "vt_malicious": vt.get("malicious", ""),
                "vt_suspicious": vt.get("suspicious", ""),
                "vt_reputation": vt.get("reputation", ""),
                "abuse_confidence": abuse.get(
                    "abuse_confidence_score", ""
                ),
                "abuse_reports": abuse.get("total_reports", ""),
                "country": vt.get("country", ""),
                "asn": vt.get("asn", ""),
                "as_owner": vt.get("as_owner", ""),
            })

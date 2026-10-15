
import json
import os

from utils.ioc_detector import detect_ioc_type
from utils.validator import validate_ip

from collectors.feodo_tracker import fetch_malicious_ips
from collectors.virustotal import check_ip
from collectors.virustotal_parser import parse_ip_report

from collectors.abuseipdb import check_ip as abuseipdb_check
from collectors.abuseipdb_parser import parse_ip_report as parse_abuseipdb

from analyzer.risk_analyzer import analyze_ioc
from analyzer.risk_score import calculate_risk_score
from analyzer.correlation import correlate_sources

from utils.csv_exporter import export_to_csv


MAX_IPS = 5

JSON_OUTPUT = "output/automated_feed_results.json"
CSV_OUTPUT = "output/automated_feed_results.csv"


def process_ip(ip):
    """Enrich an IP address and assess its threat risk."""

    print(f"\nProcessing: {ip}")

    # Detect IOC type
    ioc_type = detect_ioc_type(ip)
    print(f"IOC Type: {ioc_type}")

    # This automated feed currently supports IP addresses only.
    if ioc_type != "IP":
        print(f"Unsupported IOC type: {ioc_type}")

        return {
            "ioc": ip,
            "ip": ip,
            "ioc_type": ioc_type,
            "source": "Feodo Tracker",
            "status": "unsupported",
            "risk": {
                "score": None,
                "level": "UNAVAILABLE"
            }
        }

    # Validate IP address
    if not validate_ip(ip):
        print("Invalid IP address.")

        return {
            "ioc": ip,
            "ip": ip,
            "ioc_type": ioc_type,
            "source": "Feodo Tracker",
            "status": "invalid",
            "risk": {
                "score": None,
                "level": "UNAVAILABLE"
            }
        }

    print("Valid IP")

    # --------------------------------------------------
    # VirusTotal enrichment
    # --------------------------------------------------

    print("Querying VirusTotal...")

    try:
        virustotal_raw = check_ip(ip)

        vt_ok = (
            isinstance(virustotal_raw, dict)
            and "error" not in virustotal_raw
            and isinstance(virustotal_raw.get("data"), dict)
            and isinstance(
                virustotal_raw["data"].get("attributes"),
                dict
            )
        )

        if vt_ok:
            virustotal_result = parse_ip_report(
                virustotal_raw
            )

            vt_ok = isinstance(virustotal_result, dict)

        else:
            virustotal_result = {}

    except Exception as exc:
        print(f"VirusTotal processing error: {exc}")
        virustotal_raw = {
            "error": "processing_failed",
            "message": str(exc)
        }
        virustotal_result = {}
        vt_ok = False

    if not vt_ok:
        print("Warning: VirusTotal enrichment failed.")

    # --------------------------------------------------
    # AbuseIPDB enrichment
    # --------------------------------------------------

    print("Querying AbuseIPDB...")

    try:
        abuseipdb_raw = abuseipdb_check(ip)

        abuse_ok = (
            isinstance(abuseipdb_raw, dict)
            and "error" not in abuseipdb_raw
            and isinstance(abuseipdb_raw.get("data"), dict)
        )

        if abuse_ok:
            abuseipdb_result = parse_abuseipdb(
                abuseipdb_raw
            )

            abuse_ok = isinstance(abuseipdb_result, dict)

        else:
            abuseipdb_result = {}

    except Exception as exc:
        print(f"AbuseIPDB processing error: {exc}")
        abuseipdb_raw = {
            "error": "processing_failed",
            "message": str(exc)
        }
        abuseipdb_result = {}
        abuse_ok = False

    if not abuse_ok:
        print("Warning: AbuseIPDB enrichment failed.")

    # --------------------------------------------------
    # Handle enrichment failures
    # --------------------------------------------------

    if not vt_ok or not abuse_ok:

        if vt_ok or abuse_ok:
            status = "partial"
        else:
            status = "enrichment_failed"

        errors = {}

        if not vt_ok:
            errors["virustotal"] = virustotal_raw

        if not abuse_ok:
            errors["abuseipdb"] = abuseipdb_raw

        print(
            "Risk assessment unavailable because "
            "one or more enrichment sources failed."
        )

        return {
            "ioc": ip,
            "ip": ip,
            "ioc_type": ioc_type,
            "source": "Feodo Tracker",
            "status": status,
            "virustotal": virustotal_result,
            "abuseipdb": abuseipdb_result,
            "errors": errors,
            "analysis": {
                "findings": [
                    "Risk assessment unavailable because "
                    "one or more enrichment sources failed."
                ]
            },
            "correlation": {
                "cross_source_agreements": 0,
                "evidence": []
            },
            "risk": {
                "score": None,
                "level": "UNAVAILABLE"
            }
        }

    # --------------------------------------------------
    # Threat analysis
    # --------------------------------------------------

    print("Analyzing threat intelligence...")

    analysis = analyze_ioc(
        virustotal_result,
        abuseipdb_result
    )

    # --------------------------------------------------
    # Source correlation
    # --------------------------------------------------

    print("Correlating sources...")

    correlation = correlate_sources(
        virustotal_result,
        abuseipdb_result
    )

    # --------------------------------------------------
    # Risk scoring
    # --------------------------------------------------

    print("Calculating risk score...")

    risk = calculate_risk_score(
        analysis["virustotal_malicious"],
        analysis["virustotal_suspicious"],
        analysis["abuse_confidence_score"]
    )

    # --------------------------------------------------
    # Return processed result
    # --------------------------------------------------

    return {
        "ioc": ip,
        "ip": ip,
        "ioc_type": ioc_type,
        "source": "Feodo Tracker",
        "status": "processed",
        "virustotal": virustotal_result,
        "abuseipdb": abuseipdb_result,
        "analysis": analysis,
        "correlation": correlation,
        "risk": risk
    }


def main():
    """Fetch, process, and export Feodo Tracker IP addresses."""

    print("=" * 60)
    print("AUTOMATED IOC FEED PROCESSOR")
    print("=" * 60)

    # --------------------------------------------------
    # Fetch feed
    # --------------------------------------------------

    print("\nFetching malicious IPs from Feodo Tracker...")

    try:
        ips = fetch_malicious_ips()
    except Exception as exc:
        print(f"Error fetching Feodo Tracker feed: {exc}")
        return

    if not ips:
        print(
            "No IP addresses were retrieved. "
            "The feed may be unavailable or empty."
        )
        return

    print(f"Retrieved {len(ips)} IP(s) from feed.")

    # --------------------------------------------------
    # Limit feed processing
    # --------------------------------------------------

    selected_ips = ips[:MAX_IPS]

    print(f"Processing first {len(selected_ips)} IP(s).")

    # --------------------------------------------------
    # Process IP addresses
    # --------------------------------------------------

    results = []

    for ip in selected_ips:
        try:
            result = process_ip(ip)
        except Exception as exc:
            print(f"Unexpected processing error for {ip}: {exc}")

            result = {
                "ioc": ip,
                "ip": ip,
                "ioc_type": "IP",
                "source": "Feodo Tracker",
                "status": "processing_failed",
                "errors": {
                    "processing": {
                        "message": str(exc)
                    }
                },
                "risk": {
                    "score": None,
                    "level": "UNAVAILABLE"
                }
            }

        results.append(result)

    # --------------------------------------------------
    # Prepare output directory
    # --------------------------------------------------

    os.makedirs("output", exist_ok=True)

    # --------------------------------------------------
    # Export JSON
    # --------------------------------------------------

    with open(
        JSON_OUTPUT,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            results,
            file,
            indent=4,
            ensure_ascii=False
        )

    print(f"\nJSON results saved to: {JSON_OUTPUT}")

    # --------------------------------------------------
    # Export CSV
    # --------------------------------------------------

    export_to_csv(
        results,
        CSV_OUTPUT
    )

    print(f"CSV results saved to: {CSV_OUTPUT}")

    # --------------------------------------------------
    # Summary
    # --------------------------------------------------

    processed = sum(
        1 for result in results
        if result.get("status") == "processed"
    )

    unavailable = sum(
        1 for result in results
        if result.get("risk", {}).get("level") == "UNAVAILABLE"
    )

    print("\n" + "=" * 60)
    print("PROCESSING SUMMARY")
    print("=" * 60)
    print(f"Total IPs processed: {len(results)}")
    print(f"Successfully enriched: {processed}")
    print(f"Risk assessments unavailable: {unavailable}")
    print("Processing complete.")


if __name__ == "__main__":
    main()

import argparse
import json

from utils.validator import validate_ip
from utils.ioc_detector import detect_ioc_type

from collectors.virustotal import check_ip
from collectors.virustotal_parser import parse_ip_report

from collectors.abuseipdb import check_ip as abuseipdb_check
from collectors.abuseipdb_parser import parse_ip_report as parse_abuseipdb

from analyzer.risk_analyzer import analyze_ioc
from analyzer.risk_score import calculate_risk_score
from analyzer.correlation import correlate_sources
from analyzer.report_generator import generate_report

from utils.csv_exporter import export_to_csv
from analyzer.summary import generate_summary


def process_ip(ip):

    print(f"\nProcessing: {ip}")

    # --------------------------------------------------
    # IOC TYPE DETECTION
    # --------------------------------------------------

    ioc_type = detect_ioc_type(ip)

    print(f"IOC Type: {ioc_type}")

    # --------------------------------------------------
    # CURRENTLY SUPPORTED IOC TYPE
    # --------------------------------------------------

    if ioc_type != "IP":

        print(
            f"IOC type '{ioc_type}' is currently "
            "not supported for enrichment."
        )

        return {
            "ioc": ip,
            "ioc_type": ioc_type,
            "ip": ip,
            "status": "unsupported"
        }

    # --------------------------------------------------
    # IP VALIDATION
    # --------------------------------------------------

    if not validate_ip(ip):

        print("Invalid IP address.")

        return {
            "ioc": ip,
            "ioc_type": ioc_type,
            "ip": ip,
            "status": "invalid"
        }

    print("Valid IP")

    # --------------------------------------------------
    # VIRUSTOTAL
    # --------------------------------------------------

    print("Querying VirusTotal...")

    virustotal_raw = check_ip(ip)

    virustotal_result = parse_ip_report(
        virustotal_raw
    )

    # --------------------------------------------------
    # ABUSEIPDB
    # --------------------------------------------------

    print("Querying AbuseIPDB...")

    abuseipdb_raw = abuseipdb_check(ip)

    abuseipdb_result = parse_abuseipdb(
        abuseipdb_raw
    )

    # --------------------------------------------------
    # THREAT ANALYSIS
    # --------------------------------------------------

    print("Analyzing threat intelligence...")

    analysis = analyze_ioc(
        virustotal_result,
        abuseipdb_result
    )

    # --------------------------------------------------
    # SOURCE CORRELATION
    # --------------------------------------------------

    print("Correlating sources...")

    correlation = correlate_sources(
        virustotal_result,
        abuseipdb_result
    )

    # --------------------------------------------------
    # RISK SCORE
    # --------------------------------------------------

    print("Calculating risk score...")

    risk = calculate_risk_score(
        analysis["virustotal_malicious"],
        analysis["virustotal_suspicious"],
        analysis["abuse_confidence_score"]
    )

    # --------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------

    result = {
        "ioc": ip,
        "ioc_type": ioc_type,
        "ip": ip,
        "status": "processed",
        "virustotal": virustotal_result,
        "abuseipdb": abuseipdb_result,
        "analysis": analysis,
        "correlation": correlation,
        "risk": risk
    }

    return result


def main():

    # --------------------------------------------------
    # COMMAND-LINE ARGUMENTS
    # --------------------------------------------------

    parser = argparse.ArgumentParser(
        description=(
            "Automated IOC Enrichment and "
            "Threat Intelligence Analysis System"
        )
    )

    parser.add_argument(
        "--ip",
        help="Analyze a single IOC"
    )

    parser.add_argument(
        "--file",
        help="Analyze IOCs from a file"
    )

    args = parser.parse_args()

    # --------------------------------------------------
    # ARGUMENT VALIDATION
    # --------------------------------------------------

    if not args.ip and not args.file:

        parser.error(
            "You must provide either --ip or --file"
        )

    # --------------------------------------------------
    # PROCESS IOCs
    # --------------------------------------------------

    results = []

    # Single IOC
    if args.ip:

        result = process_ip(
            args.ip
        )

        results.append(result)

    # IOC file
    if args.file:

        try:

            with open(
                args.file,
                "r"
            ) as file:

                for line in file:

                    ioc = line.strip()

                    if not ioc:
                        continue

                    result = process_ip(
                        ioc
                    )

                    results.append(result)

        except FileNotFoundError:

            print(
                f"\nError: File not found: {args.file}"
            )

            return

    # --------------------------------------------------
    # SUMMARY
    # --------------------------------------------------

    summary = generate_summary(
        results
    )

    print("\n")

    print("=" * 50)
    print("IOC ANALYSIS SUMMARY")
    print("=" * 50)

    print(
        f"Total IOCs: {summary['total_iocs']}"
    )

    print(
        f"Low Risk: {summary['low']}"
    )

    print(
        f"Medium Risk: {summary['medium']}"
    )

    print(
        f"High Risk: {summary['high']}"
    )

    print(
        f"Critical Risk: {summary['critical']}"
    )

    print(
        f"Invalid: {summary['invalid']}"
    )

    # --------------------------------------------------
    # SAVE JSON RESULTS
    # --------------------------------------------------

    output_file = (
        "output/enrichment_results.json"
    )

    with open(
        output_file,
        "w"
    ) as file:

        json.dump(
            results,
            file,
            indent=4
        )

    print(
        f"\nJSON results saved to: "
        f"{output_file}"
    )

    # --------------------------------------------------
    # GENERATE TEXT REPORT
    # --------------------------------------------------

    report_file = (
        "output/threat_intelligence_report.txt"
    )

    with open(
        report_file,
        "w"
    ) as file:

        for result in results:

            # Only generate the detailed report
            # for successfully processed IPs.

            if result.get("status") == "processed":

                report = generate_report(
                    result
                )

                file.write(
                    report
                )

                file.write(
                    "\n\n"
                )

            else:

                file.write(
                    "=" * 60
                )

                file.write(
                    "\n"
                )

                file.write(
                    "IOC PROCESSING RESULT"
                )

                file.write(
                    "\n"
                )

                file.write(
                    "=" * 60
                )

                file.write(
                    "\n"
                )

                file.write(
                    f"IOC: {result.get('ioc')}\n"
                )

                file.write(
                    f"IOC Type: "
                    f"{result.get('ioc_type')}\n"
                )

                file.write(
                    f"Status: "
                    f"{result.get('status')}\n"
                )

                file.write(
                    "\n\n"
                )

    print(
        f"Report saved to: "
        f"{report_file}"
    )

    # --------------------------------------------------
    # EXPORT CSV
    # --------------------------------------------------

    csv_file = (
        "output/enrichment_results.csv"
    )

    export_to_csv(
        results,
        csv_file
    )

    print(
        f"CSV results saved to: "
        f"{csv_file}"
    )


if __name__ == "__main__":

    main()

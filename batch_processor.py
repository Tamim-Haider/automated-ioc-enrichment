from analyzer.correlation import correlate_sources
from analyzer.report_generator import generate_report
from analyzer.risk_analyzer import analyze_ioc
from analyzer.risk_score import calculate_risk_score
import json

from collectors.abuseipdb import check_ip as abuseipdb_check
from collectors.abuseipdb_parser import parse_ip_report as parse_abuseipdb
from collectors.virustotal import check_ip
from collectors.virustotal_parser import parse_ip_report

from utils.ioc_reader import read_iocs
from utils.validator import validate_ip


INPUT_FILE = "input/iocs.txt"


def process_iocs():

    iocs = read_iocs(INPUT_FILE)

    results = []

    for ip in iocs:

        print(f"\nProcessing: {ip}")

        # Step 1: Validate IP
        if not validate_ip(ip):

            print("Invalid IP")

            results.append({
                "ip": ip,
                "status": "invalid"
            })

            continue

        print("Valid IP")

        # Step 2: Query VirusTotal
        print("Querying VirusTotal...")

        virustotal_raw = check_ip(ip)

        virustotal_result = parse_ip_report(
            virustotal_raw
        )

        # Step 3: Query AbuseIPDB
        print("Querying AbuseIPDB...")

        abuseipdb_raw = abuseipdb_check(ip)

        abuseipdb_result = parse_abuseipdb(
            abuseipdb_raw
        )

        # Step 4: Analyze IOC
        analysis = analyze_ioc(
            virustotal_result,
            abuseipdb_result
        )

        # Step 5: Correlate Sources
        correlation = correlate_sources(
            virustotal_result,
            abuseipdb_result
        )

        # Step 6: Calculate Risk Score
        risk = calculate_risk_score(
            analysis["virustotal_malicious"],
            analysis["virustotal_suspicious"],
            analysis["abuse_confidence_score"]
        )

        # Step 7: Combine Results
        combined_result = {
            "ip": ip,
            "status": "processed",
            "virustotal": virustotal_result,
            "abuseipdb": abuseipdb_result,
            "analysis": analysis,
            "correlation": correlation,
            "risk": risk
        }

        results.append(combined_result)

    return results


if __name__ == "__main__":

    results = process_iocs()

    output_file = "output/enrichment_results.json"

    with open(output_file, "w") as file:

        json.dump(
            results,
            file,
            indent=4
        )

    print("\nResults saved to:")
    print(output_file)

    report_file = "output/threat_intelligence_report.txt"

    with open(report_file, "w") as file:

        for result in results:

            report = generate_report(result)

            file.write(report)
            file.write("\n\n")

    print("\nReport saved to:")
    print(report_file)


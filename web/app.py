from flask import Flask, render_template, request

from utils.validator import validate_ip
from utils.ioc_detector import detect_ioc_type

from collectors.virustotal import check_ip
from collectors.virustotal_parser import parse_ip_report

from collectors.abuseipdb import check_ip as abuseipdb_check
from collectors.abuseipdb_parser import parse_ip_report as parse_abuseipdb

from collectors.feodo_tracker import fetch_malicious_ips

from analyzer.risk_analyzer import analyze_ioc
from analyzer.risk_score import calculate_risk_score
from analyzer.correlation import correlate_sources
from analyzer.summary import generate_summary
from analyzer.dashboard_stats import generate_dashboard_stats

app = Flask(__name__)


def process_ip(ip, source="Manual Input"):

    ioc_type = detect_ioc_type(ip)

    if ioc_type != "IP":

        return {
            "ioc": ip,
            "ip": ip,
            "ioc_type": ioc_type,
            "source": source,
            "status": "unsupported"
        }

    if not validate_ip(ip):

        return {
            "ioc": ip,
            "ip": ip,
            "ioc_type": ioc_type,
            "source": source,
            "status": "invalid",
            "error": "Invalid IP address"
        }

    print(f"\nProcessing: {ip}")
    print(f"IOC Type: {ioc_type}")
    print(f"Source: {source}")

    print("Querying VirusTotal...")

    virustotal_raw = check_ip(ip)

    virustotal_result = parse_ip_report(
        virustotal_raw
    )

    print("Querying AbuseIPDB...")

    abuseipdb_raw = abuseipdb_check(ip)

    abuseipdb_result = parse_abuseipdb(
        abuseipdb_raw
    )

    print("Analyzing threat intelligence...")

    analysis = analyze_ioc(
        virustotal_result,
        abuseipdb_result
    )

    print("Correlating sources...")

    correlation = correlate_sources(
        virustotal_result,
        abuseipdb_result
    )

    print("Calculating risk score...")

    risk = calculate_risk_score(
        analysis["virustotal_malicious"],
        analysis["virustotal_suspicious"],
        analysis["abuse_confidence_score"]
    )

    return {
        "ioc": ip,
        "ip": ip,
        "ioc_type": ioc_type,
        "source": source,
        "status": "processed",
        "virustotal": virustotal_result,
        "abuseipdb": abuseipdb_result,
        "analysis": analysis,
        "correlation": correlation,
        "risk": risk
    }


def process_feed():

    print(
        "\nFetching malicious IPs from Feodo Tracker..."
    )

    ips = fetch_malicious_ips()

    print(
        f"Retrieved {len(ips)} IP(s) from feed."
    )

    selected_ips = ips[:5]

    print(
        f"Processing {len(selected_ips)} IP(s)..."
    )

    results = []

    for ip in selected_ips:

        print(
            f"\nProcessing feed IP: {ip}"
        )

        result = process_ip(
            ip,
            source="Feodo Tracker"
        )

        results.append(result)

    return results


@app.route("/", methods=["GET", "POST"])
def index():

    result = None
    stats = None

    if request.method == "POST":

        ip = request.form.get(
            "ip",
            ""
        ).strip()

        if ip:

            result = process_ip(
                ip,
                source="Manual Input"
            )

            stats = generate_dashboard_stats(
                [result]
            )

    return render_template(
        "index.html",
        result=result,
        stats=stats
    )


@app.route("/feed", methods=["GET"])
def feed():

    results = process_feed()

    stats = generate_dashboard_stats(
        results
    )

    return render_template(
        "feed.html",
        results=results,
        stats=stats
    )


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )

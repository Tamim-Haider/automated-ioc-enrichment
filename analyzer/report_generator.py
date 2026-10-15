def generate_report(result):

    ip = result["ip"]
    status = result["status"]

    virustotal = result.get("virustotal", {})
    abuseipdb = result.get("abuseipdb", {})
    analysis = result.get("analysis", {})
    correlation = result.get("correlation", {})
    risk = result.get("risk", {})

    report = []

    report.append("=" * 60)
    report.append("IOC THREAT INTELLIGENCE REPORT")
    report.append("=" * 60)

    report.append("")
    report.append(f"IOC: {ip}")
    report.append(f"IOC Type: {result.get('ioc_type', 'UNKNOWN')}")
    report.append(f"Source: {result.get('source', 'Unknown')}")
    report.append(f"Status: {status}")

    report.append("")
    report.append("RISK ASSESSMENT")
    report.append("-" * 60)

    report.append(
        f"Risk Score: {risk.get('score', 0)}/100"
    )

    report.append(
        f"Risk Level: {risk.get('level', 'UNKNOWN')}"
    )

    report.append("")
    report.append("VIRUSTOTAL")
    report.append("-" * 60)

    report.append(
        f"Country: {virustotal.get('country')}"
    )

    report.append(
        f"ASN: {virustotal.get('asn')}"
    )

    report.append(
        f"AS Owner: {virustotal.get('as_owner')}"
    )

    report.append(
        f"Network: {virustotal.get('network')}"
    )

    report.append(
        f"Reputation: {virustotal.get('reputation')}"
    )

    report.append(
        f"Malicious: {virustotal.get('malicious', 0)}"
    )

    report.append(
        f"Suspicious: {virustotal.get('suspicious', 0)}"
    )

    report.append(
        f"Harmless: {virustotal.get('harmless', 0)}"
    )

    report.append(
        f"Undetected: {virustotal.get('undetected', 0)}"
    )

    report.append("")
    report.append("ABUSEIPDB")
    report.append("-" * 60)

    report.append(
        f"Country: {abuseipdb.get('country')}"
    )

    report.append(
        f"ISP: {abuseipdb.get('isp')}"
    )

    report.append(
        f"Domain: {abuseipdb.get('domain')}"
    )

    report.append(
        f"Usage Type: {abuseipdb.get('usage_type')}"
    )

    report.append(
        f"Abuse Confidence Score: "
        f"{abuseipdb.get('abuse_confidence_score', 0)}%"
    )

    report.append(
        f"Total Reports: "
        f"{abuseipdb.get('total_reports', 0)}"
    )

    report.append(
        f"Distinct Users: "
        f"{abuseipdb.get('distinct_users', 0)}"
    )

    report.append("")
    report.append("SOURCE CORRELATION")
    report.append("-" * 60)

    report.append(
        f"Cross-source agreements: "
        f"{correlation.get('cross_source_agreements', 0)}"
    )

    correlation_evidence = correlation.get(
        "evidence",
        []
    )

    for item in correlation_evidence:

        report.append(f"- {item}")

    report.append("")
    report.append("ANALYSIS FINDINGS")
    report.append("-" * 60)

    findings = analysis.get("findings", [])

    if findings:

        for finding in findings:

            report.append(f"- {finding}")

    else:

        report.append(
            "No significant findings were identified."
        )

    report.append("")
    report.append("=" * 60)
    report.append("END OF REPORT")
    report.append("=" * 60)

    return "\n".join(report)


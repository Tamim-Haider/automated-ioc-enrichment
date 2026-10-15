def analyze_ioc(virustotal, abuseipdb):

    malicious = virustotal.get("malicious", 0)
    suspicious = virustotal.get("suspicious", 0)

    abuse_score = abuseipdb.get(
        "abuse_confidence_score", 0
    )

    total_reports = abuseipdb.get(
        "total_reports", 0
    )

    reputation = virustotal.get(
        "reputation", 0
    )

    findings = []

    # VirusTotal analysis

    if malicious > 0:

        findings.append(
            f"VirusTotal detected the IP as malicious "
            f"in {malicious} engine(s)."
        )

    if suspicious > 0:

        findings.append(
            f"VirusTotal marked the IP as suspicious "
            f"in {suspicious} engine(s)."
        )

    # AbuseIPDB analysis

    if abuse_score >= 50:

        findings.append(
            f"AbuseIPDB reports an abuse confidence "
            f"score of {abuse_score}%."
        )

    if total_reports > 0:

        findings.append(
            f"AbuseIPDB contains {total_reports} report(s) "
            f"for this IP."
        )

    # Reputation

    if reputation < 0:

        findings.append(
            "VirusTotal reputation is negative."
        )

    return {
        "virustotal_malicious": malicious,
        "virustotal_suspicious": suspicious,
        "abuse_confidence_score": abuse_score,
        "abuse_total_reports": total_reports,
        "virustotal_reputation": reputation,
        "findings": findings
    }

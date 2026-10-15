def correlate_sources(virustotal, abuseipdb):

    evidence = []
    agreements = 0

    vt_malicious = virustotal.get(
        "malicious", 0
    )

    vt_suspicious = virustotal.get(
        "suspicious", 0
    )

    abuse_score = abuseipdb.get(
        "abuse_confidence_score", 0
    )

    total_reports = abuseipdb.get(
        "total_reports", 0
    )

    # VirusTotal evidence

    if vt_malicious > 0:

        evidence.append(
            f"VirusTotal has {vt_malicious} "
            f"malicious detection(s)."
        )

    if vt_suspicious > 0:

        evidence.append(
            f"VirusTotal has {vt_suspicious} "
            f"suspicious detection(s)."
        )

    # AbuseIPDB evidence

    if abuse_score > 0:

        evidence.append(
            f"AbuseIPDB reports an abuse confidence "
            f"score of {abuse_score}%."
        )

    if total_reports > 0:

        evidence.append(
            f"AbuseIPDB contains {total_reports} "
            f"report(s)."
        )

    # Cross-source agreement

    if vt_malicious > 0 and abuse_score >= 50:

        agreements += 1

        evidence.append(
            "VirusTotal and AbuseIPDB both provide "
            "strong threat evidence."
        )

    elif vt_malicious > 0 and abuse_score > 0:

        agreements += 1

        evidence.append(
            "Both VirusTotal and AbuseIPDB provide "
            "some threat evidence."
        )

    elif vt_malicious == 0 and abuse_score >= 50:

        evidence.append(
            "AbuseIPDB provides significant abuse "
            "evidence, while VirusTotal has no "
            "malicious detections."
        )

    elif vt_malicious == 0 and abuse_score == 0:

        evidence.append(
            "Neither source currently provides "
            "strong malicious activity evidence."
        )

    return {
        "cross_source_agreements": agreements,
        "evidence": evidence
    }

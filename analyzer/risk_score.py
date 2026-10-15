def calculate_risk_score(
    malicious,
    suspicious,
    abuse_confidence
):

    score = 0

    # VirusTotal malicious detections
    if malicious > 0:
        score += min(malicious * 5, 40)

    # VirusTotal suspicious detections
    if suspicious > 0:
        score += min(suspicious * 3, 15)

    # AbuseIPDB confidence
    score += round(
        abuse_confidence * 0.4
    )

    # Maximum score
    score = min(score, 100)

    # Determine level
    if score >= 80:
        level = "CRITICAL"

    elif score >= 60:
        level = "HIGH"

    elif score >= 30:
        level = "MEDIUM"

    else:
        level = "LOW"

    return {
        "score": score,
        "level": level
    }

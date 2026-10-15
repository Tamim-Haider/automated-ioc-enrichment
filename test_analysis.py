from analyzer.risk_analyzer import analyze_ioc
from analyzer.risk_score import calculate_risk_score


virustotal = {
    "malicious": 5,
    "suspicious": 2,
    "reputation": -10
}

abuseipdb = {
    "abuse_confidence_score": 80,
    "total_reports": 120
}


analysis = analyze_ioc(
    virustotal,
    abuseipdb
)

risk = calculate_risk_score(
    analysis["virustotal_malicious"],
    analysis["virustotal_suspicious"],
    analysis["abuse_confidence_score"]
)


print("Analysis")
print("========")

for finding in analysis["findings"]:
    print("-", finding)

print("\nRisk")
print("====")

print("Score:", risk["score"])
print("Level:", risk["level"])

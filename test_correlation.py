from analyzer.correlation import correlate_sources


virustotal = {
    "malicious": 5,
    "suspicious": 2
}

abuseipdb = {
    "abuse_confidence_score": 85,
    "total_reports": 120
}


result = correlate_sources(
    virustotal,
    abuseipdb
)


print("Correlation Analysis")
print("====================")

print(
    "Cross-source agreements:",
    result["cross_source_agreements"]
)

print("\nEvidence:")

for item in result["evidence"]:

    print("-", item)

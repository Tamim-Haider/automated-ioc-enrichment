from utils.csv_exporter import export_to_csv


results = [
    {
        "ip": "8.8.8.8",
        "status": "processed",

        "virustotal": {
            "malicious": 0,
            "suspicious": 0,
            "reputation": 562,
            "country": "US",
            "asn": 15169,
            "as_owner": "Google LLC"
        },

        "abuseipdb": {
            "abuse_confidence_score": 0,
            "total_reports": 0
        },

        "risk": {
            "score": 0,
            "level": "LOW"
        }
    }
]


export_to_csv(
    results,
    "output/test_results.csv"
)

print("CSV created successfully.")

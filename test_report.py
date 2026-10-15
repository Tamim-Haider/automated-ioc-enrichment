from analyzer.report_generator import generate_report


test_result = {

    "ip": "8.8.8.8",
    "ioc_type": "IP",
    "source": "Manual Input",
    "status": "processed",

    "virustotal": {
        "country": "US",
        "asn": 15169,
        "as_owner": "Google LLC",
        "network": "8.8.8.0/24",
        "reputation": 562,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 53,
        "undetected": 38
    },

    "abuseipdb": {
        "country": "US",
        "isp": "Google LLC",
        "domain": "google.com",
        "usage_type": "Data Center/Web Hosting/Transit",
        "abuse_confidence_score": 0,
        "total_reports": 0,
        "distinct_users": 0
    },

    "analysis": {
        "findings": []
    },

    "risk": {
        "score": 0,
        "level": "LOW"
    }
}


report = generate_report(test_result)

print(report)

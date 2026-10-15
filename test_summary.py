from analyzer.summary import generate_summary


results = [
    {
        "ip": "1.1.1.1",
        "status": "processed",
        "risk": {
            "level": "LOW"
        }
    },
    {
        "ip": "2.2.2.2",
        "status": "processed",
        "risk": {
            "level": "HIGH"
        }
    },
    {
        "ip": "3.3.3.3",
        "status": "processed",
        "risk": {
            "level": "CRITICAL"
        }
    },
    {
        "ip": "invalid",
        "status": "invalid"
    }
]


summary = generate_summary(results)


print("IOC SUMMARY")
print("===========")

print(
    "Total IOCs:",
    summary["total_iocs"]
)

print(
    "Low:",
    summary["low"]
)

print(
    "Medium:",
    summary["medium"]
)

print(
    "High:",
    summary["high"]
)

print(
    "Critical:",
    summary["critical"]
)

print(
    "Invalid:",
    summary["invalid"]
)

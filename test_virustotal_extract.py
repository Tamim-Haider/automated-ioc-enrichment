from collectors.virustotal import check_ip


ip = "8.8.8.8"

result = check_ip(ip)

if "data" not in result:
    print("Error:")
    print(result)
    exit()

attributes = result["data"]["attributes"]

print("IP Address:", ip)
print("Country:", attributes.get("country"))
print("Continent:", attributes.get("continent"))
print("ASN:", attributes.get("asn"))
print("AS Owner:", attributes.get("as_owner"))
print("Network:", attributes.get("network"))
print("Reputation:", attributes.get("reputation"))
print("Tags:", attributes.get("tags"))


stats = attributes.get("last_analysis_stats", {})

print("\nDetection Statistics")
print("--------------------")
print("Harmless:", stats.get("harmless", 0))
print("Malicious:", stats.get("malicious", 0))
print("Suspicious:", stats.get("suspicious", 0))
print("Timeout:", stats.get("timeout", 0))
print("Undetected:", stats.get("undetected", 0))


results = attributes.get("last_analysis_results", {})

print("\nEngine Results")
print("--------------")

for engine, details in results.items():

    category = details.get("category")
    result_name = details.get("result")

    if category in ["malicious", "suspicious"]:
        print(
            f"{engine}: {category} ({result_name})"
        )

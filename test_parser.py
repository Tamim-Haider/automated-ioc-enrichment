from collectors.virustotal import check_ip
from collectors.virustotal_parser import parse_ip_report


ip = "8.8.8.8"

raw_result = check_ip(ip)

parsed_result = parse_ip_report(raw_result)

print("\nVirusTotal Enrichment")
print("=====================")

for key, value in parsed_result.items():

    if key != "detections":
        print(f"{key}: {value}")


print("\nMalicious/Suspicious Detections")
print("================================")

for detection in parsed_result["detections"]:

    print(
        f"{detection['engine']} -> "
        f"{detection['category']} -> "
        f"{detection['result']}"
    )

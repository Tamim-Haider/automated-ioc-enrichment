from collectors.abuseipdb import check_ip
from collectors.abuseipdb_parser import parse_ip_report


ip = "8.8.8.8"

raw_result = check_ip(ip)

parsed_result = parse_ip_report(raw_result)

print("\nAbuseIPDB Enrichment")
print("====================")

for key, value in parsed_result.items():

    print(f"{key}: {value}")

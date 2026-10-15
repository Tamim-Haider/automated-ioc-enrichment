from collectors.feodo_tracker import fetch_malicious_ips


ips = fetch_malicious_ips()

print("Number of IPs retrieved:", len(ips))

print("\nFirst 10 IPs:")

for ip in ips[:10]:
    print(ip)

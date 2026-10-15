from utils.validator import validate_ip

test_ips = [
    "8.8.8.8",
    "1.1.1.1",
    "999.999.999.999",
    "hello"
]

for ip in test_ips:
    if validate_ip(ip):
        print(f"{ip} -> Valid IP")
    else:
        print(f"{ip} -> Invalid IP")

from utils.ioc_detector import detect_ioc_type


test_iocs = [
    "8.8.8.8",
    "1.1.1.1",
    "example.com",
    "www.google.com",
    "https://example.com/login",
    "44d88612fea8a8f36de82e1278abb02f",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb924"
    "27ae41e4649b934ca495991b7852b855",
    "this-is-not-an-ioc"
]


for ioc in test_iocs:

    ioc_type = detect_ioc_type(ioc)

    print(
        f"{ioc:<70} -> {ioc_type}"
    )

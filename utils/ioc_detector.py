import ipaddress
import re


MD5_PATTERN = re.compile(
    r"^[a-fA-F0-9]{32}$"
)

SHA1_PATTERN = re.compile(
    r"^[a-fA-F0-9]{40}$"
)

SHA256_PATTERN = re.compile(
    r"^[a-fA-F0-9]{64}$"
)

URL_PATTERN = re.compile(
    r"^https?://",
    re.IGNORECASE
)

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}"
    r"[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def detect_ioc_type(ioc):

    ioc = ioc.strip()

    if not ioc:
        return "UNKNOWN"

    # IP address
    try:
        ipaddress.ip_address(ioc)
        return "IP"
    except ValueError:
        pass

    # URL
    if URL_PATTERN.match(ioc):
        return "URL"

    # MD5
    if MD5_PATTERN.match(ioc):
        return "MD5"

    # SHA-1
    if SHA1_PATTERN.match(ioc):
        return "SHA1"

    # SHA-256
    if SHA256_PATTERN.match(ioc):
        return "SHA256"

    # Domain
    if DOMAIN_PATTERN.match(ioc):
        return "DOMAIN"

    return "UNKNOWN"

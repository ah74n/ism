import math
import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "bank",
    "paypal",
    "signin",
    "password",
    "wallet"
]


SUSPICIOUS_TLDS = [
    ".xyz",
    ".tk",
    ".top",
    ".club",
    ".cc",
    ".gq"
]


def calculate_entropy(text):

    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]

    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])

    return round(entropy, 2)


def extract_features(url):

    parsed = urlparse(url)

    domain = parsed.netloc if parsed.netloc else parsed.path

    path = parsed.path

    url_length = len(url)

    digit_count = sum(c.isdigit() for c in url)

    digit_ratio = digit_count / url_length if url_length else 0

    special_char_count = len(re.findall(r"[!@#$%^&*(),?\":{}|<>]", url))

    special_char_ratio = (
        special_char_count / url_length if url_length else 0
    )

    entropy = calculate_entropy(url)

    keyword_count = sum(
        keyword in url.lower()
        for keyword in SUSPICIOUS_KEYWORDS
    )

    subdomain_depth = domain.count(".")

    has_https = 1 if url.startswith("https") else 0

    has_ip_address = 1 if re.search(
        r"(?:\d{1,3}\.){3}\d{1,3}",
        url
    ) else 0

    path_depth = len([x for x in path.split("/") if x])

    suspicious_tld = 1 if any(
        tld in domain for tld in SUSPICIOUS_TLDS
    ) else 0

    return [

        url_length,
        digit_ratio,
        special_char_ratio,
        entropy,
        keyword_count,
        subdomain_depth,
        has_https,
        has_ip_address,
        path_depth,
        suspicious_tld
    ]
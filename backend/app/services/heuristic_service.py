
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [

    "login",
    "secure",
    "verify",
    "account",
    "update",
    "bank",
    "paypal",
    "signin",
    "wallet",
    "free",
    "bonus",
    "crypto"
]


SUSPICIOUS_TLDS = [

    ".xyz",
    ".tk",
    ".ru",
    ".top",
    ".gq",
    ".ml",
    ".cf"
]


def analyze_url(url):

    logs = []

    risk_score = 0

    parsed = urlparse(url)

    domain = parsed.netloc or parsed.path

    # URL LENGTH

    if len(url) > 75:

        risk_score += 15

        logs.append(
            "Long URL structure detected."
        )

    # HYPHENS

    hyphen_count = domain.count("-")

    if hyphen_count >= 2:

        risk_score += 20

        logs.append(
            f"Suspicious hyphen usage ({hyphen_count} hyphens)."
        )

    # KEYWORDS

    found_keywords = [

        keyword

        for keyword in SUSPICIOUS_KEYWORDS

        if keyword in url.lower()
    ]

    if found_keywords:

        risk_score += 25

        logs.append(
            f"Suspicious keywords detected: {', '.join(found_keywords)}"
        )

    # TLD CHECK

    for tld in SUSPICIOUS_TLDS:

        if domain.endswith(tld):

            risk_score += 20

            logs.append(
                f"Suspicious TLD detected ({tld})."
            )

            break

    # HTTPS CHECK

    if not url.startswith("https://"):

        risk_score += 10

        logs.append(
            "No HTTPS encryption detected."
        )

    # FINAL STATUS

    if risk_score >= 60:

        status = "malicious"

    elif risk_score >= 30:

        status = "suspicious"

    else:

        status = "safe"

    return {

        "status": status,

        "risk_score": risk_score,

        "logs": logs
    }


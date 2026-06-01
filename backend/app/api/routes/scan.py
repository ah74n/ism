from fastapi import APIRouter
from datetime import datetime
import socket
import ssl
import time
from urllib.parse import urlparse

from app.models.schemas import URLRequest
from app.services.ml_service import predict_url
from app.services.heuristic_service import analyze_url
from app.services.dns_service import analyze_dns

router = APIRouter(prefix="/api")


def calculate_entropy(text):
    import math
    from collections import Counter

    if not text:
        return 0

    counter = Counter(text)
    length = len(text)

    entropy = 0

    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 2)


def get_threat_level(score):
    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


def get_final_verdict(score):
    if score >= 70:
        return "malicious"

    if score >= 40:
        return "suspicious"

    return "safe"


@router.post("/scan")
def scan_url(request: URLRequest):

    start_time = time.time()

    url = request.url.strip()

    parsed = urlparse(url)

    domain = parsed.netloc.replace("www.", "")

    # =========================
    # ML ANALYSIS
    # =========================
    ml_result = predict_url(url)

    # =========================
    # HEURISTIC ANALYSIS
    # =========================
    heuristic_result = analyze_url(url)

    # =========================
    # DNS ANALYSIS
    # =========================
    dns_result = analyze_dns(url)

    # =========================
    # NETWORK INFORMATION
    # =========================
    resolved_ip = None

    try:
        resolved_ip = socket.gethostbyname(domain)
    except:
        resolved_ip = "Unknown"

    network = {
        "resolved_ip": resolved_ip,
        "asn": "Unknown",
        "country": "Unknown",
        "hosting_provider": "Unknown"
    }

    # =========================
    # SSL ANALYSIS
    # =========================
    ssl_info = {
        "valid": False,
        "issuer": "Unknown",
        "expires": "Unknown"
    }

    try:
        context = ssl.create_default_context()

        with context.wrap_socket(
            socket.socket(),
            server_hostname=domain
        ) as s:

            s.settimeout(3)

            s.connect((domain, 443))

            cert = s.getpeercert()

            ssl_info["valid"] = True

            issuer = dict(
                x[0] for x in cert.get("issuer")
            )

            ssl_info["issuer"] = issuer.get(
                "organizationName",
                "Unknown"
            )

            ssl_info["expires"] = cert.get(
                "notAfter",
                "Unknown"
            )

    except:
        pass

    # =========================
    # HEURISTIC DETAILS
    # =========================
    suspicious_keywords = []

    keywords = [
        "login",
        "verify",
        "secure",
        "update",
        "bank",
        "free",
        "gift",
        "wallet",
        "crypto",
        "signin"
    ]

    lower_url = url.lower()

    for word in keywords:
        if word in lower_url:
            suspicious_keywords.append(word)

    excessive_subdomains = domain.count(".") > 3

    ip_based_url = domain.replace(".", "").isdigit()

    punycode_detected = "xn--" in domain

    entropy_score = calculate_entropy(domain)

    heuristics = {
        "suspicious_keywords": suspicious_keywords,
        "excessive_subdomains": excessive_subdomains,
        "ip_based_url": ip_based_url,
        "punycode_detected": punycode_detected,
        "entropy_score": entropy_score
    }

    # =========================
    # THREAT INDICATORS
    # =========================
    threat_indicators = []

    if suspicious_keywords:
        threat_indicators.append(
            "Suspicious keywords detected"
        )

    if entropy_score > 3.8:
        threat_indicators.append(
            "High lexical entropy"
        )

    if excessive_subdomains:
        threat_indicators.append(
            "Excessive subdomains"
        )

    if punycode_detected:
        threat_indicators.append(
            "Punycode detected"
        )

    # =========================
    # FEATURE VECTOR
    # =========================
    feature_vector = {
        "url_length": len(url),
        "digit_ratio": round(
            sum(c.isdigit() for c in url) / max(len(url), 1),
            2
        ),
        "special_char_ratio": round(
            sum(
                not c.isalnum()
                for c in url
            ) / max(len(url), 1),
            2
        )
    }

    if "feature_vector" not in ml_result:
        ml_result["feature_vector"] = feature_vector

    # =========================
    # FINAL SCORE
    # =========================
    risk_score = heuristic_result.get(
        "risk_score",
        0
    )

    final_verdict = get_final_verdict(
        risk_score
    )

    threat_level = get_threat_level(
        risk_score
    )

    end_time = time.time()

    scan_time_ms = int(
        (end_time - start_time) * 1000
    )

    # =========================
    # FINAL RESPONSE
    # =========================
    return {

        "url": url,

        "final_verdict": final_verdict,

        "risk_score": risk_score,

        "threat_level": threat_level,

        "scan_time_ms": scan_time_ms,

        "network": network,

        "ssl": ssl_info,

        "domain_info": {
            "domain": domain,
            "ip": resolved_ip,
            "registrar": "Unknown",
            "creation_date": "Unknown",
            "expiration_date": "Unknown",
            "age_days": "Unknown"
        },

        "heuristics": heuristics,

        "heuristic_logs": heuristic_result.get(
            "logs",
            []
        ),

        "dns_logs": dns_result.get(
            "logs",
            []
        ),

        "ml_analysis": ml_result,

        "threat_indicators": threat_indicators,

        "raw_engine_output": {
            "heuristic_engine": heuristic_result,
            "dns_engine": dns_result,
            "ml_engine": ml_result
        }
    }
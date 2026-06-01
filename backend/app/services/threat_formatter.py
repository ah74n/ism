def determine_severity(score: int):

    if score >= 85:
        return "CRITICAL"

    elif score >= 70:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    else:
        return "LOW"


def build_summary(status: str, indicators: list):

    if status == "malicious":
        return (
            "This URL exhibits multiple indicators commonly associated "
            "with phishing or malicious infrastructure."
        )

    elif status == "suspicious":
        return (
            "This URL contains suspicious characteristics that may "
            "require additional investigation."
        )

    return (
        "No major malicious indicators were detected during analysis."
    )


def classify_indicator(log: str):

    log_lower = log.lower()

    if "keyword" in log_lower:
        return {
            "name": "Credential Harvesting Keywords",
            "severity": "HIGH",
            "description": log
        }

    elif "tld" in log_lower:
        return {
            "name": "Suspicious Top-Level Domain",
            "severity": "MEDIUM",
            "description": log
        }

    elif "entropy" in log_lower:
        return {
            "name": "Algorithmically Generated Domain",
            "severity": "HIGH",
            "description": log
        }

    elif "https" in log_lower:
        return {
            "name": "Missing HTTPS Encryption",
            "severity": "MEDIUM",
            "description": log
        }

    elif "offline" in log_lower:
        return {
            "name": "Inactive Infrastructure",
            "severity": "HIGH",
            "description": log
        }

    elif "mx records verified" in log_lower:
       return {
        "name": "Valid Mail Infrastructure",
        "severity": "INFO",
        "description": log
    }

    elif "no mx" in log_lower:
        return {
        "name": "Missing Mail Infrastructure",
        "severity": "LOW",
        "description": log
    }

    elif "hyphen" in log_lower:
        return {
            "name": "Suspicious URL Structure",
            "severity": "MEDIUM",
            "description": log
        }

    elif "subdomain" in log_lower:
        return {
            "name": "Subdomain Abuse Pattern",
            "severity": "MEDIUM",
            "description": log
        }

    return {
        "name": "General Threat Indicator",
        "severity": "LOW",
        "description": log
    }


def format_threat_report(
    url: str,
    status: str,
    risk_score: int,
    ml_score: int,
    heuristic_logs: list,
    dns_logs: list,
    domain_info: dict
):

    indicators = []

    all_logs = heuristic_logs + dns_logs

    for log in all_logs:
        indicators.append(classify_indicator(log))

    severity = determine_severity(risk_score)

    summary = build_summary(status, indicators)

    return {

    "overview": {

        "url": url,

        "status": status,

        "risk_score": risk_score,

        "severity": severity,

        "confidence": f"{max(55, risk_score)}%",

        "threat_category": (
            "Credential Harvesting / Phishing"
            if risk_score >= 70
            else "Suspicious Infrastructure"
            if risk_score >= 35
            else "Legitimate Infrastructure"
        )
    },

    "infrastructure_intelligence": {

        "domain": domain_info.get("domain"),

        "ip_address": domain_info.get("ip_address"),

        "reachable": domain_info.get("reachable"),

        "https_enabled": domain_info.get("https_enabled"),

        "tld": domain_info.get("tld"),

        "subdomain_depth": domain_info.get("subdomain_depth")
    },

    "behavioral_analysis": {

        "entropy_score": domain_info.get("entropy_score"),

        "entropy_classification":
            domain_info.get("entropy_classification"),

        "digit_ratio": domain_info.get("digit_ratio"),

        "obfuscation_detected":
            domain_info.get("obfuscation_detected"),

        "suspicious_keywords":
            domain_info.get("suspicious_keywords")
    },

    "ml_analysis": {

        "ml_score": ml_score,

        "model_confidence": f"{ml_score}%"
    },

    "analysis": {

        "summary": summary,

        "threat_indicators": indicators
    },

    "sandbox_analysis": {

        "status": "Not Yet Implemented",

        "planned_features": [
            "Redirect tracing",
            "DOM analysis",
            "Screenshot capture",
            "JavaScript behavior analysis"
        ]
    },

    "recommendation": (

        "Avoid interacting with this URL."
        if risk_score >= 70
        else "Exercise caution before trusting this domain."
        if risk_score >= 35
        else "No immediate threat indicators detected."
    )
}
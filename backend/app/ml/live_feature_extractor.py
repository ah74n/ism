
import math
import re

from urllib.parse import urlparse


FEATURE_COLUMNS = [

    "web_is_live",
    "web_security_score",
    "web_forms_count",
    "web_password_fields",
    "web_has_login",
    "web_ssl_valid",

    "url_len",
    "@",
    "?",
    "-",
    "=",
    ".",
    "#",
    "%",
    "+",
    "$",
    "!",
    "*",
    ",",
    "//",

    "digits",
    "letters",

    "abnormal_url",
    "https",
    "Shortining_Service",
    "having_ip_address",

    "defac_has_hacked_terms",
    "defac_has_suspicious_ext",
    "defac_path_depth",
    "defac_is_deep_path",
    "defac_path_underscores",
    "defac_is_gov_edu",
    "defac_has_index_php",
    "defac_has_option_param",

    "phish_has_brand",
    "phish_brand_in_subdomain",
    "phish_brand_in_path",
    "phish_hyphen_count",
    "phish_digit_count",
    "phish_long_domain",
    "phish_many_subdomains",
    "phish_suspicious_tld",
    "phish_keyword_count",
    "phish_has_redirect",
    "phish_param_count",
    "phish_encoded_chars",

    "enh_urgency_count",
    "enh_security_count",
    "enh_brand_count",
    "enh_brand_hijack",
    "enh_subdomain_count",
    "enh_long_path",
    "enh_many_params",
    "enh_suspicious_tld",

    "adv_domain_ngram_entropy",
    "adv_path_entropy",
    "adv_consonant_ratio",
    "adv_vowel_ratio",
    "adv_digit_ratio",
    "adv_subdomain_count",
    "adv_avg_subdomain_len",
    "adv_token_count",
    "adv_avg_token_length"
]


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


BRANDS = [
    "paypal",
    "google",
    "microsoft",
    "apple",
    "amazon",
    "facebook"
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

    if not text:
        return 0

    prob = [
        float(text.count(c)) / len(text)
        for c in dict.fromkeys(list(text))
    ]

    entropy = -sum(
        [p * math.log(p) / math.log(2.0) for p in prob]
    )

    return round(entropy, 3)


def extract_live_features(url):

    parsed = urlparse(url)

    domain = parsed.netloc if parsed.netloc else parsed.path

    path = parsed.path

    features = {

        # WEB FEATURES

        "web_is_live": 1,
        "web_security_score": 0,
        "web_forms_count": 0,
        "web_password_fields": 0,
        "web_has_login": int("login" in url.lower()),
        "web_ssl_valid": int(url.startswith("https")),

        # BASIC URL FEATURES

        "url_len": len(url),
        "@": url.count("@"),
        "?": url.count("?"),
        "-": url.count("-"),
        "=": url.count("="),
        ".": url.count("."),
        "#": url.count("#"),
        "%": url.count("%"),
        "+": url.count("+"),
        "$": url.count("$"),
        "!": url.count("!"),
        "*": url.count("*"),
        ",": url.count(","),
        "//": url.count("//"),

        "digits": sum(c.isdigit() for c in url),
        "letters": sum(c.isalpha() for c in url),

        "abnormal_url": int("@" in url),
        "https": int(url.startswith("https")),
        "Shortining_Service": 0,

        "having_ip_address": int(
            bool(
                re.search(
                    r"(?:\d{1,3}\.){3}\d{1,3}",
                    url
                )
            )
        ),

        # DEFACEMENT FEATURES

        "defac_has_hacked_terms": int(
            any(
                word in url.lower()
                for word in [
                    "hack",
                    "hacked",
                    "deface"
                ]
            )
        ),

        "defac_has_suspicious_ext": int(
            any(
                ext in url.lower()
                for ext in [
                    ".php",
                    ".sql",
                    ".exe"
                ]
            )
        ),

        "defac_path_depth": len(
            [x for x in path.split("/") if x]
        ),

        "defac_is_deep_path": int(
            len(path.split("/")) > 5
        ),

        "defac_path_underscores": path.count("_"),

        "defac_is_gov_edu": int(
            ".gov" in domain or ".edu" in domain
        ),

        "defac_has_index_php": int(
            "index.php" in url.lower()
        ),

        "defac_has_option_param": int(
            "option=" in url.lower()
        ),

        # PHISHING FEATURES

        "phish_has_brand": int(
            any(
                brand in url.lower()
                for brand in BRANDS
            )
        ),

        "phish_brand_in_subdomain": int(
            any(
                brand in domain.lower()
                for brand in BRANDS
            )
        ),

        "phish_brand_in_path": int(
            any(
                brand in path.lower()
                for brand in BRANDS
            )
        ),

        "phish_hyphen_count": url.count("-"),

        "phish_digit_count": sum(
            c.isdigit() for c in url
        ),

        "phish_long_domain": int(
            len(domain) > 30
        ),

        "phish_many_subdomains": int(
            domain.count(".") > 3
        ),

        "phish_suspicious_tld": int(
            any(
                tld in domain
                for tld in SUSPICIOUS_TLDS
            )
        ),

        "phish_keyword_count": sum(
            keyword in url.lower()
            for keyword in SUSPICIOUS_KEYWORDS
        ),

        "phish_has_redirect": int("//" in path),

        "phish_param_count": url.count("&"),

        "phish_encoded_chars": url.count("%"),

        # ENHANCED FEATURES

        "enh_urgency_count": sum(
            word in url.lower()
            for word in [
                "urgent",
                "verify",
                "immediate"
            ]
        ),

        "enh_security_count": sum(
            word in url.lower()
            for word in [
                "secure",
                "ssl",
                "login"
            ]
        ),

        "enh_brand_count": sum(
            brand in url.lower()
            for brand in BRANDS
        ),

        "enh_brand_hijack": int(
            "-" in domain and any(
                brand in domain.lower()
                for brand in BRANDS
            )
        ),

        "enh_subdomain_count": domain.count("."),

        "enh_long_path": int(len(path) > 50),

        "enh_many_params": int(url.count("&") > 3),

        "enh_suspicious_tld": int(
            any(
                tld in domain
                for tld in SUSPICIOUS_TLDS
            )
        ),

        # ADVANCED FEATURES

        "adv_domain_ngram_entropy":
            calculate_entropy(domain),

        "adv_path_entropy":
            calculate_entropy(path),

        "adv_consonant_ratio": 0,

        "adv_vowel_ratio": 0,

        "adv_digit_ratio":
            (
                sum(c.isdigit() for c in url)
                / len(url)
            )
            if len(url)
            else 0,

        "adv_subdomain_count":
            domain.count("."),

        "adv_avg_subdomain_len":
            (
                sum(
                    len(x)
                    for x in domain.split(".")
                )
                /
                max(domain.count("."), 1)
            ),

        "adv_token_count":
            len(
                re.split(r"[-./?=&]", url)
            ),

        "adv_avg_token_length":
            (
                sum(
                    len(x)
                    for x in re.split(
                        r"[-./?=&]",
                        url
                    )
                )
                /
                max(
                    len(
                        re.split(
                            r"[-./?=&]",
                            url
                        )
                    ),
                    1
                )
            )
    }

    return [features[col] for col in FEATURE_COLUMNS]

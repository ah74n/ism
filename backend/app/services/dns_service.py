from urllib.parse import urlparse
import socket


def analyze_dns(url: str):

    logs = []

    try:

        domain = urlparse(url).netloc

        if domain.startswith("www."):
            domain = domain.replace("www.", "")

        ip = socket.gethostbyname(domain)

        logs.append(f"Resolved IP: {ip}")

        return {

            "status": "resolved",

            "ip": ip,

            "logs": logs,

            "domain_info": {
                "domain": domain,
                "ip": ip
            }
        }

    except Exception as e:

        logs.append(str(e))

        return {

            "status": "failed",

            "ip": None,

            "logs": logs,

            "domain_info": {
                "domain": domain if 'domain' in locals() else None,
                "ip": None
            }
        }
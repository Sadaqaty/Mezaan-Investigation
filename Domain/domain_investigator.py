import socket
import whois
import requests
import json
import logging
import ssl
import datetime
from urllib.parse import urlparse
from ipwhois import IPWhois

# ---------------- Logging Setup ----------------
logging.basicConfig(
    filename='domain_investigation.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logging.info("====== Starting Domain Investigation ======")

# ------------- Input --------------
url = "http://43.154.209.241/You-Meezan/download.php?file=Meezan-A.apk"

# ------------- Parse URL --------------
parsed = urlparse(url)
domain = parsed.hostname
logging.info(f"Parsed domain/IP: {domain}")

# ------------- DNS Lookup --------------
try:
    ip = socket.gethostbyname(domain)
    logging.info(f"Resolved IP: {ip}")
except Exception as e:
    ip = domain  # use IP as-is if domain is already IP
    logging.warning(f"DNS resolution failed: {e}")

# ------------- WHOIS Lookup --------------
try:
    whois_info = whois.whois(domain)
    with open("whois_info.txt", "w") as f:
        f.write(str(whois_info))
    logging.info("WHOIS info saved to whois_info.txt")
except Exception as e:
    logging.warning(f"WHOIS lookup failed: {e}")

# ------------- IP Geolocation --------------
try:
    obj = IPWhois(ip)
    results = obj.lookup_rdap()
    with open("ip_geolocation.txt", "w") as f:
        f.write(json.dumps(results, indent=2))
    logging.info("IP Geolocation info saved to ip_geolocation.txt")
except Exception as e:
    logging.warning(f"IP WHOIS lookup failed: {e}")

# ------------- HTTP Headers & Status --------------
try:
    response = requests.get(url, timeout=10)
    with open("http_response_headers.txt", "w") as f:
        f.write(f"Status Code: {response.status_code}\n")
        for k, v in response.headers.items():
            f.write(f"{k}: {v}\n")
    logging.info("HTTP response headers saved.")
except Exception as e:
    logging.warning(f"HTTP request failed: {e}")

# ------------- SSL Certificate (if HTTPS) --------------
if parsed.scheme == 'https':
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                with open("ssl_certificate_info.txt", "w") as f:
                    f.write(json.dumps(cert, indent=2))
                logging.info("SSL certificate info saved.")
    except Exception as e:
        logging.warning(f"SSL certificate fetch failed: {e}")
else:
    logging.info("Skipping SSL cert check (non-HTTPS URL)")

# ------------- VirusTotal (Optional) --------------
# Optional: Put your VirusTotal API key below to enable scanning
VT_API_KEY = ""
if VT_API_KEY:
    try:
        headers = {
            "x-apikey": VT_API_KEY
        }
        vt_url = "https://www.virustotal.com/api/v3/urls"
        scan_resp = requests.post(vt_url, headers=headers, data={"url": url})
        scan_data = scan_resp.json()
        scan_id = scan_data['data']['id']

        report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        report_resp = requests.get(report_url, headers=headers)
        report_data = report_resp.json()
        with open("virustotal_report.json", "w") as f:
            json.dump(report_data, f, indent=2)
        logging.info("VirusTotal report saved.")
    except Exception as e:
        logging.warning(f"VirusTotal lookup failed: {e}")
else:
    logging.info("VirusTotal check skipped (no API key provided)")

logging.info("====== Investigation Complete ======")

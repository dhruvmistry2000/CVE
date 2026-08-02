"""
Fetch the CISA Known Exploited Vulnerabilities catalog in bulk.
https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_all():
    """Returns { cve_id: date_added } for every CVE in the KEV catalog."""
    r = requests.get(KEV_URL, timeout=30)
    r.raise_for_status()
    data = r.json()
    out = {}
    for vuln in data.get("vulnerabilities", []):
        out[vuln["cveID"]] = vuln.get("dateAdded")
    return out


if __name__ == "__main__":
    kev = fetch_all()
    print(f"[KEV] fetched {len(kev)} known-exploited CVEs")

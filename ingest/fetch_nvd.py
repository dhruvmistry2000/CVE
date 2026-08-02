"""
Fetch CVE + CVSS + CWE data from the NVD API 2.0.

Rate limits (see https://nvd.nist.gov/developers/start-here#RateLimits):
  - without an API key: 5 requests per rolling 30s window
  - with NVD_API_KEY env var set: 50 requests per rolling 30s window

Get a free key at https://nvd.nist.gov/developers/request-an-api-key
and add it as a GitHub Actions secret named NVD_API_KEY.
"""
import os
import time
import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.environ.get("NVD_API_KEY")

# Sleep between requests to stay well under the rate limit even on
# retries or unexpected bursts.
SLEEP_SECONDS = 2.0 if API_KEY else 6.5


def _headers():
    return {"apiKey": API_KEY} if API_KEY else {}


def _request(params, retries=3):
    for attempt in range(retries):
        r = requests.get(NVD_API, params=params, headers=_headers(), timeout=30)
        if r.status_code == 200:
            return r.json()
        if r.status_code in (403, 429):
            print(f"[NVD] rate limited (HTTP {r.status_code}), backing off...")
            time.sleep(SLEEP_SECONDS * (attempt + 1))
            continue
        print(f"[NVD] WARNING: HTTP {r.status_code} for params={params}")
        return None
    print(f"[NVD] WARNING: exhausted {retries} retries for params={params}")
    return None


def fetch_by_id(cve_id):
    """Fetch a single CVE by ID. Returns the raw NVD vulnerability item or None."""
    data = _request({"cveId": cve_id})
    time.sleep(SLEEP_SECONDS)
    if not data or not data.get("vulnerabilities"):
        return None
    return data["vulnerabilities"][0]


def fetch_by_keyword(keyword, results_per_page=20):
    """Fetch CVEs matching a keyword search. Returns a list of raw NVD items."""
    data = _request({"keywordSearch": keyword, "resultsPerPage": results_per_page})
    time.sleep(SLEEP_SECONDS)
    if not data:
        return []
    return data.get("vulnerabilities", [])


def normalize(item):
    """Turn a raw NVD vulnerability item into the flat dict our schema wants."""
    c = item.get("cve", {})
    out = {
        "cve_id": c.get("id"),
        "state": c.get("vulnStatus"),
        "published": c.get("published"),
        "last_modified": c.get("lastModified"),
        "description": None,
        "severity": None,
        "cvss_score": None,
        "cvss_vector": None,
        "assigner": c.get("sourceIdentifier"),
        "cwes": [],
    }

    descs = c.get("descriptions", [])
    if descs:
        out["description"] = descs[0].get("value")

    metrics = c.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            m = metrics[key][0]
            data = m.get("cvssData", {})
            out["severity"] = data.get("baseSeverity") or m.get("baseSeverity")
            out["cvss_score"] = data.get("baseScore")
            out["cvss_vector"] = data.get("vectorString")
            break

    for w in c.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                out["cwes"].append(val)

    return out


if __name__ == "__main__":
    # quick manual test: python fetch_nvd.py CVE-2021-44228
    import sys
    item = fetch_by_id(sys.argv[1])
    print(normalize(item) if item else "not found")
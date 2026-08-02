"""
Fetch the daily EPSS score file in bulk (one request for every scored CVE)
rather than querying the API per CVE, per FIRST.org's own guidance.

https://www.first.org/epss/data
"""
import csv
import gzip
import io
import requests

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def fetch_all():
    """Returns { cve_id: (epss_score, epss_percentile, score_date) } for every scored CVE."""
    r = requests.get(EPSS_URL, timeout=60)
    r.raise_for_status()
    text = gzip.decompress(r.content).decode()

    lines = text.splitlines()
    # first line is a comment like: #model_version:v2024.03.14,score_date:2026-08-01
    score_date = "unknown"
    if lines and lines[0].startswith("#"):
        for part in lines[0].lstrip("#").split(","):
            if part.startswith("score_date:"):
                score_date = part.split(":", 1)[1]
        lines = lines[1:]

    reader = csv.DictReader(lines)
    out = {}
    for row in reader:
        out[row["cve"]] = (float(row["epss"]), float(row["percentile"]), score_date)
    return out


def fetch_for(cve_ids):
    """Filter the bulk EPSS file down to just the CVE IDs you care about."""
    all_scores = fetch_all()
    return {cid: all_scores[cid] for cid in cve_ids if cid in all_scores}


if __name__ == "__main__":
    scores = fetch_all()
    print(f"[EPSS] fetched {len(scores)} scored CVEs")

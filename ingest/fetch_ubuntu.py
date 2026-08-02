"""
Fetch package status from Ubuntu's per-CVE JSON API.

This is one request per CVE, which is fine at seed-list scale (a handful
to a few hundred CVEs). For a full database covering every Ubuntu CVE,
switch to cloning https://git.launchpad.net/ubuntu-cve-tracker instead
and parsing its bulk text files - see README.md, "Scaling to a full
database".
"""
import time
import requests

UBUNTU_API = "https://ubuntu.com/security/cves"


def fetch_one(cve_id):
    r = requests.get(f"{UBUNTU_API}/{cve_id}.json", timeout=15)
    if r.status_code != 200:
        return None
    return r.json()


def rows_for(cve_ids, releases):
    """
    Returns a list of dicts: {cve_id, distro, release, package, status, fixed_version}
    for the given CVE IDs across the given Ubuntu releases.
    """
    rows = []
    for cve_id in cve_ids:
        data = fetch_one(cve_id)
        time.sleep(0.5)  # be polite, this is a public free API with no key
        if not data:
            continue
        for pkg in data.get("packages", []):
            pkg_name = pkg.get("name", "")
            for status in pkg.get("statuses", []):
                release = status.get("release_codename") or status.get("release")
                if release not in releases:
                    continue
                rows.append({
                    "cve_id": cve_id,
                    "distro": "ubuntu",
                    "release": release,
                    "package": pkg_name,
                    "status": status.get("status", "unknown"),
                    "fixed_version": status.get("description", "") or f"({status.get('status')})",
                })
    return rows


if __name__ == "__main__":
    from config import SEED_CVE_IDS, UBUNTU_RELEASES
    rows = rows_for(SEED_CVE_IDS, UBUNTU_RELEASES)
    print(f"[Ubuntu] {len(rows)} package status rows for {len(SEED_CVE_IDS)} seed CVEs")

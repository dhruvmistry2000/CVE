"""
Fetch package status from the Debian Security Tracker's bulk JSON file.
https://security-tracker.debian.org/tracker/data/json

This pulls the ~20MB full file once, then filters down to the CVE IDs
you care about. For a full database covering every Debian CVE (not just
your seed list), skip the filtering step and load everything.
"""
import requests

DEBIAN_API = "https://security-tracker.debian.org/tracker/data/json"


def fetch_all():
    r = requests.get(DEBIAN_API, timeout=90)
    r.raise_for_status()
    return r.json()


def rows_for(cve_ids, releases):
    """
    Returns a list of dicts: {cve_id, distro, release, package, status, fixed_version}
    for the given CVE IDs across the given Debian releases.
    """
    full = fetch_all()
    cve_set = set(cve_ids)
    rows = []

    for pkg_name, cve_map in full.items():
        for cve_id, entry in cve_map.items():
            if cve_id not in cve_set:
                continue
            pkg_releases = entry.get("releases", {})
            for release in releases:
                if release not in pkg_releases:
                    continue
                rd = pkg_releases[release]
                status = rd.get("status", "unknown")
                fixed = rd.get("fixed_version") or ""
                if status == "resolved" and fixed:
                    display = fixed
                elif status == "open":
                    display = "(unfixed)"
                else:
                    display = f"({status})"
                rows.append({
                    "cve_id": cve_id,
                    "distro": "debian",
                    "release": release,
                    "package": pkg_name,
                    "status": status,
                    "fixed_version": display,
                })
    return rows


if __name__ == "__main__":
    from config import SEED_CVE_IDS, DEBIAN_RELEASES
    rows = rows_for(SEED_CVE_IDS, DEBIAN_RELEASES)
    print(f"[Debian] {len(rows)} package status rows for {len(SEED_CVE_IDS)} seed CVEs")

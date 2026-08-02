"""
Main ingestion entrypoint. Run this to (re)build cve.sqlite from scratch:

    python ingest/build_db.py

It:
  1. Resolves the working CVE ID list (seed IDs + keyword search hits)
  2. Fetches NVD data (CVSS, CWE, description) for each
  3. Fetches EPSS scores in bulk, filters to our CVE list
  4. Fetches CISA KEV in bulk, filters to our CVE list
  5. Fetches Ubuntu + Debian package status for each
  6. Writes everything into cve.sqlite using schema.sql
  7. Writes version.json so the frontend knows when data last changed
"""
import json
import os
import sqlite3
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from config import SEED_CVE_IDS, SEED_KEYWORDS, UBUNTU_RELEASES, DEBIAN_RELEASES, DB_PATH, VERSION_PATH
import fetch_nvd
import fetch_epss
import fetch_kev
import fetch_debian
import fetch_ubuntu

HERE = os.path.dirname(__file__)
SCHEMA_PATH = os.path.join(HERE, "schema.sql")


def resolve_cve_ids():
    ids = set(SEED_CVE_IDS)
    for kw in SEED_KEYWORDS:
        print(f"[NVD] keyword search: {kw}")
        for item in fetch_nvd.fetch_by_keyword(kw):
            norm = fetch_nvd.normalize(item)
            if norm["cve_id"]:
                ids.add(norm["cve_id"])
    return sorted(ids)


def build():
    cve_ids = resolve_cve_ids()
    print(f"[build] tracking {len(cve_ids)} CVEs total")

    # --- NVD ---
    cve_records = []
    cwe_links = []
    seen_cwes = {}
    for i, cve_id in enumerate(cve_ids):
        print(f"[NVD] {i+1}/{len(cve_ids)} {cve_id}")
        item = fetch_nvd.fetch_by_id(cve_id)
        if not item:
            continue
        norm = fetch_nvd.normalize(item)
        cve_records.append(norm)
        for cwe_id in norm["cwes"]:
            seen_cwes.setdefault(cwe_id, cwe_id)  # name backfilled later if known
            cwe_links.append((cve_id, cwe_id))

    # --- EPSS (bulk, then filter) ---
    print("[EPSS] fetching bulk score file...")
    epss_all = fetch_epss.fetch_all()
    epss_rows = [
        (cid, *epss_all[cid]) for cid in cve_ids if cid in epss_all
    ]
    print(f"[EPSS] matched {len(epss_rows)} of {len(cve_ids)} tracked CVEs")

    # --- CISA KEV (bulk, then filter) ---
    print("[KEV] fetching catalog...")
    kev_all = fetch_kev.fetch_all()
    kev_rows = [(cid, "cisa_kev", f"added {kev_all[cid]}") for cid in cve_ids if cid in kev_all]
    print(f"[KEV] {len(kev_rows)} tracked CVEs are known-exploited")

    # --- Distro status ---
    print("[Debian] fetching tracker...")
    debian_rows = fetch_debian.rows_for(cve_ids, DEBIAN_RELEASES)
    print("[Ubuntu] fetching per-CVE status...")
    ubuntu_rows = fetch_ubuntu.rows_for(cve_ids, UBUNTU_RELEASES)

    # --- Write to SQLite ---
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())
    cur = conn.cursor()

    for r in cve_records:
        cur.execute(
            "INSERT OR REPLACE INTO cves VALUES (?,?,?,?,?,?,?,?,?)",
            (r["cve_id"], r["state"], r["published"], r["last_modified"],
             r["description"], r["severity"], r["cvss_score"], r["cvss_vector"], r["assigner"])
        )
        if r["description"]:
            cur.execute(
                "INSERT INTO cve_fts(cve_id, description) VALUES (?,?)",
                (r["cve_id"], r["description"])
            )

    for cwe_id in seen_cwes:
        cur.execute("INSERT OR IGNORE INTO cwes VALUES (?,?)", (cwe_id, cwe_id))
    for cve_id, cwe_id in cwe_links:
        cur.execute("INSERT OR IGNORE INTO cve_cwes VALUES (?,?)", (cve_id, cwe_id))

    for row in ubuntu_rows + debian_rows:
        cur.execute(
            "INSERT OR REPLACE INTO distro_status VALUES (?,?,?,?,?,?)",
            (row["cve_id"], row["distro"], row["release"], row["package"], row["status"], row["fixed_version"])
        )

    for row in kev_rows:
        cur.execute("INSERT INTO exploits VALUES (?,?,?)", row)

    for cid, score, pct, date in epss_rows:
        cur.execute("INSERT OR REPLACE INTO epss_scores VALUES (?,?,?,?)", (cid, score, pct, date))

    conn.commit()
    conn.close()
    print(f"[build] wrote {DB_PATH} ({os.path.getsize(DB_PATH)} bytes)")

    # --- version.json ---
    version = {
        "version": time.strftime("%Y%m%d%H%M%S", time.gmtime()),
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cve_count": len(cve_records),
    }
    with open(VERSION_PATH, "w") as f:
        json.dump(version, f, indent=2)
    print(f"[build] wrote {VERSION_PATH}: {version}")


if __name__ == "__main__":
    build()

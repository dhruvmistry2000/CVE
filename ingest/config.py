"""
Configuration for the ingestion pipeline.

SEED_CVE_IDS: specific CVEs to always track, regardless of keyword matches.
SEED_KEYWORDS: NVD keywordSearch terms used to pull in additional related
               CVEs each run (e.g. your own package/vendor names).

Start small (a handful of CVE IDs and keywords relevant to your images —
openssl, glibc, curl, etc.) and widen this list over time. For a full
"all CVEs ever" database, replace the NVD keyword-search step in
fetch_nvd.py with a bulk sync against the CVEProject/cvelistV5 git repo
instead (see README.md, "Scaling to a full database").
"""

SEED_CVE_IDS = [
    "CVE-2014-0160",   # Heartbleed
    "CVE-2021-44228",  # Log4Shell
    "CVE-2017-5638",   # Apache Struts RCE
    "CVE-2023-38545",  # curl SOCKS5 heap overflow
    "CVE-2022-0778",   # OpenSSL BN_mod_sqrt infinite loop
]

SEED_KEYWORDS = [
    "openssl",
    "glibc",
]

# Ubuntu releases to check package status against (skip EOL releases you
# don't ship on top of, to save API calls).
UBUNTU_RELEASES = ["noble", "jammy", "focal"]

# Debian releases to check package status against.
DEBIAN_RELEASES = ["bookworm", "bullseye"]

DB_PATH = "cve.sqlite"
VERSION_PATH = "version.json"

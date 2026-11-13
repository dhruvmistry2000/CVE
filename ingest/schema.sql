-- CVE aggregator schema
-- One row per CVE, joined against CWE, EPSS, exploit, and distro tables.

CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    state TEXT,
    published TEXT,
    last_modified TEXT,
    description TEXT,
    severity TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    assigner TEXT
);

CREATE TABLE IF NOT EXISTS cwes (
    cwe_id TEXT PRIMARY KEY,
    name TEXT
);

CREATE TABLE IF NOT EXISTS cve_cwes (
    cve_id TEXT REFERENCES cves(cve_id),
    cwe_id TEXT REFERENCES cwes(cwe_id),
    PRIMARY KEY (cve_id, cwe_id)
);

CREATE TABLE IF NOT EXISTS distro_status (
    cve_id TEXT REFERENCES cves(cve_id),
    distro TEXT,          -- 'ubuntu' | 'debian'
    release TEXT,         -- 'noble', 'bookworm', etc.
    package TEXT,
    status TEXT,
    fixed_version TEXT,
    PRIMARY KEY (cve_id, distro, release, package)
);

CREATE TABLE IF NOT EXISTS exploits (
    cve_id TEXT REFERENCES cves(cve_id),
    source TEXT,           -- 'exploitdb' | 'cisa_kev' | 'github_poc'
    reference TEXT
);

CREATE TABLE IF NOT EXISTS epss_scores (
    cve_id TEXT PRIMARY KEY REFERENCES cves(cve_id),
    epss_score REAL,
    epss_percentile REAL,
    score_date TEXT
);

-- Standalone FTS5 table (no content= option) so column values are
-- actually retrievable, not just searchable. "content=''" (contentless
-- mode) looks tempting to save space, but it discards the indexed text
-- after insertion -- SELECT cve_id FROM cve_fts then returns NULL for
-- every row, which silently breaks any join back to cves.cve_id.
CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(
    cve_id,
    description
);

CREATE VIEW IF NOT EXISTS cve_priority AS
SELECT
    c.cve_id,
    c.severity,
    c.cvss_score,
    e.epss_score,
    e.epss_percentile,
    EXISTS(SELECT 1 FROM exploits x WHERE x.cve_id = c.cve_id AND x.source = 'cisa_kev') AS in_kev,
    EXISTS(SELECT 1 FROM exploits x WHERE x.cve_id = c.cve_id) AS has_public_exploit,
    CASE
        WHEN EXISTS(SELECT 1 FROM exploits x WHERE x.cve_id = c.cve_id AND x.source='cisa_kev') THEN 'act now'
        WHEN e.epss_score > 0.5 AND c.cvss_score >= 7 THEN 'high priority'
        WHEN e.epss_score > 0.1 OR c.cvss_score >= 9 THEN 'monitor'
        ELSE 'low priority'
    END AS triage_bucket
FROM cves c
LEFT JOIN epss_scores e ON e.cve_id = c.cve_id;

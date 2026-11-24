# vulnerabilities-linux

Public vulnerability intelligence portal for Linux, Kubernetes, containers and SAP.

A scheduled GitHub Action runs `collector/collector.py`, stores source-specific history in SQLite, aggregates duplicate CVEs, writes `site/vulns.json`, generates RSS/status files and deploys `site/` to GitHub Pages.

## Sources

- CISA Known Exploited Vulnerabilities (KEV)
- NVD
- OSV.dev and OSV ecosystem dumps
- GitHub Security Advisories
- Kubernetes official CVE feed
- Red Hat Security Data
- Ubuntu Security Notices
- Debian Security Advisories
- Linux kernel CVE announcements
- oss-security
- CISA Cybersecurity Advisories
- ENISA EUVD
- SAP Security Patch Day
- FIRST EPSS

## Deduplication

The database keeps the provenance of each source as `(CVE, source)`, but the public export contains **one entry per CVE**. Source information, affected systems, affected versions and mitigations are merged. NVD is preferred for the CVSS score when available.

Edit `collector/techlist.json` to change coverage.

Informational only; verify against the original vendor or distribution advisory before acting.

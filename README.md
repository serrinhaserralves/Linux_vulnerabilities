# vulnerabilities-linux

Public vulnerability intelligence portal for Linux, Kubernetes, containers and SAP.
A scheduled GitHub Action runs `collector/collector.py`, writes `site/vulns.json` and deploys `site/` to GitHub Pages.

Sources: CISA KEV, NVD, OSV.dev, GitHub Advisories, Kubernetes CVE feed, FIRST EPSS.
Edit `collector/techlist.json` to change coverage. Informational only; verify against vendor advisories.

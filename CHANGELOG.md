# Changelog

All notable changes to Stiglitz are documented here. Dates are approximate.

## v7.5 — Report & risk-score quality

- **Non-saturating risk score** — previously summed per-URL occurrences (the same alert across N URLs blew up the number; almost every scan hit 100/100). Now uses unique types with a base tier from the highest severity present + a quantity bonus with diminishing returns. The CRITICAL band requires a real critical finding or a KEV CVE — soft bonuses (EPSS/JS) cannot manufacture a CRITICAL on their own.
- **Confirmed exploit ≠ verified** — active confirmation separates abusable vulnerabilities (default-login, SQLi, weak ciphers) from hardening verifications (headers, HSTS/CAA, TLS config). Distinct card badges (✓ EXPLOIT CONFIRMED / ✓ VERIFIED) and separate report sections.
- **Effort × Impact matrix** — Big4-style prioritization grid with the high-impact/low-effort quadrant highlighted as ★ quick wins.
- **Diff with previous scan** — "Evolution Since Last Scan" section: new / fixed / persistent vs the previous scan of the same domain.
- **CVSS vector on cards** — shows the full vector (`CVSS:3.1/AV:N/...`) plus a decode of the exploitability fields (attack vector, complexity, privileges, interaction).
- **False-positive reduction** — JS secrets: "Hardcoded Password" no longer matches UI labels; "Private Key" requires a full PEM block. poc_validator no longer flags testssl metadata (scanTime) as an exploit.
- **Scheme normalization** — `target.com` without `https://` now assumes HTTPS, fixing an HTTP 000 abort on HTTPS-only targets.
- **Full English report** — the entire HTML/JSON report and all finding text translated to English.

## v7.4 — stiglitz.sh modularization

The main scanner carried ~2,500 lines of Python embedded in 12 bash heredocs — no syntax check, lint, tests or debugging possible. Extracted into standalone modules, shrinking the scanner from **4,991 → ~1,870 lines**.

- **Report generator → `stiglitz_report.py`** (1,817 lines). Validated byte-identical HTML/JSON output.
- **11 collection heredocs → `lib/*.py`** (scan_metadata, security_headers, version_fingerprint, tech_profile, monitoring_check, secscan, cve_enrich, email_security, zap_config_fix, js_analysis, ratelimit_check). Bodies validated byte-identical to the originals.
- **`eval` removed** from the Nuclei invocation — flag/input strings became bash arrays, which correctly preserve arguments with spaces (e.g. `-H "User-Agent: ..."`).
- **Active confirmation linked to cards** — findings with a matching confirmation show a badge in the report.
- **CI hardened** — new `py_compile` step validates the report generator and all `lib/*.py` on every push/PR.

## v7.3 — Adaptive scanning by technology stack

The scanner detects the target's stack and automatically tunes every tool (Nuclei, ffuf, PROBES, CMS scanners) based on what it finds.

- **Tech Profile Builder** — aggregates httpx `-tech-detect`, katana URL fingerprinting and confirmed version PROBES into `raw/tech_profile.json`.
- **Dynamic Nuclei tags** — extends base tags with stack-specific tags (WordPress → `wordpress,wp`; Spring Boot → `spring,springboot,actuator`; etc.).
- **Expanded version PROBES** — WordPress, Drupal, Joomla, Spring Boot Actuator, Django Debug, Laravel Debug, Apache Struts.
- **Conditional ffuf wordlists** — 10 stack profiles select extra paths on top of the generic list.
- **Conditional CMS scanners** — wpscan / joomscan / droopescan triggered automatically when the CMS is detected (`WPSCAN_API_TOKEN` supported).
- **Technology Inventory report section** — component, detected version, status, known CVEs and detection source.

## v7.3.1 — Report counting & CI fixes

- TLS and email findings now included in the master findings list (`all_f`) — terminal and HTML counts match.
- `email_security` dict converted to standardized findings with CWE.
- CI: `pytest` added via `requirements-dev.txt`; install errors no longer silently swallowed.

## v7.2 — Expanded surface coverage + exploitation engine improvements

- **Dangerous-service scan** — nmap now includes Redis, MongoDB, Elasticsearch, Kubernetes API, etcd, CouchDB, Memcached, MSSQL, PostgreSQL, MySQL. Exposed databases highlighted.
- **security.txt (RFC-9116) check** and **internal IP exposure** detection.
- **Expanded ffuf wordlist** — PHP debug, .NET ELMAH, Laravel, Symfony paths.
- **HTTP form brute force** — auto-detects `/login`, `/signin`, `/auth` and runs hydra `http-post-form`.
- **Advisory-URL filter** — excludes advisory domains (nvd.nist.gov, github.com/security, etc.) from SQLi/XSS targets.
- **`--swarm-dir`** integrates origin-scan findings into the exploitation report.

## v7.1 — Tooling updates

- Go 1.26.3 toolchain; recompiled all ProjectDiscovery binaries.
- sqlmap 1.10.5, nikto 2.6.0, hydra 9.8-dev, katana 1.6.1, trufflehog 3.95.3.
- amass intentionally pinned to v3.19.2 (v5 breaks the CLI interface).

## v7.0 — Full pipeline + CI/CD

- **End-to-end orchestrator** chaining OSINT → recon/scan → exploitation → PCI, with a single authorization gate and consolidated HTML index.
- **Exploitation engine refactored** into a thin orchestrator delegating to independent `lib/` modules (recon, crawl, sqli, xss, brute, msf, web).
- **Scan-completion notifications** — Telegram, Slack, Microsoft Teams.
- **Automatic scan diff** — detects the previous scan of the same domain and generates a diff report.
- **CI/CD** — GitHub Actions syntax check + Python unit tests on every push/PR.

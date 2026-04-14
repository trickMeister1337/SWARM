# 🕷️ SWARM - Security Workflow and Risk Management

> Automated web security scanner — subfinder + httpx + nmap + Nuclei + OWASP ZAP, unified into a single HTML report.

![Bash](https://img.shields.io/badge/Shell-Bash-4EAA25?logo=gnu-bash&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?logo=kalilinux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Overview

SWARM is a modular bash script that chains industry-standard security tools into a single automated assessment pipeline. It discovers subdomains, maps the attack surface, scans for vulnerabilities with Nuclei templates, and runs a full OWASP ZAP active scan — then consolidates everything into a clean, self-contained HTML report with full evidence.

```
subfinder → httpx + nmap → testssl → nuclei → exploit confirm → owasp zap (+ openapi) → screenshots → HTML report
```

---

## Features

- **Subdomain enumeration** via subfinder with automatic fallback
- **HTTP surface mapping** — status codes, titles, technology fingerprinting
- **Port scanning** — common web ports (80, 443, 8080, 8443, 8000, 8888, 3000, 9090)
- **TLS/SSL analysis** via testssl — cipher suites, protocol versions, certificate issues, CVEs
- **Vulnerability scanning** via Nuclei (CVE, misconfig, default-login, exposure templates)
- **Active exploit confirmation** — re-executes each Nuclei curl payload, captures live HTTP response
- **OpenAPI/Swagger auto-import** — detects spec endpoints and imports into ZAP before scanning
- **Dynamic analysis** via OWASP ZAP — Spider + Active Scan, runs to 100% completion with no timeout
- **Full evidence capture** — request, response, curl command, attack payload, TLS findings
- **Evidence screenshots** — chromium headless captures target + vulnerable URLs, embedded as base64
- **Smart deduplication** — Low/Info ZAP alerts grouped by type to reduce noise
- **Self-contained HTML report** — no external dependencies to open
- **87-test test harness** included

---

## Requirements

### Mandatory
| Tool | Purpose |
|---|---|
| `bash` | Script runtime |
| `curl` | Connectivity check + ZAP API calls |
| `python3` | Report generation |

### Optional (phases skipped gracefully if absent)
| Tool | Install | Purpose |
|---|---|---|
| `subfinder` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | Subdomain discovery |
| `httpx` | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` | HTTP surface mapping |
| `nmap` | `sudo apt install nmap` | Port + service detection |
| `nuclei` | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | Template-based vuln scan |
| `testssl` | `sudo apt install testssl.sh` | TLS/SSL cipher and certificate analysis |
| `zaproxy` | `sudo apt install zaproxy` | Active web application scan |
| `chromium` | `sudo apt install chromium` | Evidence screenshots (headless) |
| `jq` | `sudo apt install jq` | JSON processing |

> **Go tools path:** SWARM automatically adds `~/go/bin` to PATH at startup, so `bash swarm.sh` works without sourcing `.bashrc`.

### Install all at once (Kali Linux)
```bash
sudo apt update && sudo apt install -y nmap jq zaproxy testssl.sh chromium
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

---

## Installation

```bash
git clone https://github.com/trickMeister1337/swarm.git
cd swarm
chmod +x swarm.sh test_swarm.sh
```

---

## Usage

### Validate first
```bash
bash test_swarm.sh
```
All 62 tests should pass before running against a live target.

### Run a scan
```bash
bash swarm.sh https://target.com
```

### Output structure
```
scan_target.com_20260413_143022/
├── relatorio_swarm.html      ← open in browser
└── raw/
    ├── subdomains.txt        ← subfinder output
    ├── httpx_results.txt     ← active hosts
    ├── nmap.txt              ← port scan
    ├── nuclei.json           ← findings (JSONL)
    ├── nuclei_error.log
    ├── zap_daemon.log        ← ZAP startup log
    ├── zap_alerts.json       ← ZAP alerts (JSON)
    └── zap_evidencias.xml    ← ZAP full report (XML)
```

---

## Configuration

Edit the variables at the top of `swarm.sh`:

```bash
ZAP_PORT=8080
ZAP_HOST="127.0.0.1"
ZAP_SPIDER_TIMEOUT=0       # 0 = no timeout (waits for 100%)
ZAP_SCAN_TIMEOUT=0         # 0 = no timeout (waits for 100%)
NUCLEI_RATE_LIMIT=50       # requests/second
NUCLEI_CONCURRENCY=10      # parallel templates
```

### Rate limit guidance

| Environment | Recommended rate limit |
|---|---|
| Production / sensitive target | 20–30 |
| Staging / default | 50 |
| Internal lab | 100–150 |

---

## Report

The HTML report is fully self-contained (no external requests). It includes:

1. **Executive Summary** — severity counters + 0–100 risk score bar
2. **Attack Surface** — subdomains, active hosts, open ports/services
3. **Critical / High / Medium findings** — full cards with:
   - CVE reference (extracted from ZAP references) or CWE fallback
   - Vulnerable URL and parameter
   - Attack payload used
   - Full evidence (request, response, curl command)
   - Remediation guidance
4. **TLS/SSL findings** — table from testssl (CRITICAL/HIGH/WARN/LOW severities)
5. **Exploit confirmations** — live re-execution results for each Nuclei finding
6. **Evidence screenshots** — base64-embedded captures of target and vulnerable URLs
7. **Low / Informational findings** — deduplicated summary table grouped by alert type
8. **Appendix** — links to raw output files

---

## How OWASP ZAP Integration Works

SWARM manages the full ZAP lifecycle:

- Checks for a pre-existing ZAP instance and reuses it if found
- Kills stale/locked instances and removes `~/.ZAP/zap.lock`
- Patches `~/.ZAP/config.xml` to authorize API access from `127.0.0.1`
- Starts ZAP in daemon mode and waits up to 180s for the API to be ready
- Runs Spider → Active Scan, polling progress every 10s until **100% completion**
- Collects all alerts with full evidence (evidence, parameter, attack payload)
- Only shuts down ZAP if SWARM started it (preserves pre-existing sessions)

---

## Legal Disclaimer

> **SWARM is intended for authorized security testing only.**
>
> Use of this tool against systems you do not own or have explicit written permission to test is illegal and unethical. The authors assume no liability for misuse. Always obtain proper authorization before conducting security assessments.

---

## Contributing

Contributions are welcome. Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Run the test harness and ensure all 87 tests pass (`bash test_swarm.sh`)
4. Submit a pull request with a clear description of the change

---

## License

MIT License — see [LICENSE](LICENSE) for details.

# 🕷️ SWARM

> Automated web security scanner — subfinder + httpx + nmap + testssl + Nuclei + OWASP ZAP, unified into a single self-contained HTML report.

![Bash](https://img.shields.io/badge/Shell-Bash-4EAA25?logo=gnu-bash&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20%7C%20Ubuntu-557C94?logo=linux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Overview

SWARM is a modular bash script that chains industry-standard security tools into a single automated assessment pipeline. It discovers subdomains, maps the attack surface, analyzes TLS, scans for vulnerabilities with Nuclei templates, actively confirms exploits, and runs a full OWASP ZAP active scan — then consolidates everything into a clean, self-contained HTML report with full evidence and screenshots.

```
subfinder → httpx + nmap → testssl ┐
                                    ├─ paralelo ─ nuclei → exploit confirm (C/A/M only)
owasp zap (+ openapi) → screenshots → HTML report
```

---

## Features

- **Subdomain enumeration** via subfinder with automatic fallback
- **HTTP surface mapping** — status codes, titles, technology fingerprinting
- **Port scanning** — common web ports (80, 443, 8080, 8443, 8000, 8888, 3000, 9090)
- **TLS/SSL analysis** via testssl — cipher suites, protocol versions, certificate issues, CVEs
- **Vulnerability scanning** via Nuclei (CVE, misconfig, default-login, exposure templates)
- **Active exploit confirmation** — re-executes Nuclei curl for Critical/High/Medium findings only
- **OpenAPI/Swagger auto-import** — detects spec endpoints and imports into ZAP before scanning
- **Dynamic analysis** via OWASP ZAP — Spider + Active Scan, runs to 100% completion with no timeout
- **Full evidence capture** — request, response, curl command, attack payload, TLS findings
- **Evidence screenshots** — captures target + vulnerable URLs from both Nuclei and ZAP, embedded as base64
- **Smart deduplication** — Medium/Low/Info ZAP alerts grouped by type; Critical/High always individual cards
- **EPSS-weighted risk score** — probability of exploitation (FIRST.org) incorporated into 0–100 risk score
- **Scan duration** — total elapsed time shown in report header and executive summary
- **Parallel TLS + vuln scan** — testssl runs in background while Nuclei scans, saving 15–25 minutes
- **NVD retry with backoff** — handles rate limiting gracefully with exponential backoff (6s, 12s, 24s)
- **Self-contained HTML report** — no external dependencies to open
- **110-test test harness** included

---

## Installation

### Kali Linux

```bash
# 1. System packages
sudo apt update && sudo apt install -y \
    curl python3 python3-pip jq nmap git \
    zaproxy testssl chromium golang-go

# 2. Python dependencies
pip3 install requests pdfminer.six --break-system-packages

# 3. Go tools (subfinder, httpx, nuclei)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 4. Update Nuclei templates
nuclei -update-templates

# 5. Add Go bin to PATH permanently
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc
```

---

### Ubuntu / WSL (Windows Subsystem for Linux)

```bash
# 1. System packages
sudo apt update && sudo apt upgrade -y
sudo apt install -y \
    curl python3 python3-pip jq nmap git \
    zaproxy testssl chromium-browser golang-go

# 2. Python dependencies
pip3 install requests pdfminer.six --break-system-packages

# 3. Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 4. Update Nuclei templates
nuclei -update-templates

# 5. Add Go bin to PATH permanently
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc

# 6. WSL-specific: headless mode for ZAP and Chromium
echo 'export DISPLAY=""' >> ~/.bashrc
echo 'export JAVA_TOOL_OPTIONS="-Djava.awt.headless=true"' >> ~/.bashrc

source ~/.bashrc
```

> **WSL tip:** if `testssl` is not found, try `sudo apt install testssl.sh` then verify with `which testssl testssl.sh`.

---

### Clone and set up

```bash
git clone https://github.com/trickMeister1337/swarm.git
cd swarm
chmod +x swarm.sh test_swarm.sh
```

---

### Verify installation

Run this to confirm everything is in place:

```bash
for tool in curl python3 jq nmap subfinder httpx nuclei testssl zaproxy; do
    command -v $tool &>/dev/null \
        && echo "[OK] $tool" \
        || echo "[--] $tool not found"
done
chromium --version 2>/dev/null || chromium-browser --version 2>/dev/null || echo "[--] chromium not found"
```

---

## Usage

### Validate before first run
```bash
bash test_swarm.sh
```
All 110 tests must pass before running against a live target.

### Run a scan
```bash
bash swarm.sh https://target.com
```

### Output structure
```
scan_target.com_20260413_143022/
├── relatorio_swarm.html           ← open in browser
└── raw/
    ├── subdomains.txt             ← subfinder output
    ├── httpx_results.txt          ← active hosts + technologies
    ├── nmap.txt                   ← port scan
    ├── testssl.json               ← TLS analysis
    ├── nuclei.json                ← findings (JSONL)
    ├── nuclei_error.log
    ├── exploit_confirmations.json ← active exploit verification
    ├── openapi_spec.json          ← imported OpenAPI spec (if found)
    ├── zap_daemon.log             ← ZAP startup log
    ├── zap_alerts.json            ← ZAP alerts (JSON)
    ├── zap_evidencias.xml         ← ZAP full report (XML)
    └── screenshots/
        ├── main.png               ← target homepage
        └── finding_1.png          ← vulnerable URL captures
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

| Environment | Recommended |
|---|---|
| Production / sensitive target | 20–30 |
| Staging (default) | 50 |
| Internal lab | 100–150 |

---

## Report

The HTML report is fully self-contained (no external requests). Sections:

1. **Executive Summary** — severity counters + 0–100 risk score bar
2. **Attack Surface** — subdomains, active hosts, open ports/services
3. **Critical / High / Medium findings** — full cards with CVE, URL, parameter, attack payload, full evidence
4. **TLS/SSL findings** — testssl results (CRITICAL / HIGH / WARN / LOW)
5. **Exploit confirmations** — live re-execution for Critical/High/Medium Nuclei findings
6. **Evidence screenshots** — base64-embedded captures from Nuclei + ZAP high/critical URLs
7. **Medium/Low/Info findings** — deduplicated table grouped by alert type; preserves highest severity representative
8. **Appendix** — links to all raw output files

---

## Tool Reference

| Tool | Phase | Required |
|---|---|---|
| `curl` | All | ✅ Mandatory |
| `python3` | Report | ✅ Mandatory |
| `subfinder` | 1 — Discovery | Optional |
| `httpx` | 2 — Mapping | Optional |
| `nmap` | 2 — Mapping | Optional |
| `testssl` | 3 — TLS | Optional |
| `nuclei` | 4 — Vuln scan | Optional |
| `zaproxy` | 6 — Active scan | Optional |
| `chromium` | 7 — Screenshots | Optional |
| `jq` | Misc | Optional |

> SWARM automatically adds `~/go/bin` to PATH at startup — no need to source `.bashrc` manually before running.

---

## How OWASP ZAP Integration Works

SWARM manages the full ZAP lifecycle automatically:

- Checks for a pre-existing ZAP instance and reuses it if found
- Kills stale/locked instances and removes `~/.ZAP/zap.lock`
- Patches `~/.ZAP/config.xml` to authorize API access from `127.0.0.1`
- Starts ZAP in daemon mode, waits up to 180s for API readiness
- Detects and imports OpenAPI/Swagger specs before spidering
- Runs Spider → Active Scan, polling progress until **100% completion** (no timeout)
- Captures full evidence: alert, parameter, attack payload, raw evidence
- Only shuts down ZAP if SWARM started it — preserves pre-existing sessions

---

## Legal Disclaimer

> **SWARM is intended for authorized security testing only.**
>
> Use of this tool against systems you do not own or have explicit written permission to test is illegal and unethical. The authors assume no liability for misuse. Always obtain proper authorization before conducting security assessments.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Ensure all 110 tests pass: `bash test_swarm.sh`
4. Submit a pull request with a clear description

---

## License

MIT License — see [LICENSE](LICENSE) for details.

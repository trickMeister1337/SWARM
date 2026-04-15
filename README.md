# SWARM - - Security Workflow and Risk Management

> Automated web security scanner — 9-phase pipeline from subdomain discovery to JS secrets analysis, delivering a single self-contained HTML report in Portuguese, designed for both security analysts and tech leads.

!\[Bash](https://img.shields.io/badge/Shell-Bash-4EAA25?logo=gnu-bash\&logoColor=white)
!\[Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python\&logoColor=white)
!\[Platform](https://img.shields.io/badge/Platform-Kali%20%7C%20Ubuntu%20%7C%20WSL-557C94?logo=linux\&logoColor=white)
!\[Tests](https://img.shields.io/badge/Tests-133%20passing-brightgreen)
!\[License](https://img.shields.io/badge/License-MIT-green)

\---

## What SWARM Does

SWARM chains 10+ industry-standard security tools into a single automated command. One execution covers subdomain discovery, surface mapping, TLS analysis, vulnerability scanning, exploit confirmation, dynamic application testing, JavaScript secret detection, evidence screenshots, and CVE enrichment — producing a single report in Portuguese optimized for tech leads.

### Who It's For

|Role|What they get|
|-|-|
|**Security analyst**|Full evidence (raw HTTP request/response, curl commands), CVSS + EPSS scores, deduplication, TLS findings|
|**Tech lead**|Plain-language impact statements, specific fix guidance per technology, prioritized 3-horizon action plan|
|**Security manager**|0–100 risk index (weighted by EPSS exploitation probability), scan duration, executive summary|

\---

## Architecture

```
TARGET URL
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│  FASE 1   Subfinder ──────────────────── Subdomains         │
│  FASE 2   httpx + nmap ──────────────── HTTP surface + ports│
│                                                              │
│  FASE 3   testssl ─────────────────┐                        │
│                     (background)   │  parallel              │
│  FASE 4   Nuclei ──────────────────┘                        │
│           CVE + misconfig + default-login + exposure        │
│                                                              │
│  FASE 5   Exploit Confirmation                              │
│           re-executes curl for Critical/High/Medium only    │
│                                                              │
│  FASE 5.5 CVE Enrichment (NVD + EPSS)                       │
│           CVSS v3, exploitation probability, description     │
│                                                              │
│  FASE 6   OWASP ZAP                                         │
│           OpenAPI import ──▶ Spider ──▶ Active Scan         │
│           (runs to 100%, no timeout)                        │
│                                                              │
│  FASE 7   Screenshots (Critical only, chromium headless)    │
│                                                              │
│  FASE 8   JS / Secrets Analysis                             │
│           crawl ──▶ download JS ──▶ 20 secret patterns      │
│           framework versions ──▶ endpoint probing           │
│                                                              │
│  FASE 9   HTML Report Generation                            │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
scan\_domain\_TIMESTAMP/
├── relatorio\_swarm.html   ← self-contained, opens offline
└── raw/                   ← all raw evidence files
```

\---

## What SWARM Covers

### Reconnaissance

* **Subdomain enumeration** — subfinder with automatic fallback to main domain
* **HTTP surface mapping** — active hosts, status codes, page titles, technology fingerprinting (httpx)
* **Port scanning** — web-relevant ports: 80, 443, 8000, 8080, 8443, 8888, 3000, 9090

### TLS / SSL

* Protocol version support (SSLv3, TLS 1.0/1.1/1.2/1.3)
* Cipher suite weaknesses
* Certificate validity, chain issues, HSTS
* Known CVEs (Heartbleed, POODLE, BEAST, ROBOT, etc.)
* CRITICAL / HIGH / WARN / LOW severity classification

### Vulnerability Scanning (Nuclei)

* **CVE templates** — known vulnerabilities in specific software versions
* **Default credentials** — admin panels, management interfaces (Node-RED, Grafana, Jupyter, etc.)
* **Misconfiguration** — exposed configs, debug endpoints, stack traces
* **Exposure** — open S3 buckets, Git repos, backup files, sensitive paths
* **Active exploit confirmation** — re-runs curl from Nuclei's finding to verify it's still exploitable

### Dynamic Analysis (OWASP ZAP)

* **Spider** — crawls all reachable pages
* **OpenAPI/Swagger auto-import** — detects and imports API specs before scanning
* **Active scan** — injection attacks, XSS, CSRF, authentication bypasses, IDOR patterns
* **Smart deduplication** — one card per alert type with list of all affected URLs
* **CWE-based severity reclassification** — overrides ZAP's severity with CVSS synthetic score from 37-entry CWE table

### CVE Intelligence

* **NVD lookup** — CVSS v3 score and official description for each CVE
* **EPSS score** — probability of exploitation in next 30 days (FIRST.org)
* **Risk score weighting** — EPSS incorporated into 0–100 index (high EPSS = higher score)
* **Retry with exponential backoff** — handles NVD rate limiting (6s → 12s → 24s)

### JavaScript \& Secret Detection

* **JS file discovery** — crawls pages for `<script src>`, webpack chunks, dynamic imports
* **20 secret patterns**: AWS keys, Google API keys, GitHub/GitLab tokens, OpenAI/Anthropic keys, JWT tokens, Stripe keys, Firebase configs, database connection strings, private keys, Slack tokens, hardcoded passwords, internal network URLs
* **Framework detection** — React, Angular, Vue.js, jQuery, Next.js with version extraction
* **Vulnerable version alerts** — flags known-vulnerable framework versions with CVE
* **Endpoint extraction** — fetches URLs from `axios`, `fetch`, `http.get` calls
* **Active endpoint probing** — tests extracted endpoints, identifies APIs accessible without auth
* **Sensitive comment detection** — TODO/FIXME/password in source comments

### Report (in Portuguese 🇧🇷)

* **All severity labels in PT-BR** — CRÍTICO / ALTO / MÉDIO / BAIXO / INFO
* **Impact statement** per finding — plain-language description of what an attacker can do
* **Fix guidance** — technology-specific remediation (not just ZAP boilerplate)
* **Reclassification badge** — shows when CWE/CVE changed ZAP's original severity
* **Action plan for tech leads** — 3 horizons: this week / next sprint / 30-day backlog
* **Evidence screenshots** — base64-embedded, opens without external files
* **Scan duration** shown in header and executive summary

\---

## What SWARM Does NOT Cover

Being explicit about scope helps set correct expectations:

|Gap|Why|Workaround|
|-|-|-|
|**Authenticated scanning**|ZAP runs without session tokens|Pass Bearer token via ZAP config manually|
|**Backend dependency analysis (SCA)**|No access to `package.json`, `pom.xml` etc.|Use Snyk, Dependabot, or OWASP Dependency Check separately|
|**Subdomain takeover**|Not in current scope|Add `nuclei -tags takeover` manually|
|**Social engineering / phishing**|Out of scope by design|—|
|**Network-layer attacks**|Web application focus only|Use separate network scanner|
|**Internal services behind VPN**|Requires network access|Run from inside the network|

\---

## Installation

### Kali Linux

```bash
# 1. System packages
sudo apt update \&\& sudo apt install -y \\
    curl python3 python3-pip jq nmap git \\
    zaproxy testssl chromium golang-go

# 2. Python dependencies
pip3 install requests pdfminer.six --break-system-packages

# 3. Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# 4. PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> \~/.bashrc \&\& source \~/.bashrc
```

### Ubuntu / WSL

```bash
# 1. System packages
sudo apt update \&\& sudo apt upgrade -y
sudo apt install -y \\
    curl python3 python3-pip jq nmap git \\
    zaproxy testssl chromium-browser golang-go

# 2. Python dependencies
pip3 install requests pdfminer.six --break-system-packages

# 3. Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# 4. PATH + WSL headless mode
echo 'export PATH=$PATH:$HOME/go/bin' >> \~/.bashrc
echo 'export DISPLAY=""' >> \~/.bashrc
echo 'export JAVA\_TOOL\_OPTIONS="-Djava.awt.headless=true"' >> \~/.bashrc
source \~/.bashrc
```

> \*\*WSL tip:\*\* if `testssl` is not found, try `sudo apt install testssl.sh`.
> For npm global packages without sudo: `mkdir \~/.npm-global \&\& npm config set prefix '\~/.npm-global' \&\& echo 'export PATH=$PATH:\~/.npm-global/bin' >> \~/.bashrc`

### Clone

```bash
git clone https://github.com/trickMeister1337/swarm.git
cd swarm
chmod +x swarm.sh test\_swarm.sh
```

### Verify

```bash
for tool in curl python3 jq nmap subfinder httpx nuclei testssl zaproxy; do
    command -v $tool \&>/dev/null \&\& echo "\[OK] $tool" || echo "\[--] $tool not found"
done
chromium --version 2>/dev/null || chromium-browser --version 2>/dev/null
```

\---

## Usage

```bash
# Validate first (133 tests)
bash test\_swarm.sh

# Run full scan
bash swarm.sh https://target.com
```

### Output structure

```
scan\_target.com\_20260415\_091522/
├── relatorio\_swarm.html            ← open in any browser, works offline
└── raw/
    ├── subdomains.txt              ← subfinder
    ├── httpx\_results.txt           ← active hosts + technologies
    ├── nmap.txt                    ← port scan
    ├── testssl.json                ← TLS/SSL analysis
    ├── nuclei.json                 ← Nuclei findings (JSONL)
    ├── exploit\_confirmations.json  ← active verification results
    ├── cve\_enrichment.json         ← CVSS + EPSS data from NVD/FIRST
    ├── zap\_alerts.json             ← OWASP ZAP alerts (JSON)
    ├── zap\_evidencias.xml          ← full ZAP report (XML)
    ├── openapi\_spec.json           ← imported API spec (if found)
    ├── js\_urls.txt                 ← discovered JS files
    ├── js\_analysis.json            ← secrets, endpoints, frameworks
    ├── js\_files/                   ← downloaded JS for forensic analysis
    └── screenshots/
        └── main.png                ← critical findings only
```

\---

## Report Sections

The HTML report is fully self-contained. All content in Portuguese (BR), evidence fields preserved in original language.

|#|Section|Content|
|-|-|-|
|1|Sumário Executivo|Risk index 0–100 (CVSS + EPSS weighted), severity counters, scan duration|
|2|Superfície de Ataque|Subdomains, active hosts, open ports|
|3|Vulnerabilidades Identificadas|Cards with CVE, CVSS, EPSS, impact statement, fix guidance, full evidence|
|4|TLS / SSL|testssl findings with severity and CVE|
|5|Confirmação Ativa de Exploits|Live curl re-execution results per Nuclei finding|
|6|JS / Secrets|Detected secrets (masked), framework versions, exposed endpoints|
|7|Screenshots|Base64-embedded screenshots of critical findings|
|8|Achados Baixo / Info|Deduplicated table grouped by alert type|
|9|Plano de Ação|3-horizon action plan: this week / next sprint / 30-day backlog|
|10|Arquivos de Evidência|Links to all raw output files|

\---

## Configuration

```bash
# Top of swarm.sh
ZAP\_PORT=8080
ZAP\_HOST="127.0.0.1"
ZAP\_SPIDER\_TIMEOUT=0       # 0 = no timeout
ZAP\_SCAN\_TIMEOUT=0         # 0 = no timeout
NUCLEI\_RATE\_LIMIT=50       # req/s — lower for sensitive targets
NUCLEI\_CONCURRENCY=10      # parallel templates
```

|Environment|Rate limit|
|-|-|
|Production / sensitive|20–30|
|Staging (default)|50|
|Internal lab|100–150|

\---

## Tool Reference

|Tool|Phase|Role|Required|
|-|-|-|-|
|`curl`|All|HTTP requests, ZAP API|✅ Mandatory|
|`python3`|All|Analysis + report|✅ Mandatory|
|`subfinder`|1|Subdomain discovery|Optional|
|`httpx`|2|HTTP surface mapping|Optional|
|`nmap`|2|Port + service detection|Optional|
|`testssl`|3|TLS/SSL analysis|Optional|
|`nuclei`|4|Template-based vuln scan|Optional|
|`zaproxy`|6|Dynamic application scan|Optional|
|`chromium`|7|Evidence screenshots|Optional|
|`jq`|Misc|JSON processing|Optional|

> SWARM automatically adds `\~/go/bin` to PATH — no need to source `.bashrc` before running.

\---

## How ZAP Integration Works

SWARM manages the full ZAP lifecycle:

* Checks for pre-existing instance — reuses if found, starts new if not
* Kills stale instances, removes `\~/.ZAP/zap.lock`
* Patches `\~/.ZAP/config.xml` to authorize API from `127.0.0.1`
* Detects and imports OpenAPI/Swagger specs before spidering
* Spider → Active Scan with polling every 10s until **100% complete**
* Deduplicates alerts by name: one card per alert type with all affected URLs
* Reclassifies severity using CWE→CVSS table (37 entries, based on NVD historical data)
* Shuts down only if SWARM started it — preserves pre-existing sessions

\---

## Legal Disclaimer

> \*\*SWARM is intended for authorized security testing only.\*\*
>
> Use against systems you do not own or have explicit written permission to test is illegal and unethical. The authors assume no liability for misuse. Always obtain proper authorization before conducting security assessments.

\---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Ensure all 133 tests pass: `bash test\_swarm.sh`
4. Submit a pull request with a clear description

\---

## License

MIT License — see [LICENSE](LICENSE) for details.


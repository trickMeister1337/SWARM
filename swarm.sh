#!/bin/bash

# ==============================================================================
# SWARM - CONSULTANT EDITION
# Security Assessment Tool
# ==============================================================================

# ── PATH: garantir ferramentas Go e instalações locais ────────────────────────
for _dir in "$HOME/go/bin" "/root/go/bin" "$HOME/.local/bin" "/usr/local/go/bin" "/opt/go/bin"; do
    [ -d "$_dir" ] && [[ ":$PATH:" != *":$_dir:"* ]] && export PATH="$PATH:$_dir"
done
unset _dir

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

ZAP_PORT=8080
ZAP_HOST="127.0.0.1"
ZAP_STARTED_BY_SCRIPT=0
ZAP_SPIDER_TIMEOUT=0             # 0 = sem timeout (aguarda conclusão)
ZAP_SCAN_TIMEOUT=0               # 0 = sem timeout (aguarda conclusão)
NUCLEI_RATE_LIMIT=50
NUCLEI_CONCURRENCY=10

# ====================== FUNÇÕES ======================

validate_tool() {
    local tool=$1 required=${2:-optional}
    if ! command -v "$tool" &>/dev/null; then
        [ "$required" = "required" ] && \
            echo -e "${RED}[✗] $tool não encontrado — obrigatório. Abortando.${NC}" && exit 1
        echo -e "${YELLOW}[○] $tool não encontrado (opcional — fase será ignorada)${NC}"
        return 1
    fi
    echo -e "${GREEN}[✓] $tool encontrado${NC}"
}

zap_api_call() {
    local url="http://${ZAP_HOST}:${ZAP_PORT}/JSON/${1}"
    [ -n "$2" ] && url="${url}?${2}"
    curl -s --max-time 10 "$url" 2>/dev/null
}

wait_for_zap() {
    echo -e "${BLUE}[*] Aguardando ZAP ficar pronto...${NC}"
    for i in {1..180}; do
        zap_api_call "core/view/version" "" | grep -q "version" && \
            echo -e "\n${GREEN}[✓] ZAP pronto${NC}" && return 0
        echo -ne "\r${YELLOW}[*] Aguardando... $i/180s${NC}"
        sleep 1
    done
    echo -e "\n${RED}[✗] ZAP não ficou pronto em 180s${NC}"
    return 1
}

wait_for_zap_progress() {
    local status_endpoint=$1 scan_id=$2 timeout_secs=$3 label=$4
    local elapsed=0 interval=10 progress
    # timeout_secs=0 significa aguardar indefinidamente até 100%
    echo -e "${BLUE}[*] Aguardando $label completar (sem timeout)...${NC}"
    while true; do
        progress=$(zap_api_call "$status_endpoint" "scanId=${scan_id}" 2>/dev/null \
                   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',0))" 2>/dev/null)
        progress=${progress:-0}
        if [ "$timeout_secs" -gt 0 ] 2>/dev/null; then
            echo -ne "\r${YELLOW}[*] $label: ${progress}% (${elapsed}s/${timeout_secs}s)${NC}"
        else
            echo -ne "\r${YELLOW}[*] $label: ${progress}% (${elapsed}s)${NC}"
        fi
        { [ "$progress" = "100" ] || { [ "$progress" -eq "$progress" ] 2>/dev/null && [ "$progress" -ge 100 ]; }; } && \
            echo -e "\n${GREEN}[✓] $label concluído${NC}" && return 0
        # Respeitar timeout se definido (>0)
        if [ "$timeout_secs" -gt 0 ] 2>/dev/null && [ "$elapsed" -ge "$timeout_secs" ]; then
            echo -e "\n${YELLOW}[!] $label atingiu limite de ${timeout_secs}s — coletando resultados parciais${NC}"
            return 1
        fi
        sleep $interval; elapsed=$((elapsed + interval))
    done
}

cleanup() {
    [ "$ZAP_STARTED_BY_SCRIPT" -eq 1 ] || return 0
    echo -e "\n${BLUE}[*] Encerrando ZAP...${NC}"
    zap_api_call "core/action/shutdown" "" > /dev/null 2>&1
    sleep 2
    pkill -f "zaproxy.*-port ${ZAP_PORT}" 2>/dev/null
    echo -e "${GREEN}[✓] ZAP encerrado${NC}"
}

trap cleanup EXIT

# ====================== VALIDAÇÃO INICIAL ======================
TARGET=$1
[ -z "$TARGET" ] && echo -e "${RED}Uso: $0 <URL_ALVO>${NC}" && \
    echo -e "${YELLOW}Exemplo: $0 https://target.com${NC}" && exit 1

DOMAIN=$(echo "$TARGET" | sed -E 's|https?://||' | cut -d/ -f1 | cut -d: -f1)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="scan_${DOMAIN}_${TIMESTAMP}"
mkdir -p "$OUTDIR/raw"

echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}       SWARM - SECURITY ASSESSMENT${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}[+] Alvo     : $TARGET${NC}"
echo -e "${GREEN}[+] Domínio  : $DOMAIN${NC}"
echo -e "${GREEN}[+] Diretório: $OUTDIR${NC}"
echo -e "${GREEN}[+] Iniciado : $(date '+%d/%m/%Y %H:%M:%S')${NC}"
echo ""

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$TARGET" 2>/dev/null)
echo "$HTTP_CODE" | grep -qE "^(200|301|302|401|403|404)$" || \
    { echo -e "${RED}[✗] Site não acessível (HTTP ${HTTP_CODE:-timeout})${NC}"; exit 1; }
echo -e "${GREEN}[✓] Site acessível (HTTP ${HTTP_CODE})${NC}"
echo ""

# ====================== VALIDAÇÃO DE FERRAMENTAS ======================
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  VALIDAÇÃO DE FERRAMENTAS${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}[*] PATH ativo: $PATH${NC}"; echo ""

validate_tool "curl"      "required"
validate_tool "python3"   "required"
validate_tool "jq"        "optional"
validate_tool "subfinder" "optional"
validate_tool "httpx"     "optional"
validate_tool "nmap"      "optional"
validate_tool "nuclei"    "optional"
validate_tool "zaproxy"   "optional"
validate_tool "testssl"   "optional"

# Screenshot: detectar melhor ferramenta disponível
SCREENSHOT_TOOL=""
for _st in chromium chromium-browser google-chrome wkhtmltoimage; do
    if command -v "$_st" &>/dev/null; then
        SCREENSHOT_TOOL="$_st"
        echo -e "${GREEN}[✓] Screenshot: $_st${NC}"
        break
    fi
done
[ -z "$SCREENSHOT_TOOL" ] && echo -e "${YELLOW}[○] Nenhuma ferramenta de screenshot disponível${NC}"

_missing_go=()
for _t in subfinder httpx nuclei; do
    command -v "$_t" &>/dev/null || _missing_go+=("$_t")
done
[ ${#_missing_go[@]} -gt 0 ] && echo "" && \
    echo -e "${YELLOW}[!] Ferramentas Go ausentes: ${_missing_go[*]}${NC}" && \
    echo -e "${YELLOW}    Fix: export PATH=\$PATH:\$HOME/go/bin${NC}"
unset _missing_go _t
echo ""

# ====================== FASE 1: DESCOBERTA ======================
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  FASE 1/8: DESCOBERTA DE SUBDOMÍNIOS${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"

command -v subfinder &>/dev/null && \
    subfinder -d "$DOMAIN" -silent -o "$OUTDIR/raw/subdomains.txt" 2>/dev/null

[ ! -s "$OUTDIR/raw/subdomains.txt" ] && \
    echo "$DOMAIN" > "$OUTDIR/raw/subdomains.txt" && \
    echo -e "${YELLOW}[!] Subfinder sem resultados — usando domínio principal${NC}"

SUB_COUNT=$(wc -l < "$OUTDIR/raw/subdomains.txt" | tr -d ' ')
echo -e "${GREEN}[✓] $SUB_COUNT subdomínio(s) descoberto(s)${NC}"

# ====================== FASE 2: MAPEAMENTO ======================
echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  FASE 2/8: MAPEAMENTO DE SUPERFÍCIE${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"

ACTIVE_COUNT=0
if command -v httpx &>/dev/null; then
    cat "$OUTDIR/raw/subdomains.txt" | \
        httpx -silent -status-code -title -tech-detect -timeout 5 \
              -o "$OUTDIR/raw/httpx_results.txt" 2>"$OUTDIR/raw/httpx_error.log"
    [ -f "$OUTDIR/raw/httpx_results.txt" ] && \
        ACTIVE_COUNT=$(grep -c . "$OUTDIR/raw/httpx_results.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[✓] $ACTIVE_COUNT subdomínio(s) ativo(s) detectado(s)${NC}"
else
    echo -e "${YELLOW}[○] httpx não disponível — pulando mapeamento HTTP${NC}"
fi

OPEN_PORTS="N/A"
if command -v nmap &>/dev/null; then
    echo -e "${BLUE}[*] Executando nmap...${NC}"
    nmap -p 80,443,8000,8080,8443,8888,3000,9090 -T4 -sV --open \
         "$DOMAIN" -oN "$OUTDIR/raw/nmap.txt" > /dev/null 2>&1
    OPEN_PORTS=$(grep -E "^[0-9]+/tcp.*open" "$OUTDIR/raw/nmap.txt" 2>/dev/null \
                 | awk '{print $1}' | tr '\n' ' ' | sed 's/ $//')
    OPEN_PORTS=${OPEN_PORTS:-nenhuma}
    echo -e "${GREEN}[✓] Portas abertas: ${OPEN_PORTS}${NC}"
else
    echo -e "${YELLOW}[○] nmap não disponível — pulando scan de portas${NC}"
fi

# ====================== FASE 4: TESTSSL ======================
echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  FASE 3/8: ANÁLISE TLS (testssl)${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"

TLS_ISSUES=0
if command -v testssl &>/dev/null; then
    echo -e "${BLUE}[*] Executando análise TLS...${NC}"
    testssl --color 0 --warnings off --quiet             --jsonfile "$OUTDIR/raw/testssl.json"             "$DOMAIN" > "$OUTDIR/raw/testssl.log" 2>&1
    if [ -f "$OUTDIR/raw/testssl.json" ] && [ -s "$OUTDIR/raw/testssl.json" ]; then
        TLS_ISSUES=$(python3 -c "
import json, sys
try:
    data = json.load(open('$OUTDIR/raw/testssl.json'))
    # Contar achados com severidade WARN, HIGH, CRITICAL
    findings = data if isinstance(data, list) else data.get('scanResult',[{}])[0].get('findings',[])
    issues = [f for f in findings if f.get('severity','') in ('WARN','HIGH','CRITICAL','LOW')]
    print(len(issues))
except: print(0)" 2>/dev/null)
        echo -e "${GREEN}[✓] testssl concluído — $TLS_ISSUES problema(s) TLS detectado(s)${NC}"
    else
        echo -e "${YELLOW}[!] testssl sem output JSON — ver testssl.log${NC}"
    fi
else
    echo -e "${YELLOW}[○] testssl não disponível — pulando análise TLS${NC}"
    echo -e "${YELLOW}    Instale: sudo apt install testssl.sh${NC}"
fi

# ====================== FASE 3: NUCLEI ======================
echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  FASE 4/8: SCAN DE VULNERABILIDADES (NUCLEI)${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"

NUCLEI_COUNT=0
if command -v nuclei &>/dev/null; then
    echo -e "${YELLOW}[!] Scan pode levar 5-10 minutos (rate-limit: ${NUCLEI_RATE_LIMIT} req/s)...${NC}"
    nuclei -u "$TARGET" \
           -tags cve,tech,exposure,default-login,misconfig \
           -severity critical,high,medium,low \
           -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" \
           -timeout 10 -no-interactsh \
           -jsonl -o "$OUTDIR/raw/nuclei.json" \
           > /dev/null 2>"$OUTDIR/raw/nuclei_error.log"

    if [ -s "$OUTDIR/raw/nuclei.json" ]; then
        NUCLEI_COUNT=$(grep -c . "$OUTDIR/raw/nuclei.json" 2>/dev/null || echo 0)
        echo -e "${GREEN}[✓] Nuclei concluído. $NUCLEI_COUNT vulnerabilidade(s)${NC}"
    else
        echo -e "${YELLOW}[!] Sem resultados com tags. Tentando scan completo...${NC}"
        nuclei -u "$TARGET" \
               -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" \
               -no-interactsh -jsonl -o "$OUTDIR/raw/nuclei.json" \
               > /dev/null 2>>"$OUTDIR/raw/nuclei_error.log"
        NUCLEI_COUNT=$(grep -c . "$OUTDIR/raw/nuclei.json" 2>/dev/null || echo 0)
        echo -e "${GREEN}[✓] $NUCLEI_COUNT vulnerabilidade(s) encontrada(s)${NC}"
    fi
else
    echo -e "${YELLOW}[○] nuclei não disponível — pulando scan de templates${NC}"
fi

# ====================== FASE 5: CONFIRMAÇÃO DE EXPLOITS ======================
echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  FASE 5/8: CONFIRMAÇÃO ATIVA DE EXPLOITS (Nuclei)${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"

CONFIRMED_COUNT=0
if [ -s "$OUTDIR/raw/nuclei.json" ]; then
    echo -e "${BLUE}[*] Re-executando curl de cada achado para confirmar...${NC}"
    python3 - "$OUTDIR" << 'PYCONFIRM'
import json, subprocess, re, sys, os
from datetime import datetime, timezone

outdir = sys.argv[1]
nuclei_file = os.path.join(outdir, "raw", "nuclei.json")
confirm_file = os.path.join(outdir, "raw", "exploit_confirmations.json")

confirmations = []
with open(nuclei_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            curl_cmd = data.get("curl-command", "")
            if not curl_cmd:
                continue

            template_id = data.get("template-id", "unknown")
            url = data.get("matched-at", "")
            severity = data.get("info", {}).get("severity", "info")

            # Re-executar com captura de status e resposta
            safe_cmd = re.sub(
                r"^curl\s+",
                "curl -s --max-time 15 -w '\n---SWARM_STATUS:%{http_code}---' ",
                curl_cmd
            )
            print(f"  [>] Confirmando {template_id} em {url[:60]}...")
            try:
                result = subprocess.run(
                    safe_cmd, shell=True,
                    capture_output=True, text=True, timeout=20
                )
                output = result.stdout
                status_match = re.search(r'---SWARM_STATUS:(\d+)---', output)
                status = status_match.group(1) if status_match else "???"
                body = output.split('---SWARM_STATUS:')[0].strip()[:800]

                # Confirmado = resposta 2xx ou 3xx (acesso bem-sucedido)
                confirmed = status.startswith('2') or status.startswith('3')

                entry = {
                    "template_id": template_id,
                    "url": url,
                    "severity": severity,
                    "confirmed": confirmed,
                    "http_status": status,
                    "response_snippet": body,
                    "curl_command": curl_cmd,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                confirmations.append(entry)
                state = "CONFIRMADO" if confirmed else "NÃO CONFIRMADO"
                print(f"  [{'✓' if confirmed else '!'}] {state} (HTTP {status})")

            except subprocess.TimeoutExpired:
                confirmations.append({
                    "template_id": template_id, "url": url,
                    "severity": severity, "confirmed": False,
                    "http_status": "TIMEOUT", "response_snippet": "",
                    "curl_command": curl_cmd,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
                print(f"  [!] TIMEOUT")

        except Exception as e:
            print(f"  [!] Erro ao processar linha: {e}")

with open(confirm_file, "w", encoding="utf-8") as f:
    json.dump(confirmations, f, ensure_ascii=False, indent=2)

confirmed_n = sum(1 for c in confirmations if c["confirmed"])
print(f"\n  Resultado: {confirmed_n}/{len(confirmations)} achados confirmados ativamente")
PYCONFIRM

    CONFIRMED_COUNT=$(python3 -c "
import json
try:
    data = json.load(open('$OUTDIR/raw/exploit_confirmations.json'))
    print(sum(1 for c in data if c['confirmed']))
except: print(0)" 2>/dev/null)
    echo -e "${GREEN}[✓] $CONFIRMED_COUNT exploit(s) confirmado(s) ativamente${NC}"
else
    echo -e "${YELLOW}[○] Nenhum achado Nuclei para confirmar${NC}"
fi

# ====================== FASE 6: ZAP ======================
echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  FASE 6/8: COLETA DE EVIDÊNCIAS (OWASP ZAP)${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"

ALERT_COUNT=0
if command -v zaproxy &>/dev/null; then

    if zap_api_call "core/view/version" "" 2>/dev/null | grep -q "version"; then
        echo -e "${GREEN}[✓] ZAP já estava rodando — reutilizando${NC}"
        ZAP_STARTED_BY_SCRIPT=0
    else
        echo -e "${BLUE}[*] Preparando ambiente ZAP...${NC}"

        # Limpar instâncias travadas e lock file
        pkill -9 -f "zap-.*\.jar" 2>/dev/null
        pkill -9 -f zaproxy 2>/dev/null
        sleep 2
        rm -f ~/.ZAP/zap.lock 2>/dev/null

        # Corrigir config.xml — adicionar 127.0.0.1 e localhost sem porta na lista de addrs
        # O ZAP 2.17 bloqueia a API para IPs não listados mesmo com api.disablekey=true
        # O arquivo real usa a tag <name> para os endereços
        ZAP_CONFIG="$HOME/.ZAP/config.xml"
        if [ -f "$ZAP_CONFIG" ]; then
            cp "$ZAP_CONFIG" "${ZAP_CONFIG}.swarm_backup" 2>/dev/null
            python3 - "$ZAP_CONFIG" << 'PYFIX'
import sys

path = sys.argv[1]
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

entry = '''            <addr>
                <name>{}</name>
                <regex>false</regex>
                <enabled>true</enabled>
            </addr>'''

changed = False
for addr in ['127.0.0.1', 'localhost']:
    # Procurar <name>ADDR</name> exato — sem porta
    if '<name>' + addr + '</name>' not in content:
        content = content.replace(
            '        </addrs>',
            entry.format(addr) + '\n        </addrs>'
        )
        print('OK: adicionado ' + addr)
        changed = True
    else:
        print('OK: ' + addr + ' ja existe')

if '<disablekey>false</disablekey>' in content:
    content = content.replace(
        '<disablekey>false</disablekey>',
        '<disablekey>true</disablekey>'
    )
    print('OK: disablekey corrigido')
    changed = True

if changed:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
PYFIX
            echo -e "${GREEN}[✓] config.xml configurado${NC}"
        else
            echo -e "${YELLOW}[!] config.xml não encontrado — será criado pelo ZAP${NC}"
        fi

        echo -e "${BLUE}[*] Iniciando OWASP ZAP...${NC}"
        export JAVA_OPTS="-Xmx512m -Djava.awt.headless=true"

        zaproxy -daemon \
                -host "$ZAP_HOST" \
                -port "$ZAP_PORT" \
                -config api.disablekey=true \
                > "$OUTDIR/raw/zap_daemon.log" 2>&1 &

        ZAP_STARTED_BY_SCRIPT=1

        if ! wait_for_zap; then
            echo -e "${RED}[✗] ZAP não iniciou em 180s${NC}"
            echo -e "${YELLOW}[!] Últimas linhas do log:${NC}"
            tail -5 "$OUTDIR/raw/zap_daemon.log" 2>/dev/null | sed 's/^/    /'
            [ -f "${ZAP_CONFIG}.swarm_backup" ] && \
                mv "${ZAP_CONFIG}.swarm_backup" "$ZAP_CONFIG" 2>/dev/null
            ZAP_STARTED_BY_SCRIPT=0
        fi
    fi

    if zap_api_call "core/view/version" "" | grep -q "version"; then
        echo -e "${GREEN}[✓] API do ZAP respondendo${NC}"

        ENCODED_URL=$(python3 -c \
            "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$TARGET")

        # ── OpenAPI/Swagger: detectar spec e importar no ZAP ────────────
        echo -e "${BLUE}[*] Verificando OpenAPI/Swagger...${NC}"
        OPENAPI_FOUND=0
        OPENAPI_PATHS=("/swagger.json" "/swagger/v1/swagger.json" "/openapi.json"
                       "/api/swagger.json" "/api/openapi.json" "/api-docs"
                       "/v1/swagger.json" "/v2/swagger.json" "/v3/swagger.json"
                       "/swagger-ui/swagger.json" "/docs/swagger.json")
        for _oapath in "${OPENAPI_PATHS[@]}"; do
            _oa_url="${TARGET%/}${_oapath}"
            _oa_resp=$(curl -s --max-time 8 -w "%{http_code}" -o /tmp/swarm_oa_check.tmp "$_oa_url" 2>/dev/null)
            if echo "$_oa_resp" | grep -q "^2"; then
                if grep -qE '"swagger"|"openapi"|"paths"' /tmp/swarm_oa_check.tmp 2>/dev/null; then
                    echo -e "${GREEN}[✓] OpenAPI spec encontrado: $_oapath${NC}"
                    cp /tmp/swarm_oa_check.tmp "$OUTDIR/raw/openapi_spec.json"
                    # Importar spec no ZAP via API
                    _oa_encoded=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$_oa_url")
                    _oa_result=$(zap_api_call "openapi/action/importUrl" "url=${_oa_encoded}&targetUrl=${ENCODED_URL}")
                    if echo "$_oa_result" | grep -q "OK\|Result"; then
                        echo -e "${GREEN}[✓] OpenAPI importado no ZAP — endpoints adicionados ao scan${NC}"
                        OPENAPI_FOUND=1
                    else
                        echo -e "${YELLOW}[!] Import ZAP: $_oa_result${NC}"
                    fi
                    break
                fi
            fi
        done
        rm -f /tmp/swarm_oa_check.tmp
        [ "$OPENAPI_FOUND" -eq 0 ] && echo -e "${YELLOW}[○] Nenhum endpoint OpenAPI/Swagger encontrado${NC}"

        echo -e "${BLUE}[*] Iniciando Spider...${NC}"
        SPIDER_ID=$(zap_api_call "spider/action/scan" "url=${ENCODED_URL}" \
                    | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan','0'))" 2>/dev/null)
        wait_for_zap_progress "spider/view/status" "${SPIDER_ID:-0}" "$ZAP_SPIDER_TIMEOUT" "Spider"

        echo -e "${BLUE}[*] Iniciando Active Scan...${NC}"
        SCAN_ID=$(zap_api_call "ascan/action/scan" "url=${ENCODED_URL}&recurse=true" \
                  | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan','0'))" 2>/dev/null)
        wait_for_zap_progress "ascan/view/status" "${SCAN_ID:-0}" "$ZAP_SCAN_TIMEOUT" "Active Scan"

        echo -e "${BLUE}[*] Coletando alertas...${NC}"
        curl -s "http://${ZAP_HOST}:${ZAP_PORT}/JSON/core/view/alerts/" \
             -o "$OUTDIR/raw/zap_alerts.json" 2>/dev/null
        curl -s "http://${ZAP_HOST}:${ZAP_PORT}/OTHER/core/other/xmlreport/" \
             -o "$OUTDIR/raw/zap_evidencias.xml" 2>/dev/null

        ALERT_COUNT=$(python3 -c "
import json
try:
    data = json.load(open('$OUTDIR/raw/zap_alerts.json'))
    print(len(data.get('alerts',[])))
except: print(0)" 2>/dev/null)
        echo -e "${GREEN}[✓] ZAP encontrou ${ALERT_COUNT} alerta(s)${NC}"
    else
        echo -e "${RED}[✗] API do ZAP não respondeu — pulando coleta${NC}"
    fi
else
    echo -e "${YELLOW}[○] ZAP não instalado — pulando fase 4${NC}"
fi

# ====================== FASE 7: SCREENSHOTS ======================
echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  FASE 7/8: SCREENSHOTS DE EVIDÊNCIA${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"

mkdir -p "$OUTDIR/raw/screenshots"
SCREENSHOT_COUNT=0

if [ -n "$SCREENSHOT_TOOL" ]; then
    echo -e "${BLUE}[*] Capturando screenshots com $SCREENSHOT_TOOL...${NC}"

    # Função de screenshot
    take_screenshot() {
        local url=$1 outfile=$2
        case "$SCREENSHOT_TOOL" in
            chromium|chromium-browser|google-chrome)
                "$SCREENSHOT_TOOL" --headless --no-sandbox --disable-gpu \
                    --disable-dev-shm-usage \
                    --window-size=1280,800 \
                    --screenshot="$outfile" \
                    --timeout=15000 "$url" > /dev/null 2>&1
                ;;
            wkhtmltoimage)
                wkhtmltoimage --quiet --width 1280 --height 800 \
                    --load-error-handling ignore \
                    --javascript-delay 2000 \
                    "$url" "$outfile" > /dev/null 2>&1
                ;;
        esac
        [ -f "$outfile" ] && [ "$(stat -c%s "$outfile" 2>/dev/null || echo 0)" -gt 1000 ]
    }

    # Capturar alvo principal
    _ss_file="$OUTDIR/raw/screenshots/main.png"
    if take_screenshot "$TARGET" "$_ss_file"; then
        echo -e "${GREEN}[✓] Screenshot: $TARGET${NC}"
        SCREENSHOT_COUNT=$((SCREENSHOT_COUNT + 1))
    fi

    # Capturar URLs únicas dos achados críticos/altos do Nuclei
    if [ -s "$OUTDIR/raw/nuclei.json" ]; then
        python3 -c "
import json, sys
seen = set()
urls = []
for line in open('$OUTDIR/raw/nuclei.json'):
    try:
        d = json.loads(line.strip())
        sev = d.get('info',{}).get('severity','')
        url = d.get('matched-at','')
        if sev in ('critical','high') and url not in seen:
            seen.add(url); urls.append(url)
    except: pass
print('\n'.join(urls[:5]))" > /tmp/swarm_ss_urls.txt 2>/dev/null

        _idx=1
        while IFS= read -r _ss_url; do
            [ -z "$_ss_url" ] && continue
            _ss_out="$OUTDIR/raw/screenshots/finding_${_idx}.png"
            echo -ne "\r${BLUE}[*] Screenshot finding $_idx: ${_ss_url:0:60}...${NC}"
            if take_screenshot "$_ss_url" "$_ss_out"; then
                SCREENSHOT_COUNT=$((SCREENSHOT_COUNT + 1))
            fi
            _idx=$((_idx + 1))
        done < /tmp/swarm_ss_urls.txt
        echo ""
        rm -f /tmp/swarm_ss_urls.txt
    fi

    echo -e "${GREEN}[✓] $SCREENSHOT_COUNT screenshot(s) capturado(s)${NC}"
else
    echo -e "${YELLOW}[○] Sem ferramenta de screenshot — pulando fase 7${NC}"
    echo -e "${YELLOW}    Instale: sudo apt install chromium${NC}"
fi

export SCREENSHOT_COUNT OPENAPI_FOUND TLS_ISSUES CONFIRMED_COUNT

# ====================== FASE 5: RELATÓRIO ======================
echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  FASE 8/8: GERAÇÃO DE RELATÓRIO${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"

export OUTDIR TARGET DOMAIN OPEN_PORTS ACTIVE_COUNT SUB_COUNT SCREENSHOT_COUNT OPENAPI_FOUND TLS_ISSUES CONFIRMED_COUNT

python3 << 'PYEOF'
import json, os, html, re
from datetime import datetime

OUTDIR          = os.environ.get('OUTDIR','scan_output')
TARGET          = os.environ.get('TARGET','https://example.com')
DOMAIN          = os.environ.get('DOMAIN','example.com')
OPEN_PORTS      = os.environ.get('OPEN_PORTS','N/A')
ACTIVE_COUNT    = os.environ.get('ACTIVE_COUNT','0')
SUB_COUNT       = os.environ.get('SUB_COUNT','0')
SCREENSHOT_COUNT = int(os.environ.get('SCREENSHOT_COUNT','0'))
OPENAPI_FOUND   = os.environ.get('OPENAPI_FOUND','0') == '1'
TLS_ISSUES      = int(os.environ.get('TLS_ISSUES','0'))
CONFIRMED_COUNT = int(os.environ.get('CONFIRMED_COUNT','0'))
errors = []

# Nuclei
findings = []
nuclei_file = os.path.join(OUTDIR,"raw","nuclei.json")
if os.path.exists(nuclei_file) and os.path.getsize(nuclei_file) > 0:
    with open(nuclei_file,"r",encoding="utf-8") as f:
        for ln, line in enumerate(f,1):
            line = line.strip()
            if not line: continue
            try:
                data = json.loads(line)
                info = data.get("info",{})
                sev  = info.get("severity","info").lower()
                cl   = info.get("classification",{}) or {}
                cves = cl.get("cve-id",[]) or []
                # Evidência: montar a partir de request/response/matcher do nuclei
                ev_parts = []
                if data.get("request"): ev_parts.append("REQUEST:\n" + str(data["request"]))
                if data.get("response"): ev_parts.append("RESPONSE:\n" + str(data["response"]))
                if data.get("extracted-results"): ev_parts.append("EXTRACTED: " + str(data["extracted-results"]))
                if data.get("curl-command"): ev_parts.append("CURL:\n" + str(data["curl-command"]))
                ev = "\n\n".join(ev_parts)  # sem truncagem — evidência completa
                meta = data.get("meta",{}) or {}
                findings.append({"source":"Nuclei","name":info.get("name","Vuln"),
                    "severity":sev,"description":(info.get("description","N/A") or "N/A")[:500],
                    "cve":", ".join(cves) if cves else "N/A","url":data.get("matched-at",TARGET),
                    "remediation":info.get("remediation","Revisar.") or "Revisar.",
                    "evidence":ev,
                    "param":str(meta.get("username","") or meta.get("param","") or ""),
                    "attack":str(meta.get("password","") or ""),
                    "other":data.get("template-id","") or ""})
            except json.JSONDecodeError as e: errors.append(f"Nuclei L{ln}: {e}")
            except Exception as e: errors.append(f"Nuclei L{ln}: {type(e).__name__}: {e}")

# ZAP — com deduplicação de alertas repetidos e filtro de confiança
zap_findings = []
zap_low_groups = {}  # {alert_name: {count, urls, finding}}
zap_file = os.path.join(OUTDIR,"raw","zap_alerts.json")
if os.path.exists(zap_file) and os.path.getsize(zap_file) > 0:
    try:
        zap_data = json.load(open(zap_file,"r",encoding="utf-8"))
        rmap = {"high":"high","medium":"medium","low":"low","informational":"info"}
        # Filtrar alertas de confiança "False Positive" ou "Low" confidence para Low/Info
        SKIP_CONFIDENCE = {"false positive"}
        for i,a in enumerate(zap_data.get("alerts",[])):
            try:
                sev = rmap.get(a.get("risk","info").lower(),"info")
                conf = a.get("confidence","").lower()
                # Descartar apenas confirmados como falsos positivos
                if conf in SKIP_CONFIDENCE:
                    continue
                ev = (a.get("evidence","") or "")[:2000]
                if a.get("param"): ev = f"Parâmetro: {a['param']}\n{ev}"
                if a.get("attack"): ev = f"Ataque: {a['attack'][:200]}\n{ev}"
                # Extrair CVE do campo reference; fallback para CWE
                _refs = a.get("reference","") or ""
                _cves = re.findall(r"CVE-\d{4}-\d{4,7}", _refs, re.IGNORECASE)
                _cve_str = ", ".join(sorted(set(c.upper() for c in _cves))) if _cves \
                    else f"CWE-{a.get('cweid','N/A')}"
                f_entry = {"source":"OWASP ZAP","name":a.get("name","Alerta"),
                    "severity":sev,"description":(a.get("description","N/A") or "N/A")[:500],
                    "cve": f"{_cve_str} | Conf: {a.get('confidence','?')}",
                    "url":a.get("url",TARGET),
                    "remediation":a.get("solution","Revisar.") or "Revisar.",
                    "evidence":ev,
                    "param":(a.get("param","") or ""),
                    "attack":(a.get("attack","") or "")[:500],
                    "other":(a.get("other","") or "")[:500]}
                # Para Low/Info: agrupar por nome (deduplicar)
                if sev in ("low","info"):
                    name = a.get("name","Alerta")
                    if name not in zap_low_groups:
                        zap_low_groups[name] = {"count":0,"urls":[],"finding":f_entry,
                            "cve": _cve_str, "conf":a.get("confidence","?")}
                    zap_low_groups[name]["count"] += 1
                    url = a.get("url","")
                    if url and url not in zap_low_groups[name]["urls"]:
                        zap_low_groups[name]["urls"].append(url)
                else:
                    zap_findings.append(f_entry)
            except Exception as e: errors.append(f"ZAP alerta {i}: {e}")
    except json.JSONDecodeError as e: errors.append(f"ZAP JSON malformado: {e}")
    except Exception as e: errors.append(f"ZAP: {e}")

# httpx / nmap
httpx_lines = []
hf = os.path.join(OUTDIR,"raw","httpx_results.txt")
if os.path.exists(hf):
    try: httpx_lines = [l.strip() for l in open(hf) if l.strip()]
    except Exception as e: errors.append(f"httpx: {e}")

nmap_lines = []
nf = os.path.join(OUTDIR,"raw","nmap.txt")
if os.path.exists(nf):
    try: nmap_lines = [l.strip() for l in open(nf) if "open" in l and "/tcp" in l]
    except Exception as e: errors.append(f"nmap: {e}")

# ── testssl ───────────────────────────────────────────────────
tls_findings = []
tf = os.path.join(OUTDIR,"raw","testssl.json")
if os.path.exists(tf) and os.path.getsize(tf) > 0:
    try:
        tdata = json.load(open(tf,"r",encoding="utf-8"))
        findings_raw = tdata if isinstance(tdata,list) else \
            tdata.get("scanResult",[{}])[0].get("findings",[])
        SEV_MAP = {"CRITICAL":"critical","HIGH":"high","WARN":"medium","LOW":"low","OK":"info","INFO":"info"}
        for item in findings_raw:
            sev_raw = item.get("severity","INFO")
            sev = SEV_MAP.get(sev_raw.upper(),"info")
            if sev_raw.upper() in ("CRITICAL","HIGH","WARN","LOW"):
                tls_findings.append({
                    "id":   item.get("id",""),
                    "sev":  sev,
                    "sev_raw": sev_raw,
                    "finding": item.get("finding",""),
                    "cve":  item.get("cve",""),
                })
    except Exception as e: errors.append(f"testssl: {e}")

# ── exploit confirmations ─────────────────────────────────────
confirmations = []
cf = os.path.join(OUTDIR,"raw","exploit_confirmations.json")
if os.path.exists(cf) and os.path.getsize(cf) > 0:
    try: confirmations = json.load(open(cf,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"confirmations: {e}")

# ── screenshots ───────────────────────────────────────────────
import base64
screenshots = []  # list of (label, base64_data)
ss_dir = os.path.join(OUTDIR,"raw","screenshots")
if os.path.exists(ss_dir):
    for fname in sorted(os.listdir(ss_dir)):
        if fname.endswith(".png"):
            fpath = os.path.join(ss_dir, fname)
            try:
                with open(fpath,"rb") as imgf:
                    b64 = base64.b64encode(imgf.read()).decode()
                label = "Alvo Principal" if fname=="main.png" else \
                    f"Achado #{fname.replace('finding_','').replace('.png','')}"
                screenshots.append((label, b64))
            except Exception as e: errors.append(f"screenshot {fname}: {e}")

# Stats — all_f contém Crítico/Alto/Médio completos + representante de cada grupo Low/Info
all_f = sorted(findings + zap_findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x["severity"],5))
stats = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
for f in all_f:
    if f["severity"] in stats: stats[f["severity"]] += 1
# Contabilizar os agrupados de Low/Info
for grp in zap_low_groups.values():
    sev = grp["finding"]["severity"]
    if sev in stats: stats[sev] += grp["count"]
total = sum(stats.values())
risk      = min((stats["critical"]*10)+(stats["high"]*5)+(stats["medium"]*2)+stats["low"],100)
stxt,scol = ("CRÍTICO — Ação Imediata","#7a2e2e") if stats["critical"] else \
            ("ALTO — Atenção Urgente","#b34e4e") if stats["high"] else \
            ("MÉDIO — Correção Planejada","#d4833a") if stats["medium"] else \
            ("BAIXO — Monitoramento","#4a7c8c")
rdate = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

def badge(sev):
    c={"critical":"#7a2e2e","high":"#b34e4e","medium":"#d4833a","low":"#4a7c8c","info":"#6e8f72"}.get(sev,"#999")
    return f'<span style="background:{c};color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{sev.upper()}</span>'

def trows(items,empty="Sem resultados"):
    if not items: return f'<tr><td style="color:#999;font-style:italic">{empty}</td></tr>'
    return "".join(f'<tr><td style="font-family:monospace;font-size:12px">{html.escape(i)}</td></tr>' for i in items[:50])

def render_finding(f):
    rows = f"""
    <tr><th style="width:120px">CVE/CWE</th><td>{html.escape(str(f.get('cve','N/A')))}</td></tr>
    <tr><th>URL</th><td><code>{html.escape(f.get('url',''))}</code></td></tr>
    <tr><th>Descrição</th><td>{html.escape(f.get('description',''))}</td></tr>"""
    if f.get('param'):
        rows += f"\n    <tr><th>Parâmetro</th><td><code>{html.escape(f['param'])}</code></td></tr>"
    if f.get('attack'):
        rows += f"\n    <tr><th>Ataque</th><td><code>{html.escape(f['attack'])}</code></td></tr>"
    if f.get('evidence'):
        rows += f'\n    <tr><th>Evidência</th><td><div class="evidence-box">{html.escape(f["evidence"])}</div></td></tr>'
    if f.get('other'):
        rows += f"\n    <tr><th>Detalhe</th><td>{html.escape(f['other'])}</td></tr>"
    rows += f"\n    <tr><th>Recomendação</th><td>{html.escape(f.get('remediation',''))}</td></tr>"
    src_cls = 'source-nuclei' if f.get('source') == 'Nuclei' else 'source-zap'
    return f'''<div class="vuln {f['severity']}">
  <h3>{html.escape(f.get('name',''))} <span class="source-badge {src_cls}">{f.get('source','')}</span> {badge(f['severity'])}</h3>
  <table>{rows}
  </table></div>'''

vhtml = '<div class="info-box"><p>✅ Nenhuma vulnerabilidade encontrada.</p></div>' if not all_f else     "".join(render_finding(f) for f in all_f)

# Tabela compacta para Low/Info agrupados
low_table_html = ""
if zap_low_groups:
    rows_low = "".join(
        f'<tr><td>{html.escape(name)}</td>'
        f'<td style="text-align:center">{grp["count"]}</td>'
        f'<td style="text-align:center"><span style="background:#4a7c8c;color:white;padding:2px 6px;border-radius:3px;font-size:11px">{grp["finding"]["severity"].upper()}</span></td>'
        f'<td>{html.escape(grp["cve"])}</td>'
        f'<td>{html.escape(grp["conf"])}</td>'
        f'<td style="font-size:11px;color:#555">{html.escape(", ".join(grp["urls"][:3]))}{"..." if len(grp["urls"])>3 else ""}</td>'
        f'<td style="font-size:11px">{html.escape((grp["finding"]["remediation"] or "")[:80])}...</td></tr>'
        for name, grp in sorted(zap_low_groups.items())
    )
    low_table_html = f'''<h2>4. Achados Baixo / Informativo (ZAP — {len(zap_low_groups)} tipos únicos, {sum(g["count"] for g in zap_low_groups.values())} ocorrências)</h2>
    <p style="color:#666;font-size:13px">Agrupados por tipo para reduzir ruído. Verificar manualmente antes de reportar.</p>
    <table>
      <tr style="background:#f5f5f5"><th>Tipo de Alerta</th><th>Qtd</th><th>Sev</th><th>CVE / CWE</th><th>Confiança</th><th>URLs (amostra)</th><th>Recomendação</th></tr>
      {rows_low}
    </table>'''

errsec = "" if not errors else \
    '<h2>⚠ Avisos</h2><div class="info-box" style="border-left-color:#d4833a"><ul>' + \
    "".join(f"<li><code>{html.escape(e)}</code></li>" for e in errors) + "</ul></div>"

# ── Gerar HTML: TLS ─────────────────────────────────────────
SEV_TLS_CLASS = {"critical":"tls-critical","high":"tls-high","medium":"tls-warn","low":"tls-warn","info":"tls-ok"}
if tls_findings:
    tls_rows = "".join(
        f'<tr><td style="font-family:monospace;font-size:12px">{html.escape(f["id"])}</td>'
        f'<td class="{SEV_TLS_CLASS.get(f["sev"],"tls-ok")}">{html.escape(f["sev_raw"])}</td>'
        f'<td>{html.escape(f["finding"])}</td>'
        f'<td>{html.escape(f["cve"] or "—")}</td></tr>'
        for f in tls_findings
    )
    tls_html = f'''<h2>TLS / SSL — {len(tls_findings)} problema(s) detectado(s)</h2>
    <table>
      <tr style="background:#f5f5f5"><th>ID</th><th>Severidade</th><th>Achado</th><th>CVE</th></tr>
      {tls_rows}
    </table>'''
else:
    tls_html = ""

# ── Gerar HTML: Confirmações de Exploit ──────────────────────
if confirmations:
    conf_rows = "".join(
        f'<tr>'
        f'<td style="font-family:monospace;font-size:12px">{html.escape(c["template_id"])}</td>'
        f'<td><code>{html.escape(c["url"])}</code></td>'
        f'<td style="text-align:center"><span class="{"confirm-yes" if c["confirmed"] else "confirm-no"}">'
        f'{"✓ CONFIRMADO" if c["confirmed"] else "— NÃO CONF."}</span></td>'
        f'<td style="text-align:center"><code>{html.escape(c["http_status"])}</code></td>'
        f'<td><div class="evidence-box" style="max-height:80px;overflow:hidden">{html.escape(c["response_snippet"][:200]) if c["response_snippet"] else "—"}</div></td>'
        f'</tr>'
        for c in confirmations
    )
    n_conf = sum(1 for c in confirmations if c["confirmed"])
    confirm_html = f'''<h2>Confirmação Ativa de Exploits — {n_conf}/{len(confirmations)} confirmados</h2>
    <p style="color:#666;font-size:13px">Cada achado Nuclei foi re-executado com o curl original para verificar se a vulnerabilidade permanece ativa.</p>
    <table>
      <tr style="background:#f5f5f5"><th>Template</th><th>URL</th><th>Status</th><th>HTTP</th><th>Resposta (amostra)</th></tr>
      {conf_rows}
    </table>'''
else:
    confirm_html = ""

# ── Gerar HTML: Screenshots ──────────────────────────────────
if screenshots:
    ss_cards = "".join(
        f'<div class="screenshot-card">'
        f'<div class="screenshot-label">{html.escape(label)}</div>'
        f'<img src="data:image/png;base64,{b64}" alt="{html.escape(label)}" loading="lazy">'
        f'</div>'
        for label, b64 in screenshots
    )
    screenshots_html = f'''<h2>Screenshots de Evidência ({len(screenshots)} captura(s))</h2>
    <div class="screenshot-grid">{ss_cards}</div>'''
else:
    screenshots_html = ""

page = f"""<!DOCTYPE html><html lang="pt-br"><head><meta charset="UTF-8">
<title>SWARM — {html.escape(DOMAIN)}</title><style>
body{{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:20px;background:#f0f2f5}}
.container{{max-width:1200px;margin:0 auto;background:white;border-radius:10px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,.1)}}
.header{{background:#1a3a4f;color:white;padding:30px;text-align:center}}.header h1{{margin:0 0 10px}}
.content{{padding:30px}}
.stats{{display:flex;gap:15px;margin:20px 0;flex-wrap:wrap}}
.stat-card{{flex:1;padding:20px;text-align:center;color:white;border-radius:8px;min-width:100px}}
.stat-card.critical{{background:#7a2e2e}}.stat-card.high{{background:#b34e4e}}
.stat-card.medium{{background:#d4833a}}.stat-card.low{{background:#4a7c8c}}.stat-card.info{{background:#6e8f72}}
.stat-card .number{{font-size:36px;font-weight:bold}}
.info-box{{background:#e8f4f8;padding:15px;border-radius:8px;margin:20px 0;border-left:4px solid #1a3a4f}}
.vuln{{border:1px solid #ddd;margin:20px 0;padding:20px;border-radius:8px;background:#fafafa}}
.vuln.critical{{border-left:10px solid #7a2e2e}}.vuln.high{{border-left:10px solid #b34e4e}}
.vuln.medium{{border-left:10px solid #d4833a}}.vuln.low{{border-left:10px solid #4a7c8c}}.vuln.info{{border-left:10px solid #6e8f72}}
.vuln h3{{margin-top:0}}.source-badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;margin-left:8px}}
.source-nuclei{{background:#3498db;color:white}}.source-zap{{background:#e74c3c;color:white}}
.footer{{background:#f5f5f5;padding:20px;text-align:center;font-size:12px;color:#666}}
table{{width:100%;border-collapse:collapse;margin:10px 0}}th,td{{border:1px solid #ddd;padding:10px;text-align:left;vertical-align:top}}
th{{background:#f5f5f5;font-weight:600}}h2{{color:#1a3a4f;border-bottom:2px solid #e0e0e0;padding-bottom:8px}}
.risk-bar-wrap{{background:#e0e0e0;border-radius:4px;height:12px;margin:8px 0}}
.risk-bar{{background:{scol};height:12px;border-radius:4px;width:{risk}%}}
code{{background:#f4f4f4;padding:1px 4px;border-radius:3px;font-size:12px}}
    .evidence-box{{background:#2d3436;color:#dfe6e9;padding:10px 14px;font-family:monospace;font-size:12px;border-radius:4px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}}
    .tls-ok{{color:#27ae60;font-weight:bold}}.tls-warn{{color:#d4833a;font-weight:bold}}
    .tls-high{{color:#b34e4e;font-weight:bold}}.tls-critical{{color:#7a2e2e;font-weight:bold}}
    .confirm-yes{{background:#27ae60;color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold}}
    .confirm-no{{background:#95a5a6;color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold}}
    .screenshot-grid{{display:flex;flex-wrap:wrap;gap:16px;margin:16px 0}}
    .screenshot-card{{border:1px solid #ddd;border-radius:8px;overflow:hidden;max-width:100%}}
    .screenshot-card img{{width:100%;display:block}}
    .screenshot-label{{padding:8px 12px;background:#f5f5f5;font-size:13px;font-weight:600;color:#1a3a4f}}
</style></head><body><div class="container">
<div class="header"><h1>SWARM — Relatório de Segurança</h1>
<p>Alvo: <strong>{html.escape(TARGET)}</strong> | Domínio: {html.escape(DOMAIN)}</p>
<p>Data: {rdate} &nbsp;|&nbsp; <strong>CONFIDENCIAL</strong></p></div>
<div class="content">
<h2>1. Sumário Executivo</h2>
<div class="stats">
<div class="stat-card critical"><div class="number">{stats['critical']}</div><div>CRÍTICO</div></div>
<div class="stat-card high"><div class="number">{stats['high']}</div><div>ALTO</div></div>
<div class="stat-card medium"><div class="number">{stats['medium']}</div><div>MÉDIO</div></div>
<div class="stat-card low"><div class="number">{stats['low']}</div><div>BAIXO</div></div>
<div class="stat-card info"><div class="number">{stats['info']}</div><div>INFO</div></div></div>
<div class="info-box">
<p><strong>Pontuação de Risco (0–100):</strong> {risk}</p>
<div class="risk-bar-wrap"><div class="risk-bar"></div></div>
<p><strong>Total:</strong> {total} &nbsp;|&nbsp; <strong>Status:</strong> <span style="color:{scol};font-weight:bold">{stxt}</span></p>
<p><strong>Ferramentas:</strong> Nuclei + OWASP ZAP{"+ testssl" if TLS_ISSUES >= 0 and os.path.exists(os.path.join(OUTDIR,"raw","testssl.json")) else ""}{"+ OpenAPI" if OPENAPI_FOUND else ""}{"+ Screenshots" if screenshots else ""}</p>
<p><strong>Exploits confirmados:</strong> {CONFIRMED_COUNT} ativamente verificados</p></div>
<h2>2. Superfície de Ataque</h2>
<table>
<tr><th style="width:220px">Subdomínios descobertos</th><td>{SUB_COUNT}</td></tr>
<tr><th>Subdomínios ativos (HTTP)</th><td>{ACTIVE_COUNT}</td></tr>
<tr><th>Portas abertas</th><td><code>{html.escape(OPEN_PORTS)}</code></td></tr></table>
<h3>Subdomínios Ativos (httpx)</h3><table><tr><th>Resultado</th></tr>{trows(httpx_lines,"httpx não executado ou sem resultados")}</table>
<h3>Portas e Serviços (nmap)</h3><table><tr><th>Porta / Serviço</th></tr>{trows(nmap_lines,"nmap não executado")}</table>
<h2>3. Vulnerabilidades Encontradas</h2>{vhtml}

<!-- TLS Section -->
{tls_html}

<!-- Exploit Confirmations -->
{confirm_html}

<!-- Screenshots -->
{screenshots_html}
{errsec}
{low_table_html}
<h2>5. Anexos</h2><div class="info-box"><ul>
<li><code>raw/subdomains.txt</code> — Subdomínios</li>
<li><code>raw/httpx_results.txt</code> — Subdomínios ativos</li>
<li><code>raw/nmap.txt</code> — Scan de portas</li>
<li><code>raw/nuclei.json</code> — Resultados Nuclei</li>
<li><code>raw/zap_alerts.json</code> — Alertas ZAP</li>
<li><code>raw/zap_evidencias.xml</code> — Relatório ZAP XML</li>
{"<li><code>raw/testssl.json</code> — Análise TLS</li>" if os.path.exists(os.path.join(OUTDIR,"raw","testssl.json")) else ""}
{"<li><code>raw/exploit_confirmations.json</code> — Confirmações de exploit</li>" if confirmations else ""}
{"<li><code>raw/openapi_spec.json</code> — OpenAPI spec importada</li>" if OPENAPI_FOUND else ""}
{"<li><code>raw/screenshots/</code> — Screenshots de evidência</li>" if screenshots else ""}
</ul>
<p>Recomenda-se validação manual de todos os achados.</p></div></div>
<div class="footer"><p><strong>CONFIDENCIAL — USO INTERNO AUTORIZADO</strong></p>
<p>SWARM — Automated Security Scanner</p></div></div></body></html>"""

out = os.path.join(OUTDIR,"relatorio_swarm.html")
open(out,"w",encoding="utf-8").write(page)
print(f"[✓] Relatório: {out}")
print(f"[✓] {total} vulnerabilidade(s) | C={stats['critical']} A={stats['high']} M={stats['medium']} B={stats['low']} I={stats['info']}")
if errors: print(f"[!] {len(errors)} aviso(s) — ver relatório")
PYEOF

# ====================== RESUMO FINAL ======================
echo -e "\n${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  PROCESSO CONCLUÍDO — $(date '+%d/%m/%Y %H:%M:%S')${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}📁 Resultados  : ${OUTDIR}/${NC}"
echo -e "${CYAN}📄 Relatório   : ${OUTDIR}/relatorio_swarm.html${NC}"
echo -e "${CYAN}📦 Dados brutos: ${OUTDIR}/raw/${NC}"
echo ""

[ -n "$DISPLAY" ] && command -v xdg-open &>/dev/null && \
    xdg-open "$OUTDIR/relatorio_swarm.html" 2>/dev/null

exit 0

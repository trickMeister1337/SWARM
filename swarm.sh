#!/bin/bash

# ==============================================================================
# SWARM - CONSULTANT EDITION
# Security Assessment Tool
# ==============================================================================

# ── PATH: garantir ferramentas Go e instalações locais ────────────────────────
for _dir in "$HOME/go/bin" "/root/go/bin" "$HOME/.local/bin" \
            "/usr/local/go/bin" "/opt/go/bin" \
            "/usr/local/bin" "/usr/bin" \
            "$HOME/.go/bin" "/snap/bin"; do
    [ -d "$_dir" ] && [[ ":$PATH:" != *":$_dir:"* ]] && export PATH="$PATH:$_dir"
done
unset _dir

# Para cada ferramenta Go, tentar localizar o binário se não estiver no PATH
for _tool in subfinder httpx nuclei katana; do
    if ! command -v "$_tool" &>/dev/null; then
        # Busca ampla — find é lento mas só roda quando o comando não é encontrado
        _found=$(find "$HOME" /usr/local /snap 2>/dev/null \
            -name "$_tool" -type f -perm /111 2>/dev/null | head -1)
        if [ -n "$_found" ]; then
            _found_dir=$(dirname "$_found")
            [[ ":$PATH:" != *":$_found_dir:"* ]] && export PATH="$PATH:$_found_dir"
        fi
    fi
done
unset _tool _found _found_dir

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

ZAP_PORT=8080
ZAP_HOST="127.0.0.1"
ZAP_STARTED_BY_SCRIPT=0
ZAP_SPIDER_TIMEOUT=0             # 0 = sem timeout (aguarda conclusão)
ZAP_SCAN_TIMEOUT=0               # 0 = sem timeout (aguarda conclusão)
NUCLEI_RATE_LIMIT=50
NUCLEI_CONCURRENCY=10


# Rotação de User-Agents — browsers reais para evasão passiva de WAF
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36"
)
# Selecionar UA aleatório
RANDOM_UA="${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}"

# ====================== FUNÇÕES ======================

validate_tool() {
    local tool=$1 required=${2:-optional}
    if ! command -v "$tool" &>/dev/null; then
        [ "$required" = "required" ] && \
            echo -e "  ${RED}[✗] $tool não encontrado — obrigatório. Abortando.${NC}" && exit 1
        echo -e "  ${YELLOW}[○] $tool não encontrado (opcional — fase será ignorada)${NC}"
        return 1
    fi
    echo -e "  ${GREEN}[✓] $tool encontrado${NC}"
}

zap_api_call() {
    local url="http://${ZAP_HOST}:${ZAP_PORT}/JSON/${1}"
    [ -n "$2" ] && url="${url}?${2}"
    curl -s --max-time 10 "$url" 2>/dev/null
}

wait_for_zap() {
    echo -e "  ${BLUE}[…] Aguardando ZAP ficar pronto...${NC}"
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
    local api_fail_count=0 api_fail_limit=5  # 5 falhas consecutivas = ZAP morreu
    echo -e "  ${BLUE}[…] Aguardando $label completar (sem timeout)...${NC}"
    while true; do
        local raw_response
        raw_response=$(zap_api_call "$status_endpoint" "scanId=${scan_id}" 2>/dev/null)
        progress=$(echo "$raw_response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',0))" 2>/dev/null)
        if [ -z "$progress" ] || ! [[ "$progress" =~ ^[0-9]+$ ]]; then
            api_fail_count=$((api_fail_count + 1))
            progress=0
            if [ "$api_fail_count" -ge "$api_fail_limit" ]; then
                echo -e "\n${RED}[✗] $label: API ZAP não responde há ${api_fail_count} tentativas — abortando${NC}"
                return 1
            fi
        else
            api_fail_count=0
        fi
        if [ "$timeout_secs" -gt 0 ] 2>/dev/null; then
            echo -ne "\r${YELLOW}[*] $label: ${progress}% (${elapsed}s/${timeout_secs}s)${NC}"
        else
            echo -ne "\r${YELLOW}[*] $label: ${progress}% (${elapsed}s)${NC}"
        fi
        { [ "$progress" = "100" ] || { [ "$progress" -eq "$progress" ] 2>/dev/null && [ "$progress" -ge 100 ]; }; } && \
            echo -e "\n${GREEN}[✓] $label concluído${NC}" && return 0
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
    echo -e "  ${GREEN}[✓] ZAP encerrado${NC}"
}

trap cleanup EXIT

# ====================== VALIDAÇÃO INICIAL ======================

# ── Suporte a modo single-target e multi-target (-f / --file) ───
TARGETS_FILE=""
TARGET=""

PARALLEL_JOBS=1  # default: sequencial

# Atribuir alvo se não for flag
if [ -n "$1" ] && ! echo "$1" | grep -q '^-'; then
    TARGET="$1"
fi

if [ "$1" = "-f" ] || [ "$1" = "--file" ] || [ "$1" = "--f" ]; then
    echo -e "${CYAN}[*] Modo multi-target — use swarm_batch.sh para múltiplos alvos:${NC}"
    echo -e "${YELLOW}    bash swarm_batch.sh targets.txt${NC}"
    echo ""
    # Redirecionar automaticamente para swarm_batch.sh se disponível
    _batch="$(dirname "$0")/swarm_batch.sh"
    if [ -f "$_batch" ]; then
        echo -e "  ${BLUE}[…] Redirecionando para swarm_batch.sh...${NC}"
        exec bash "$_batch" "${@:2}"
    else
        echo -e "  ${RED}[✗] swarm_batch.sh não encontrado em: $_batch${NC}"
        exit 1
    fi
fi

# ── Modo single-target: continua normalmente ─────────────────────
DOMAIN=$(echo "$TARGET" | sed -E 's|https?://||' | cut -d/ -f1 | cut -d: -f1)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SCAN_START_TS=$(date +%s)
OUTDIR="scan_${DOMAIN}_${TIMESTAMP}"
mkdir -p "$OUTDIR/raw"

# ── Banner ASCII ──────────────────────────────────────────────────────────────
clear 2>/dev/null || true
echo -e "${CYAN}"
cat << 'ASCIIART'
  ███████╗██╗    ██╗ █████╗ ██████╗ ███╗   ███╗
  ██╔════╝██║    ██║██╔══██╗██╔══██╗████╗ ████║
  ███████╗██║ █╗ ██║███████║██████╔╝██╔████╔██║
  ╚════██║██║███╗██║██╔══██║██╔══██╗██║╚██╔╝██║
  ███████║╚███╔███╔╝██║  ██║██║  ██║██║ ╚═╝ ██║
  ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝
ASCIIART
echo -e "${NC}"
echo -e "  ${BOLD}Security Web Assessment & Recon Module${NC}"
echo -e "  ${BLUE}Metodologia: KEV + EPSS + CVSS · Pipeline de 11 Fases${NC}"
echo ""
echo -e "  ${GREEN}▸${NC} Alvo     ${BOLD}$TARGET${NC}"
echo -e "  ${GREEN}▸${NC} Domínio  ${BOLD}$DOMAIN${NC}"
echo -e "  ${GREEN}▸${NC} Output   ${BOLD}$OUTDIR/${NC}"
echo -e "  ${GREEN}▸${NC} Iniciado ${BOLD}$(date '+%d/%m/%Y %H:%M:%S')${NC}"
echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ── Verificação de acesso ao alvo ─────────────────────────────────────────────
echo -ne "  ${BLUE}[…]${NC} Verificando acesso ao alvo..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$TARGET" 2>/dev/null)
if ! echo "$HTTP_CODE" | grep -qE "^(200|301|302|303|307|308|401|403|404)$"; then
    echo -e "\r  ${RED}[✗]${NC} Site não acessível ${RED}(HTTP ${HTTP_CODE:-timeout})${NC}"
    echo ""
    echo -e "  ${YELLOW}Possíveis causas:${NC}"
    echo -e "  ${YELLOW}  • URL incorreta — verifique o protocolo (https://)${NC}"
    echo -e "  ${YELLOW}  • Alvo offline ou firewall bloqueando${NC}"
    echo -e "  ${YELLOW}  • Timeout de rede (>10s)${NC}"
    [ "${SWARM_BATCH:-0}" = "1" ] && exit 1
    exit 1
fi
echo -e "\r  ${GREEN}[✓]${NC} Alvo acessível ${GREEN}(HTTP ${HTTP_CODE})${NC}"
echo ""

# ====================== VALIDAÇÃO DE FERRAMENTAS ======================
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│  VALIDAÇÃO DE FERRAMENTAS                                   │${NC}"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
echo ""

validate_tool "curl"      "required"
validate_tool "python3"   "required"
validate_tool "jq"        "optional"
validate_tool "subfinder" "optional"
validate_tool "httpx"     "optional"
validate_tool "nmap"      "optional"
validate_tool "nuclei"    "optional"
validate_tool "zaproxy"   "optional"
validate_tool "testssl"   "optional"


_missing_go=()
for _t in subfinder httpx nuclei katana; do
    if command -v "$_t" &>/dev/null; then
        true  # encontrado
    else
        _missing_go+=("$_t")
    fi
done
if [ ${#_missing_go[@]} -gt 0 ]; then
    echo ""
    echo -e "  ${YELLOW}[!] Ferramentas Go ausentes: ${_missing_go[*]}${NC}"
    echo -e "${YELLOW}    PATH atual: $PATH${NC}"
    # Tentar diagnosticar onde o binário está
    for _t in "${_missing_go[@]}"; do
        _loc=$(find "$HOME" /usr/local /usr/bin /snap 2>/dev/null \
            -name "$_t" -type f -perm /111 2>/dev/null | head -1)
        if [ -n "$_loc" ]; then
            echo -e "${YELLOW}    Binário $( basename "$_t") encontrado em: $_loc${NC}"
            echo -e "${YELLOW}    Fix: export PATH=\$PATH:$(dirname "$_loc")${NC}"
        else
            echo -e "${YELLOW}    $( basename "$_t") não instalado — instale com:${NC}"
            echo -e "${YELLOW}    go install github.com/projectdiscovery/${_t}/cmd/${_t}@latest${NC}"
        fi
    done
fi
unset _missing_go _t _loc
echo ""

# ====================== FASE 1: DESCOBERTA ======================
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  FASE 1/11: DESCOBERTA DE SUBDOMÍNIOS${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"

command -v subfinder &>/dev/null && \
    subfinder -d "$DOMAIN" -silent -o "$OUTDIR/raw/subdomains.txt" 2>/dev/null

[ ! -s "$OUTDIR/raw/subdomains.txt" ] && \
    echo "$DOMAIN" > "$OUTDIR/raw/subdomains.txt" && \
    echo -e "  ${YELLOW}[!] Subfinder sem resultados — usando domínio principal${NC}"

SUB_COUNT=$(wc -l < "$OUTDIR/raw/subdomains.txt" | tr -d ' ')
echo -e "  ${GREEN}[✓] $SUB_COUNT subdomínio(s) descoberto(s)${NC}"

# ====================== FASE 2: MAPEAMENTO ======================

echo ""
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│  FASE 2/11: MAPEAMENTO DE SUPERFÍCIE${NC}"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
echo ""

ACTIVE_COUNT=0
if command -v httpx &>/dev/null; then
    cat "$OUTDIR/raw/subdomains.txt" | \
        httpx -silent -status-code -title -tech-detect -timeout 5 \
              -o "$OUTDIR/raw/httpx_results.txt" 2>"$OUTDIR/raw/httpx_error.log"
    [ -f "$OUTDIR/raw/httpx_results.txt" ] && \
        ACTIVE_COUNT=$(grep -c . "$OUTDIR/raw/httpx_results.txt" 2>/dev/null || echo 0)
    echo -e "  ${GREEN}[✓] $ACTIVE_COUNT subdomínio(s) ativo(s) detectado(s)${NC}"
else
    echo -e "  ${YELLOW}[○] httpx não disponível — pulando mapeamento HTTP${NC}"
fi

OPEN_PORTS="N/A"
if command -v nmap &>/dev/null; then
    echo -e "  ${BLUE}[…] Executando nmap...${NC}"
    nmap -p 80,443,8000,8080,8443,8888,3000,9090 -T4 -sV --open \
         "$DOMAIN" -oN "$OUTDIR/raw/nmap.txt" > /dev/null 2>&1
    OPEN_PORTS=$(grep -E "^[0-9]+/tcp.*open" "$OUTDIR/raw/nmap.txt" 2>/dev/null \
                 | awk '{print $1}' | tr '\n' ' ' | sed 's/ $//')
    OPEN_PORTS=${OPEN_PORTS:-nenhuma}
    echo -e "  ${GREEN}[✓] Portas abertas: ${OPEN_PORTS}${NC}"
else
    echo -e "  ${YELLOW}[○] nmap não disponível — pulando scan de portas${NC}"
fi

# ====================== FASES 3+4: TESTSSL + NUCLEI (paralelo) ======================

echo ""
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│  FASE 3/11: ANÁLISE TLS (testssl) — paralelo com nuclei${NC}"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
echo ""

TLS_ISSUES=0
TLS_PID=""
if command -v testssl &>/dev/null; then
    echo -e "  ${BLUE}[…] Iniciando testssl em background...${NC}"
    testssl --color 0 --warnings off --quiet \
            --jsonfile "$OUTDIR/raw/testssl.json" \
            "$DOMAIN" > "$OUTDIR/raw/testssl.log" 2>&1 &
    TLS_PID=$!
    echo -e "  ${BLUE}[…] testssl rodando em paralelo com nuclei...${NC}"
else
    echo -e "  ${YELLOW}[○] testssl não disponível — pulando análise TLS${NC}"
    echo -e "${YELLOW}    Instale: sudo apt install testssl.sh${NC}"
fi

# ====================== FASE 4: NUCLEI ======================

echo ""
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│  FASE 4/11: SCAN DE VULNERABILIDADES (NUCLEI) — paralelo com testssl${NC}"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
echo ""

NUCLEI_COUNT=0
if command -v nuclei &>/dev/null; then
    echo -e "  ${YELLOW}[!] Scan pode levar 5-10 minutos (rate-limit: ${NUCLEI_RATE_LIMIT} req/s)...${NC}"
    # Construir flags de evasão baseado em WAF detectado
    NUCLEI_EVASION_FLAGS=""
    if [ "${WAF_DETECTED}" = "1" ]; then
        # User-Agent de browser real + headers que imitam tráfego legítimo
        NUCLEI_EVASION_FLAGS="-H \"User-Agent: ${RANDOM_UA}\""
        NUCLEI_EVASION_FLAGS="$NUCLEI_EVASION_FLAGS -H \"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\""
        NUCLEI_EVASION_FLAGS="$NUCLEI_EVASION_FLAGS -H \"Accept-Language: pt-BR,pt;q=0.9,en;q=0.8\""
        NUCLEI_EVASION_FLAGS="$NUCLEI_EVASION_FLAGS -H \"X-Forwarded-For: 127.0.0.1\""
        NUCLEI_EVASION_FLAGS="$NUCLEI_EVASION_FLAGS -H \"X-Real-IP: 127.0.0.1\""
        # Ignorar respostas de bloqueio do WAF (403/406/429) e continuar
        NUCLEI_EVASION_FLAGS="$NUCLEI_EVASION_FLAGS -hc 403,406,429"
        # Payload alterations — testa variações de encoding automaticamente
        NUCLEI_EVASION_FLAGS="$NUCLEI_EVASION_FLAGS -pa"
        [ -n "$NUCLEI_DELAY" ] && NUCLEI_EVASION_FLAGS="$NUCLEI_EVASION_FLAGS -rl-duration $NUCLEI_DELAY"
        echo -e "  ${BLUE}[…] Evasão passiva ativada: UA rotation + origin spoofing + payload alterations${NC}"
    fi

    eval nuclei -u "$TARGET" \
           -tags cve,tech,exposure,default-login,misconfig,takeover,cors \
           -severity critical,high,medium,low \
           -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" \
           -timeout 10 -no-interactsh \
           $NUCLEI_EVASION_FLAGS \
           -jsonl -o "$OUTDIR/raw/nuclei.json" \
           > /dev/null 2>"$OUTDIR/raw/nuclei_error.log"

    if [ -s "$OUTDIR/raw/nuclei.json" ]; then
        NUCLEI_COUNT=$(grep -c . "$OUTDIR/raw/nuclei.json" 2>/dev/null || echo 0)
        echo -e "  ${GREEN}[✓] Nuclei concluído. $NUCLEI_COUNT vulnerabilidade(s)${NC}"
        # Atualizar metadata com resultado Nuclei
        python3 -c "
import json,os
mf=os.path.join('$OUTDIR','raw','scan_metadata.json')
if os.path.exists(mf):
    d=json.load(open(mf)); d['nuclei_results_after_evasion']=$NUCLEI_COUNT
    json.dump(d,open(mf,'w'),indent=2)
" 2>/dev/null || true
    else
        echo -e "  ${YELLOW}[!] Sem resultados com tags. Tentando scan completo...${NC}"
        nuclei -u "$TARGET" \
               -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" \
               -no-interactsh -jsonl -o "$OUTDIR/raw/nuclei.json" \
               > /dev/null 2>>"$OUTDIR/raw/nuclei_error.log"
        NUCLEI_COUNT=$(grep -c . "$OUTDIR/raw/nuclei.json" 2>/dev/null || echo 0)
        echo -e "  ${GREEN}[✓] $NUCLEI_COUNT vulnerabilidade(s) encontrada(s)${NC}"
    fi
else
    echo -e "  ${YELLOW}[○] nuclei não disponível — pulando scan de templates${NC}"
fi

# Aguardar testssl terminar (rodou em paralelo com nuclei)
if [ -n "$TLS_PID" ] && kill -0 "$TLS_PID" 2>/dev/null; then
    echo -e "  ${BLUE}[…] Aguardando testssl finalizar...${NC}"
    wait "$TLS_PID"
fi
# Coletar resultado testssl agora que terminou
if [ -f "$OUTDIR/raw/testssl.json" ] && [ -s "$OUTDIR/raw/testssl.json" ]; then
    TLS_ISSUES=$(python3 -c "
import json
try:
    data = json.load(open('$OUTDIR/raw/testssl.json'))
    findings = data if isinstance(data, list) else data.get('scanResult',[{}])[0].get('findings',[])
    print(len([f for f in findings if f.get('severity','') in ('WARN','HIGH','CRITICAL','LOW')]))
except: print(0)" 2>/dev/null)
    echo -e "  ${GREEN}[✓] testssl concluído — $TLS_ISSUES problema(s) TLS detectado(s)${NC}"
fi

# ====================== FASE 5: CONFIRMAÇÃO DE EXPLOITS ======================

echo ""
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│  FASE 5/11: CONFIRMAÇÃO ATIVA DE EXPLOITS (Nuclei)${NC}"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
echo ""

CONFIRMED_COUNT=0
if [ -s "$OUTDIR/raw/nuclei.json" ]; then
    echo -e "  ${BLUE}[…] Re-executando curl de cada achado para confirmar...${NC}"
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

            # Confirmar apenas critical/high/medium — info/low não agregam valor
            if severity.lower() not in ("critical", "high", "medium"):
                continue

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
                body = output.split('---SWARM_STATUS:')[0].strip()  # sem truncagem

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
    echo -e "  ${GREEN}[✓] $CONFIRMED_COUNT exploit(s) confirmado(s) ativamente${NC}"
else
    echo -e "  ${YELLOW}[○] Nenhum achado Nuclei para confirmar${NC}"
fi

# ====================== FASE 10: ENRIQUECIMENTO CVE/EPSS ======================

echo ""
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│  FASE 6/11: ENRIQUECIMENTO CVE / EPSS (NVD + FIRST.org)${NC}"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
echo ""

if [ -s "$OUTDIR/raw/nuclei.json" ]; then
    echo -e "  ${BLUE}[…] Consultando NVD e EPSS para CVEs encontrados...${NC}"
    python3 - "$OUTDIR" << 'PYCVE'
import json, sys, os, urllib.request, urllib.parse, time, csv, io

outdir = sys.argv[1]
nuclei_file = os.path.join(outdir, "raw", "nuclei.json")
cve_db_file = os.path.join(outdir, "raw", "cve_enrichment.json")

# ── Baixar catálogo KEV (CISA Known Exploited Vulnerabilities) ──
kev_set = set()
kev_meta = {}  # cve_id -> {date_added, due_date, vendor, product, notes}
try:
    kev_url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
    req_kev = urllib.request.Request(kev_url, headers={"User-Agent": "SWARM/1.0"})
    with urllib.request.urlopen(req_kev, timeout=15) as r:
        raw = r.read().decode("utf-8")
    reader = csv.DictReader(io.StringIO(raw))
    for row in reader:
        cid = row.get("cveID","").strip().upper()
        if cid:
            kev_set.add(cid)
            kev_meta[cid] = {
                "date_added": row.get("dateAdded",""),
                "due_date":   row.get("dueDate",""),
                "vendor":     row.get("vendorProject",""),
                "product":    row.get("product",""),
                "notes":      row.get("notes","")[:200]
            }
    print(f"  [✓] KEV: {len(kev_set)} vulnerabilidades exploradas ativamente carregadas")
except Exception as e:
    print(f"  [!] KEV: não foi possível baixar catálogo ({e}) — continuando sem KEV")

# Coletar CVEs únicos dos achados Nuclei
cves = set()
with open(nuclei_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            data = json.loads(line)
            cl = data.get("info", {}).get("classification", {}) or {}
            for cve in (cl.get("cve-id", []) or []):
                if cve and cve.upper().startswith("CVE-"):
                    cves.add(cve.upper())
        except:
            pass

if not cves:
    print("  [○] Nenhum CVE encontrado nos achados Nuclei")
    sys.exit(0)

print(f"  [*] Consultando {len(cves)} CVE(s)...")
enriched = {}

for cve_id in sorted(cves):
    in_kev = cve_id in kev_set
    kev_info = kev_meta.get(cve_id, {})
    entry = {"cve_id": cve_id, "cvss_v3": None, "cvss_v2": None,
             "description": "", "epss_score": None, "epss_percentile": None,
             "severity": "", "in_kev": in_kev, "kev": kev_info}
    if in_kev:
        print(f"  [🔴] KEV: {cve_id} está no catálogo de explorações ativas! "
              f"(adicionado: {kev_info.get('date_added','?')} | prazo CISA: {kev_info.get('due_date','?')})")
    # NVD API v2 — com retry e backoff exponencial
    def nvd_fetch(cve_id, max_retries=3):
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(cve_id)}"
        for attempt in range(max_retries):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "SWARM/1.0"})
                with urllib.request.urlopen(req, timeout=12) as r:
                    if r.status == 200:
                        return json.loads(r.read())
            except urllib.error.HTTPError as e:
                if e.code == 403 or e.code == 429:  # rate limited
                    wait = (2 ** attempt) * 6  # 6, 12, 24s
                    print(f"  [!] NVD rate limit ({e.code}) — aguardando {wait}s...")
                    time.sleep(wait)
                    continue
                print(f"  [!] NVD HTTP {e.code} para {cve_id}")
                return None
            except Exception as e:
                print(f"  [!] NVD erro para {cve_id}: {e}")
                return None
        return None

    nvd_data = nvd_fetch(cve_id)
    if nvd_data:
        vulns = nvd_data.get("vulnerabilities", [])
        if vulns:
            cve_data = vulns[0].get("cve", {})
            for d in cve_data.get("descriptions", []):
                if d.get("lang") == "en":
                    entry["description"] = d.get("value", "")[:300]
                    break
            metrics = cve_data.get("metrics", {})
            cvss3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
            if cvss3:
                entry["cvss_v3"] = cvss3[0].get("cvssData", {}).get("baseScore")
                entry["severity"] = cvss3[0].get("cvssData", {}).get("baseSeverity", "")
            cvss2 = metrics.get("cvssMetricV2", [])
            if cvss2:
                entry["cvss_v2"] = cvss2[0].get("cvssData", {}).get("baseScore")
        print(f"  [✓] NVD: {cve_id} — CVSS {entry.get('cvss_v3','?')} {entry.get('severity','')}")
    time.sleep(0.7)  # NVD rate limit base: 5 req/30s sem API key

    # EPSS API (FIRST.org)
    try:
        epss_url = f"https://api.first.org/data/v1/epss?cve={urllib.parse.quote(cve_id)}"
        req2 = urllib.request.Request(epss_url, headers={"User-Agent": "SWARM/1.0"})
        with urllib.request.urlopen(req2, timeout=10) as r2:
            epss_data = json.loads(r2.read())
        epss_list = epss_data.get("data", [])
        if epss_list:
            entry["epss_score"] = float(epss_list[0].get("epss", 0))
            entry["epss_percentile"] = float(epss_list[0].get("percentile", 0))
            print(f"  [✓] EPSS: {cve_id} — {entry['epss_score']:.4f} ({entry['epss_percentile']*100:.1f}° percentil)")
    except Exception as e:
        print(f"  [!] EPSS erro para {cve_id}: {e}")
    time.sleep(0.3)

    enriched[cve_id] = entry

# Adicionar entradas KEV para CVEs que não passaram pelo NVD mas estão no KEV
for cve_id in cves:
    if cve_id not in enriched and cve_id in kev_set:
        kev_info = kev_meta.get(cve_id, {})
        enriched[cve_id] = {
            "cve_id": cve_id, "cvss_v3": None, "cvss_v2": None,
            "description": f"Exploração ativa confirmada ({kev_info.get('vendor','')} {kev_info.get('product','')})",
            "epss_score": None, "epss_percentile": None,
            "severity": "", "in_kev": True, "kev": kev_info
        }
        print(f"  [🔴] KEV sem NVD: {cve_id} — adicionado pelo catálogo CISA")

# Salvar também CVEs do KEV que não foram encontrados pelo Nuclei mas podem estar em templates
kev_file = os.path.join(outdir, "raw", "kev_matches.json")
kev_hits = {cid: kev_meta[cid] for cid in cves if cid in kev_set}
with open(kev_file, "w", encoding="utf-8") as f:
    json.dump(kev_hits, f, ensure_ascii=False, indent=2)
if kev_hits:
    print(f"  [🔴] {len(kev_hits)} CVE(s) encontrado(s) no catálogo KEV — exploração ativa confirmada!")

with open(cve_db_file, "w", encoding="utf-8") as f:
    json.dump(enriched, f, ensure_ascii=False, indent=2)
print(f"  [✓] Enriquecimento salvo: {cve_db_file}")
PYCVE
else
    echo -e "  ${YELLOW}[○] Sem achados Nuclei para enriquecer${NC}"
fi


# ====================== FASE 7: WAF DETECTION ======================

echo ""
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│  FASE 7/11: DETECÇÃO DE WAF${NC}"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
echo ""

WAF_DETECTED=""
WAF_NAME=""

# wafw00f pode estar em ~/.local/bin (pip --user) ou como módulo Python
_wafw00f_cmd=""
for _wc in wafw00f wafwoof; do
    command -v "$_wc" &>/dev/null && _wafw00f_cmd="$_wc" && break
done
# Fallback: tentar como módulo Python
if [ -z "$_wafw00f_cmd" ]; then
    python3 -m wafw00f --help &>/dev/null 2>&1 && _wafw00f_cmd="python3 -m wafw00f"
fi
# Fallback: procurar binário em locais comuns
if [ -z "$_wafw00f_cmd" ]; then
    for _loc in "$HOME/.local/bin/wafw00f" "/usr/local/bin/wafw00f" \
                "$HOME/.local/lib/python3."*"/site-packages/../../../bin/wafw00f"; do
        _expanded=$(eval echo "$_loc" 2>/dev/null | head -1)
        [ -f "$_expanded" ] && _wafw00f_cmd="$_expanded" && break
    done
fi

if [ -n "$_wafw00f_cmd" ]; then
    echo -e "  ${BLUE}[…] Detectando Web Application Firewall (${_wafw00f_cmd})...${NC}"
    _waf_out=$($_wafw00f_cmd "$TARGET" -o "$OUTDIR/raw/waf.json" -f json 2>/dev/null)
    # Tentar ler do JSON gerado
    if [ -f "$OUTDIR/raw/waf.json" ]; then
        WAF_NAME=$(python3 -c "
import json, sys
try:
    d = json.load(open('$OUTDIR/raw/waf.json'))
    # wafw00f JSON: lista de resultados
    results = d if isinstance(d, list) else d.get('results', [])
    for r in results:
        fw = r.get('firewall','') or r.get('waf','')
        if fw and fw.lower() not in ('none', 'generic', ''):
            print(fw); break
except: pass" 2>/dev/null)
    fi
    # Fallback: parse do stdout
    if [ -z "$WAF_NAME" ]; then
        WAF_NAME=$(echo "$_waf_out" | grep -oiE "is behind .+" | head -1 | sed 's/is behind //' | tr -d '[:punct:]' | xargs)
        [ -z "$WAF_NAME" ] && echo "$_waf_out" | grep -qi "no waf detected\|not detected" && WAF_NAME=""
    fi
    if [ -n "$WAF_NAME" ]; then
        WAF_DETECTED="1"
        echo -e "  ${YELLOW}[!] WAF detectado: ${WAF_NAME}${NC}"
        echo -e "${YELLOW}    Os achados do active scan podem ter falsos negativos.${NC}"
    else
        echo -e "  ${GREEN}[✓] Nenhum WAF detectado${NC}"
    fi
    echo "$WAF_NAME" > "$OUTDIR/raw/waf_name.txt"
else
    echo -e "  ${YELLOW}[○] wafw00f não encontrado — pulando detecção de WAF${NC}"
    echo -e "${YELLOW}    Instale: pip3 install wafw00f --break-system-packages${NC}"
    echo -e "${YELLOW}    Depois execute: source ~/.bashrc (para atualizar PATH)${NC}"
fi
unset _wafw00f_cmd _wc _loc _expanded

export WAF_DETECTED WAF_NAME

# ── Ajuste adaptativo de parâmetros quando WAF detectado ────────
if [ "${WAF_DETECTED}" = "1" ]; then
    echo -e "${YELLOW}[*] WAF detectado — ajustando configurações para evasão passiva:${NC}"
    # Rate limit reduzido para imitar tráfego legítimo
    NUCLEI_RATE_LIMIT=5
    NUCLEI_CONCURRENCY=2
    echo -e "${YELLOW}    → Nuclei: rate limit ${NUCLEI_RATE_LIMIT} req/s, concurrency ${NUCLEI_CONCURRENCY}${NC}"
    # Delay randômico entre requests (1-3s)
    NUCLEI_DELAY="1s-3s"
    echo -e "${YELLOW}    → Delay randômico: ${NUCLEI_DELAY} entre requests${NC}"
    # Selecionar novo UA aleatório para esta fase
    RANDOM_UA="${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}"
    echo -e "${YELLOW}    → User-Agent: ${RANDOM_UA:0:60}...${NC}"
else
    NUCLEI_DELAY=""
fi
export NUCLEI_RATE_LIMIT NUCLEI_CONCURRENCY NUCLEI_DELAY RANDOM_UA

# ── Registrar configuração de evasão para o relatório ───────────
python3 - "$OUTDIR" "$WAF_DETECTED" "$WAF_NAME" \
    "$NUCLEI_RATE_LIMIT" "$NUCLEI_CONCURRENCY" "${NUCLEI_DELAY:-none}" \
    "$RANDOM_UA" << 'PYMETADATA'
import json, sys, os
outdir, waf_det, waf_name = sys.argv[1], sys.argv[2], sys.argv[3]
rate, conc, delay, ua = sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7]
meta = {
    "waf_detected": waf_det == "1",
    "waf_name": waf_name,
    "evasion_active": waf_det == "1",
    "evasion_techniques": (
        ["rate_limit_reduced","user_agent_rotation","origin_spoofing",
         "payload_alterations","waf_response_bypass","zap_threads_reduced"]
        if waf_det == "1" else []
    ),
    "nuclei_rate_limit": int(rate),
    "nuclei_concurrency": int(conc),
    "nuclei_delay": None if delay == "none" else delay,
    "user_agent": ua,
    "nuclei_results_before_evasion": None,
    "nuclei_results_after_evasion": None,
    "zap_results_after_evasion": None,
}
with open(os.path.join(outdir,"raw","scan_metadata.json"),"w") as f:
    json.dump(meta, f, indent=2)
PYMETADATA

# ====================== FASE 7: EMAIL SECURITY ======================

echo ""
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│  FASE 8/11: SEGURANÇA DE EMAIL (SPF / DMARC / DKIM)${NC}"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
echo ""

EMAIL_ISSUES=0
if command -v dig &>/dev/null; then
    echo -e "  ${BLUE}[…] Verificando registros DNS de segurança de email...${NC}"
    python3 - "$DOMAIN" "$OUTDIR" << 'PYEMAIL'
import subprocess, json, sys, re, os

domain = sys.argv[1]
outdir = sys.argv[2]

def dig(record_type, name, short=True):
    cmd = ["dig", "+short", record_type, name] if short else ["dig", record_type, name]
    try:
        return subprocess.check_output(cmd, timeout=10, text=True).strip()
    except: return ""

results = {}

# ── SPF ───────────────────────────────────────────────────────────
spf_raw = dig("TXT", domain)
spf_records = [l for l in spf_raw.splitlines() if "v=spf1" in l.lower()]

if not spf_records:
    results["spf"] = {"status": "MISSING", "severity": "high",
        "detail": "Registro SPF ausente — qualquer servidor pode enviar e-mail em nome do domínio.",
        "recommendation": "Adicione um registro TXT SPF, ex: v=spf1 include:_spf.google.com ~all"}
elif any("+all" in r for r in spf_records):
    results["spf"] = {"status": "PERMISSIVE", "severity": "high",
        "detail": f"SPF com '+all' permite QUALQUER servidor enviar e-mail pelo domínio.",
        "value": spf_records[0],
        "recommendation": "Substitua '+all' por '~all' (softfail) ou '-all' (hardfail)."}
elif any("?all" in r for r in spf_records):
    results["spf"] = {"status": "NEUTRAL", "severity": "medium",
        "detail": "SPF com '?all' (neutro) não bloqueia remetentes não autorizados.",
        "value": spf_records[0],
        "recommendation": "Substitua '?all' por '~all' ou '-all'."}
else:
    qual = "softfail (~all)" if "~all" in spf_records[0] else "hardfail (-all)" if "-all" in spf_records[0] else "configurado"
    results["spf"] = {"status": "OK", "severity": "none",
        "detail": f"SPF configurado corretamente ({qual}).",
        "value": spf_records[0]}

# ── DMARC ─────────────────────────────────────────────────────────
dmarc_raw = dig("TXT", f"_dmarc.{domain}")
dmarc_records = [l for l in dmarc_raw.splitlines() if "v=dmarc1" in l.lower()]

if not dmarc_records:
    results["dmarc"] = {"status": "MISSING", "severity": "high",
        "detail": "Registro DMARC ausente — sem visibilidade ou controle sobre uso abusivo do domínio.",
        "recommendation": "Adicione: _dmarc."+domain+" TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@"+domain+"\""}
else:
    dmarc = dmarc_records[0]
    policy_m = re.search(r'p=(none|quarantine|reject)', dmarc, re.IGNORECASE)
    policy = policy_m.group(1).lower() if policy_m else "unknown"
    if policy == "none":
        results["dmarc"] = {"status": "MONITOR_ONLY", "severity": "medium",
            "detail": "DMARC com p=none apenas monitora — e-mails falsos ainda chegam aos destinatários.",
            "value": dmarc,
            "recommendation": "Evolua para p=quarantine e depois p=reject após validar relatórios."}
    elif policy in ("quarantine", "reject"):
        results["dmarc"] = {"status": "OK", "severity": "none",
            "detail": f"DMARC configurado com p={policy}.",
            "value": dmarc}
    else:
        results["dmarc"] = {"status": "INVALID", "severity": "medium",
            "detail": f"DMARC com política inválida ou não reconhecida: {policy}",
            "value": dmarc,
            "recommendation": "Verifique a sintaxe do registro DMARC."}

# ── DKIM (heurística: verificar seletores comuns) ─────────────────
selectors = ["default", "google", "mail", "k1", "s1", "s2", "email", "selector1", "selector2"]
dkim_found = []
for sel in selectors:
    r = dig("TXT", f"{sel}._domainkey.{domain}")
    if "v=dkim1" in r.lower() or "p=" in r:
        dkim_found.append(sel)

if dkim_found:
    results["dkim"] = {"status": "OK", "severity": "none",
        "detail": f"DKIM encontrado para seletores: {', '.join(dkim_found)}"}
else:
    results["dkim"] = {"status": "NOT_FOUND", "severity": "low",
        "detail": "DKIM não detectado nos seletores comuns. Pode estar configurado com seletor personalizado.",
        "recommendation": "Verifique se o provedor de e-mail configurou DKIM para o domínio."}

# ── Salvar e exibir ────────────────────────────────────────────────
with open(os.path.join(outdir, "raw", "email_security.json"), "w") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

issues = sum(1 for v in results.values() if v["severity"] in ("high","medium"))
print(f"  [{'!' if issues else '✓'}] SPF: {results['spf']['status']} | DMARC: {results['dmarc']['status']} | DKIM: {results['dkim']['status']}")
if issues:
    print(f"  [!] {issues} problema(s) de segurança de email encontrado(s)")
    for key, val in results.items():
        if val["severity"] in ("high","medium"):
            print(f"      • {key.upper()}: {val['detail']}")
PYEMAIL

    EMAIL_ISSUES=$(python3 -c "
import json, os
try:
    d = json.load(open('$OUTDIR/raw/email_security.json'))
    print(sum(1 for v in d.values() if v.get('severity','') in ('high','medium')))
except: print(0)" 2>/dev/null || echo 0)
    echo -e "  ${GREEN}[✓] Análise de email concluída — $EMAIL_ISSUES problema(s) encontrado(s)${NC}"
else
    echo -e "  ${YELLOW}[○] dig não disponível — pulando análise de email${NC}"
fi

export EMAIL_ISSUES

# ====================== FASE 9: ZAP ======================

echo ""
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│  FASE 9/11: COLETA DE EVIDÊNCIAS (OWASP ZAP)${NC}"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
echo ""

ALERT_COUNT=0
KATANA_URLS=0
if command -v zaproxy &>/dev/null; then

    if zap_api_call "core/view/version" "" 2>/dev/null | grep -q "version"; then
        echo -e "  ${GREEN}[✓] ZAP já estava rodando — reutilizando${NC}"
        ZAP_STARTED_BY_SCRIPT=0
    else
        echo -e "  ${BLUE}[…] Preparando ambiente ZAP...${NC}"

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
            echo -e "  ${GREEN}[✓] config.xml configurado${NC}"
        else
            echo -e "  ${YELLOW}[!] config.xml não encontrado — será criado pelo ZAP${NC}"
        fi

        echo -e "  ${BLUE}[…] Iniciando OWASP ZAP...${NC}"
        export JAVA_OPTS="-Xmx512m -Djava.awt.headless=true"

        zaproxy -daemon \
                -host "$ZAP_HOST" \
                -port "$ZAP_PORT" \
                -config api.disablekey=true \
                > "$OUTDIR/raw/zap_daemon.log" 2>&1 &

        ZAP_STARTED_BY_SCRIPT=1

        if ! wait_for_zap; then
            echo -e "  ${RED}[✗] ZAP não iniciou em 180s${NC}"
            echo -e "  ${YELLOW}[!] Últimas linhas do log:${NC}"
            tail -5 "$OUTDIR/raw/zap_daemon.log" 2>/dev/null | sed 's/^/    /'
            [ -f "${ZAP_CONFIG}.swarm_backup" ] && \
                mv "${ZAP_CONFIG}.swarm_backup" "$ZAP_CONFIG" 2>/dev/null
            ZAP_STARTED_BY_SCRIPT=0
        fi
    fi

    if zap_api_call "core/view/version" "" | grep -q "version"; then
        echo -e "  ${GREEN}[✓] API do ZAP respondendo${NC}"

        # Configurar evasão no ZAP quando WAF detectado
        if [ "${WAF_DETECTED}" = "1" ]; then
            echo -e "  ${BLUE}[…] Configurando ZAP para evasão passiva de WAF...${NC}"
            # Definir User-Agent de browser real
            _ua_encoded=$(python3 -c \
                "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" \
                "${RANDOM_UA}" 2>/dev/null)
            zap_api_call "network/action/setDefaultUserAgent" \
                "userAgent=${_ua_encoded}" > /dev/null 2>&1
            # Adicionar headers que imitam browser legítimo
            for _hdr in \
                "X-Forwarded-For:127.0.0.1" \
                "X-Real-IP:127.0.0.1" \
                "Accept-Language:pt-BR,pt;q=0.9,en;q=0.8" \
                "Accept:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"; do
                _hname="${_hdr%%:*}"
                _hval="${_hdr#*:}"
                _hval_enc=$(python3 -c \
                    "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" \
                    "${_hval}" 2>/dev/null)
                zap_api_call "replacer/action/addRule" \
                    "description=WAF-Evasion-${_hname}&enabled=true&matchType=REQ_HEADER&matchString=${_hname}&replacement=${_hval_enc}" \
                    > /dev/null 2>&1
            done
            # Reduzir thread count do ZAP para imitar tráfego humano
            zap_api_call "ascan/action/setOptionThreadPerHost" "Integer=2" > /dev/null 2>&1
            echo -e "  ${GREEN}[✓] ZAP: UA rotation + headers de evasão configurados${NC}"
        fi

        ENCODED_URL=$(python3 -c \
            "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$TARGET")

        # ── OpenAPI/Swagger: detectar spec e importar no ZAP ────────────
        echo -e "  ${BLUE}[…] Verificando OpenAPI/Swagger...${NC}"
        OPENAPI_FOUND=0
        OPENAPI_PATHS=("/swagger.json" "/swagger/v1/swagger.json" "/openapi.json"
                       "/api/swagger.json" "/api/openapi.json" "/api-docs"
                       "/v1/swagger.json" "/v2/swagger.json" "/v3/swagger.json"
                       "/swagger-ui/swagger.json" "/docs/swagger.json")
        for _oapath in "${OPENAPI_PATHS[@]}"; do
            _oa_url="${TARGET%/}${_oapath}"
            _oa_resp=$(curl -s --max-time 8 -w "%{http_code}" -o "$OUTDIR/raw/swarm_oa_check.tmp" "$_oa_url" 2>/dev/null)
            if echo "$_oa_resp" | grep -q "^2"; then
                if grep -qE '"swagger"|"openapi"|"paths"' "$OUTDIR/raw/swarm_oa_check.tmp" 2>/dev/null; then
                    echo -e "  ${GREEN}[✓] OpenAPI spec encontrado: $_oapath${NC}"
                    cp "$OUTDIR/raw/swarm_oa_check.tmp" "$OUTDIR/raw/openapi_spec.json"
                    # Importar spec no ZAP via API
                    _oa_encoded=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$_oa_url")
                    _oa_result=$(zap_api_call "openapi/action/importUrl" "url=${_oa_encoded}&targetUrl=${ENCODED_URL}")
                    if echo "$_oa_result" | grep -q "OK\|Result"; then
                        echo -e "  ${GREEN}[✓] OpenAPI importado no ZAP — endpoints adicionados ao scan${NC}"
                        OPENAPI_FOUND=1
                    else
                        echo -e "  ${YELLOW}[!] Import ZAP: $_oa_result${NC}"
                    fi
                    break
                fi
            fi
        done
        rm -f "$OUTDIR/raw/swarm_oa_check.tmp"
        [ "$OPENAPI_FOUND" -eq 0 ] && echo -e "  ${YELLOW}[○] Nenhum endpoint OpenAPI/Swagger encontrado${NC}"

        # ── Katana: crawl JavaScript-rendered pages ────────────────────
        KATANA_URLS=0
        if command -v katana &>/dev/null; then
            echo -e "  ${BLUE}[…] Katana: crawling com suporte a JavaScript...${NC}"

            # Detectar se chromium/chrome disponível para modo headless
            KATANA_JS_FLAGS=""
            for _br in chromium chromium-browser google-chrome; do
                if command -v "$_br" &>/dev/null; then
                    KATANA_JS_FLAGS="-jc -jsl"
                    echo -e "  ${GREEN}[✓] Modo JS headless ativado ($_br)${NC}"
                    break
                fi
            done
            [ -z "$KATANA_JS_FLAGS" ] && \
                echo -e "  ${YELLOW}[!] Chromium não encontrado — katana em modo HTTP apenas (sem JS rendering)${NC}"

            katana -u "$TARGET" \
                $KATANA_JS_FLAGS \
                -d 5 \
                -kf all \
                -rl 20 \
                -timeout 30 \
                -ef css,png,jpg,gif,ico,svg,woff,woff2,ttf,eot,mp4,mp3,pdf \
                -o "$OUTDIR/raw/katana_urls.txt" \
                -silent 2>/dev/null || true

            if [ -s "$OUTDIR/raw/katana_urls.txt" ]; then
                KATANA_URLS=$(wc -l < "$OUTDIR/raw/katana_urls.txt" | tr -d " ")
                echo -e "  ${GREEN}[✓] Katana descobriu ${KATANA_URLS} URL(s)${NC}"

                # Filtrar apenas URLs do mesmo domínio e injetar no contexto ZAP
                echo -e "  ${BLUE}[…] Injetando URLs do Katana no contexto ZAP...${NC}"
                _injected=0
                while IFS= read -r _k_url; do
                    [ -z "$_k_url" ] && continue
                    # Aceitar apenas URLs do alvo (sem assets externos)
                    echo "$_k_url" | grep -qF "$DOMAIN" || continue
                    _k_enc=$(python3 -c \
                        "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" \
                        "$_k_url" 2>/dev/null)
                    zap_api_call "core/action/accessUrl" "url=${_k_enc}" > /dev/null 2>&1
                    _injected=$((_injected + 1))
                done < "$OUTDIR/raw/katana_urls.txt"
                echo -e "  ${GREEN}[✓] $_injected URL(s) injetadas no contexto ZAP${NC}"
                sleep 2  # ZAP processar URLs antes do spider
            else
                echo -e "  ${YELLOW}[!] Katana não encontrou URLs — continuando com ZAP spider${NC}"
            fi
        else
            echo -e "  ${YELLOW}[○] Katana não instalado — usando apenas ZAP spider${NC}"
            echo -e "${YELLOW}    Instale: go install github.com/projectdiscovery/katana/cmd/katana@latest${NC}"
        fi

        # ── ZAP Spider: complementa o Katana ou age sozinho ────────────
        echo -e "  ${BLUE}[…] Iniciando ZAP Spider (complementa crawl)...${NC}"
        SPIDER_ID=$(zap_api_call "spider/action/scan" "url=${ENCODED_URL}" \
                    | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan','0'))" 2>/dev/null)
        wait_for_zap_progress "spider/view/status" "${SPIDER_ID:-0}" "$ZAP_SPIDER_TIMEOUT" "Spider"

        # ── Verificar total de URLs no contexto ZAP ───────────────────
        SPIDER_URLS=$(zap_api_call "spider/view/results" "scanId=${SPIDER_ID:-0}" \
                      | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('results',[])))" 2>/dev/null || echo 0)
        TOTAL_URLS=$(( KATANA_URLS + SPIDER_URLS ))
        echo -e "  ${BLUE}[…] Total no contexto ZAP: Katana=${KATANA_URLS} + Spider=${SPIDER_URLS} = ${TOTAL_URLS} URL(s)${NC}"

        if [ "${TOTAL_URLS:-0}" -eq 0 ]; then
            echo -e "  ${YELLOW}[!] Nenhuma URL descoberta — adicionando target manualmente${NC}"
            zap_api_call "core/action/accessUrl" "url=${ENCODED_URL}" > /dev/null 2>&1
            sleep 3
        fi

        # ── Iniciar Active Scan com validação ────────────────────────────
        echo -e "  ${BLUE}[…] Iniciando Active Scan...${NC}"
        SCAN_RESPONSE=$(zap_api_call "ascan/action/scan" "url=${ENCODED_URL}&recurse=true" 2>/dev/null)
        SCAN_ID=$(echo "$SCAN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan',''))" 2>/dev/null)

        if [ -z "$SCAN_ID" ] || [ "$SCAN_ID" = "0" ] || ! [[ "$SCAN_ID" =~ ^[0-9]+$ ]]; then
            echo -e "  ${YELLOW}[!] Active scan não iniciou (SCAN_ID='${SCAN_ID}') — resposta: ${SCAN_RESPONSE:0:200}${NC}"
            echo -e "  ${YELLOW}[!] Coletando alertas do spider e pulando active scan${NC}"
        else
            echo -e "  ${GREEN}[✓] Active Scan iniciado (ID: $SCAN_ID)${NC}"

            # Aguardar até 90s para scan sair de 0% — detecta scan travado
            _stuck_elapsed=0
            _stuck_limit=90
            _stuck=0
            echo -ne "${YELLOW}[*] Verificando se active scan progrediu...${NC}"
            while [ $_stuck_elapsed -lt $_stuck_limit ]; do
                sleep 10; _stuck_elapsed=$((_stuck_elapsed + 10))
                _progress=$(zap_api_call "ascan/view/status" "scanId=${SCAN_ID}" 2>/dev/null \
                    | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',0))" 2>/dev/null || echo 0)
                echo -ne "\r${YELLOW}[*] Active Scan: ${_progress}% (${_stuck_elapsed}s aguardando início)${NC}"
                if [ "${_progress:-0}" -gt 0 ]; then
                    _stuck=0; break
                fi
                _stuck=1
            done
            echo ""

            if [ "$_stuck" -eq 1 ]; then
                echo -e "  ${YELLOW}[!] Active scan travado em 0% por ${_stuck_limit}s — possíveis causas:${NC}"
                echo -e "${YELLOW}    • Alvo bloqueou conexões do scanner${NC}"
                echo -e "${YELLOW}    • ZAP sem URLs no contexto para escanear${NC}"
                echo -e "${YELLOW}    • Alvo exige autenticação para todas as rotas${NC}"
                echo -e "  ${YELLOW}[!] Abortando active scan e coletando alertas disponíveis${NC}"
                zap_api_call "ascan/action/stop" "scanId=${SCAN_ID}" > /dev/null 2>&1
            else
                wait_for_zap_progress "ascan/view/status" "${SCAN_ID}" "$ZAP_SCAN_TIMEOUT" "Active Scan"
            fi
        fi

        echo -e "  ${BLUE}[…] Coletando alertas...${NC}"
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
        echo -e "  ${GREEN}[✓] ZAP encontrou ${ALERT_COUNT} alerta(s)${NC}"
        # Atualizar metadata com resultado ZAP
        python3 -c "
import json,os
mf=os.path.join('$OUTDIR','raw','scan_metadata.json')
if os.path.exists(mf):
    d=json.load(open(mf)); d['zap_results_after_evasion']=$ALERT_COUNT
    json.dump(d,open(mf,'w'),indent=2)
" 2>/dev/null || true
    else
        echo -e "  ${RED}[✗] API do ZAP não respondeu — pulando coleta${NC}"
    fi
else
    echo -e "  ${YELLOW}[○] ZAP não instalado — pulando fase 4${NC}"
fi

export OPENAPI_FOUND TLS_ISSUES CONFIRMED_COUNT KATANA_URLS WAF_DETECTED WAF_NAME EMAIL_ISSUES

# ====================== FASE 10: JS ANALYSIS ======================

echo ""
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│  FASE 10/11: ANÁLISE DE JAVASCRIPT & SECRETS${NC}"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
echo ""

JS_SECRETS=0
JS_ENDPOINTS=0
JS_FRAMEWORKS=0
JS_FILES=0

python3 - "$OUTDIR" "$TARGET" "$DOMAIN" << 'PYJS'
import urllib.request, urllib.parse, re, os, sys, json, ssl, hashlib, time
from pathlib import Path

OUTDIR, TARGET, DOMAIN = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(os.path.join(OUTDIR,"raw","js_files"), exist_ok=True)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
HEADERS = {"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0"}

def fetch(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read().decode("utf-8", errors="replace"), r.status
    except Exception as e:
        return None, str(e)

def normalize(url, base):
    if not url or url.startswith(("data:","javascript:","mailto:","#")): return None
    if url.startswith("//"): return base.split("://")[0] + ":" + url
    if url.startswith("/"):
        p = urllib.parse.urlparse(base)
        return f"{p.scheme}://{p.netloc}{url}"
    if not url.startswith("http"): return urllib.parse.urljoin(base, url)
    return url

# ── Fase 8a: Descoberta de arquivos JS ───────────────────────────
pages = {TARGET}
extra = ["/","/login","/app","/dashboard","/api/docs/","/swagger-ui/"]
parsed = urllib.parse.urlparse(TARGET)
for path in extra:
    pages.add(f"{parsed.scheme}://{parsed.netloc}{path}")

crawled, js_urls = set(), set()
MAX_PAGES = 8
count = 0

while pages and count < MAX_PAGES:
    url = pages.pop()
    if url in crawled: continue
    crawled.add(url); count += 1
    content, status = fetch(url)
    if not content: continue
    # Extract <script src>
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', content, re.IGNORECASE):
        u = normalize(m.group(1), url)
        if u and DOMAIN in u: js_urls.add(u)
    # Webpack chunks
    for m in re.finditer(r'["\']([^"\']*\.(?:js|chunk\.js)(?:\?[^"\']*)?)["\']', content):
        u = normalize(m.group(1), url)
        if u and DOMAIN in u: js_urls.add(u)
    # Links for next pages
    for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\']', content, re.IGNORECASE):
        u = normalize(m.group(1), url)
        if u and DOMAIN in u and not u.endswith((".js",".css",".png",".jpg",".ico")):
            pu = urllib.parse.urlparse(u)
            pages.add(f"{pu.scheme}://{pu.netloc}{pu.path}")

js_list = sorted(js_urls)
with open(os.path.join(OUTDIR,"raw","js_urls.txt"),"w") as f:
    f.write("\n".join(js_list))
print(f"  [✓] {len(js_list)} arquivo(s) JS descoberto(s)")

# ── Fase 8b: Download e detecção de secrets ──────────────────────
SECRET_PATTERNS = [
    (r'(?i)(?:api[_\-\.]?key|apikey|access[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "API Key"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
    (r'(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key\s*[:=]\s*["\']([A-Za-z0-9/+]{40})["\']', "AWS Secret"),
    (r'arn:aws:[a-zA-Z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s"\']+', "AWS ARN"),
    (r'AIza[0-9A-Za-z\-_]{33,}', "Google API Key"),
    (r'ghp_[A-Za-z0-9]{36}', "GitHub Token"),
    (r'glpat-[A-Za-z0-9_\-]{20}', "GitLab PAT"),
    (r'sk-proj-[A-Za-z0-9_\-]{20,}', "OpenAI Key"),
    (r'sk-ant-[A-Za-z0-9_\-]{20,}', "Anthropic Key"),
    (r'sk-[A-Za-z0-9]{48}', "OpenAI Legacy"),
    (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', "JWT Token"),
    (r'sk_live_[A-Za-z0-9]{24,}', "Stripe Live Key"),
    (r'["\']AIzaSy[A-Za-z0-9_\-]{33}["\']', "Firebase Key"),
    (r'(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^\s"\'<>]{10,}', "DB Connection String"),
    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,64})["\']', "Hardcoded Password"),
    (r'(?i)(?:secret[_\-]?key|client[_-]?secret)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "Secret Key"),
    (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key"),
    (r'xox[baprs]-[A-Za-z0-9\-]{10,}', "Slack Token"),
    (r'https?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})[^\s"\'<>]*', "URL Rede Interna"),
    (r'https?://[a-zA-Z0-9\-\.]+\.(?:internal|local|corp|lan|intranet|dev|staging|hml)[^\s"\'<>]*', "Domínio Interno"),
]
ENDPOINT_PATTERNS = [
    r'(?:fetch|axios|http\.(?:get|post|put|delete|patch))\s*\(["\']([^"\']+)["\']',
    r'(?:url|endpoint|baseUrl|apiUrl|API_URL)\s*[:=]\s*["\']([^"\']{5,})["\']',
    r'["\']/(api|v\d+|graphql|rest|admin|auth|user|users|token|tokens|upload|webhook)[^"\'<>\s]{0,100}["\']',
]
FRAMEWORK_PATTERNS = [
    (r'[Rr]eact["\s\.]+[vV]?ersion["\s:]+["\']?(\d+\.\d+[\.\d]*)', "React"),
    (r'[Aa]ngular["\s\.]+[vV]?ersion["\s:]+["\']?(\d+\.\d+[\.\d]*)', "Angular"),
    (r'[Vv]ue(?:\.js)?["\s\.]+[vV]?ersion["\s:]+["\']?(\d+\.\d+[\.\d]*)', "Vue.js"),
    (r'jquery["\s]+v?(\d+\.\d+[\.\d]*)', "jQuery"),
    (r'axios["\s\/]+(\d+\.\d+[\.\d]*)', "Axios"),
    (r'next(?:js)?["\s\.]+[vV]?ersion["\s:]+["\']?(\d+\.\d+[\.\d]*)', "Next.js"),
]
VULN_VERSIONS = {
    "jQuery": [("< 3.5.0", lambda v: tuple(int(x) for x in v.split(".")[:3]) < (3,5,0), "XSS via HTML parsing", "CVE-2020-11022")],
    "React":  [("< 16.13.0", lambda v: tuple(int(x) for x in v.split(".")[:2]) < (16,13), "SSR XSS", "CVE-2018-6341")],
}
FP_WORDS = {"example","placeholder","your-key","your_key","xxx","dummy","test","sample","foo","bar","changeme"}

all_secrets, all_endpoints, all_frameworks, all_comments, js_stats = [], set(), [], [], []

for js_url in js_list:
    print(f"  [>] {js_url[:80]}")
    content, status = fetch(js_url)
    if not content: continue
    fname = hashlib.md5(js_url.encode()).hexdigest()[:8] + ".js"
    fpath = os.path.join(OUTDIR,"raw","js_files",fname)
    with open(fpath,"w",encoding="utf-8") as f: f.write(content)
    js_stats.append({"url":js_url,"size_kb":len(content)//1024,"file":fname})

    for pattern, label in SECRET_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE|re.MULTILINE):
            val = m.group(0)
            if any(fp in val.lower() for fp in FP_WORDS): continue
            line_start = content.rfind("\n", 0, m.start())+1
            line_end = content.find("\n", m.end()); line_end = len(content) if line_end==-1 else line_end
            ctx = content[line_start:line_end].strip()[:200]
            all_secrets.append({"url":js_url,"file":fname,"type":label,"value":val,"context":ctx})

    for pat in ENDPOINT_PATTERNS:
        for m in re.finditer(pat, content, re.IGNORECASE):
            ep = (m.group(1) if m.lastindex else m.group(0)).strip("\"'")
            if len(ep) > 3: all_endpoints.add(ep)

    for pat, name in FRAMEWORK_PATTERNS:
        m = re.search(pat, content, re.IGNORECASE)
        if m:
            ver = m.group(1) if m.lastindex else "?"
            vulns = []
            for vrange, checker, detail, cve in VULN_VERSIONS.get(name,[]):
                try:
                    if checker(ver): vulns.append({"range":vrange,"detail":detail,"cve":cve})
                except: pass
            all_frameworks.append({"framework":name,"version":ver,"url":js_url,"vulnerable":bool(vulns),"vulns":vulns})

    for cp in [r'//.*(?:TODO|FIXME|password|secret|api.?key|credential|token)[^\n]*',
               r'/\*[^*]*(?:password|secret|credential)[^*]*\*/']:
        for m in re.finditer(cp, content, re.IGNORECASE):
            all_comments.append({"url":js_url,"comment":m.group(0).strip()[:200]})

    time.sleep(0.2)

# ── Fase 8c: Verificação de endpoints ────────────────────────────
parsed_t = urllib.parse.urlparse(TARGET)
base = f"{parsed_t.scheme}://{parsed_t.netloc}"
probed = []
for ep in list(all_endpoints)[:30]:
    url = (base + ep) if ep.startswith("/") else (base+"/"+ep if not ep.startswith("http") else ep)
    try:
        req = urllib.request.Request(url, headers=HEADERS, method="GET")
        req.add_unredirected_header("Accept","application/json,text/html,*/*")
        with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
            st = r.status; ct = r.headers.get("Content-Type","")
            body = r.read(512).decode("utf-8",errors="replace")
    except urllib.error.HTTPError as e:
        st = e.code; ct = ""; body = ""
    except: st = 0; ct = ""; body = ""
    probed.append({"endpoint":ep,"url":url,"status":st,"content_type":ct[:80],
        "is_json":"json" in ct,"body_preview":body[:200] if st==200 else ""})
    time.sleep(0.1)

results = {"target":TARGET,"domain":DOMAIN,"js_files":js_stats,
    "secrets":all_secrets,"endpoints":sorted(all_endpoints),
    "frameworks":all_frameworks,"sensitive_comments":all_comments[:30],
    "endpoint_probes":probed}
with open(os.path.join(OUTDIR,"raw","js_analysis.json"),"w",encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

print(f"  [✓] {len(all_secrets)} secret(s) | {len(all_endpoints)} endpoint(s) | {len(all_frameworks)} framework(s)")
print(f"  [✓] {len(probed)} endpoint(s) verificado(s)")
PYJS

# Coletar contadores para o relatório
if [ -f "$OUTDIR/raw/js_analysis.json" ]; then
    JS_SECRETS=$(python3 -c "import json; d=json.load(open('$OUTDIR/raw/js_analysis.json')); print(len(d.get('secrets',[])))" 2>/dev/null || echo 0)
    JS_ENDPOINTS=$(python3 -c "import json; d=json.load(open('$OUTDIR/raw/js_analysis.json')); print(len(d.get('endpoints',[])))" 2>/dev/null || echo 0)
    JS_FRAMEWORKS=$(python3 -c "import json; d=json.load(open('$OUTDIR/raw/js_analysis.json')); print(len(d.get('frameworks',[])))" 2>/dev/null || echo 0)
    JS_FILES=$(python3 -c "import json; d=json.load(open('$OUTDIR/raw/js_analysis.json')); print(len(d.get('js_files',[])))" 2>/dev/null || echo 0)
    echo -e "  ${GREEN}[✓] JS: $JS_FILES arquivo(s) | $JS_SECRETS secret(s) | $JS_ENDPOINTS endpoint(s) | $JS_FRAMEWORKS framework(s)${NC}"
fi

export JS_SECRETS JS_ENDPOINTS JS_FRAMEWORKS JS_FILES


# ====================== FASE 11: RELATÓRIO ======================

echo ""
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│  FASE 11/11: GERAÇÃO DE RELATÓRIO${NC}"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
echo ""

export OUTDIR TARGET DOMAIN OPEN_PORTS ACTIVE_COUNT SUB_COUNT OPENAPI_FOUND TLS_ISSUES CONFIRMED_COUNT SCAN_START_TS JS_SECRETS JS_ENDPOINTS JS_FRAMEWORKS JS_FILES KATANA_URLS WAF_DETECTED WAF_NAME EMAIL_ISSUES

python3 << 'PYEOF'
import json, os, html, re
from datetime import datetime

# ── Tabela CWE → CVSS sintético (baseado em médias históricas NVD) ──
# Usada como fallback para alertas ZAP que não trazem CVE nas referências
CWE_CVSS_TABLE = {
    # Injeção / execução
    "89":  {"cvss": 9.8, "sev": "CRITICAL", "name": "SQL Injection"},
    "78":  {"cvss": 9.8, "sev": "CRITICAL", "name": "OS Command Injection"},
    "77":  {"cvss": 9.8, "sev": "CRITICAL", "name": "Command Injection"},
    "94":  {"cvss": 9.8, "sev": "CRITICAL", "name": "Code Injection"},
    "502": {"cvss": 9.8, "sev": "CRITICAL", "name": "Deserialization of Untrusted Data"},
    "611": {"cvss": 9.1, "sev": "CRITICAL", "name": "XXE"},
    "918": {"cvss": 9.8, "sev": "CRITICAL", "name": "SSRF"},
    # Autenticação / controle de acesso
    "287": {"cvss": 9.1, "sev": "CRITICAL", "name": "Improper Authentication"},
    "306": {"cvss": 9.1, "sev": "CRITICAL", "name": "Missing Authentication"},
    "284": {"cvss": 8.8, "sev": "HIGH",     "name": "Improper Access Control"},
    "285": {"cvss": 8.8, "sev": "HIGH",     "name": "Improper Authorization"},
    "862": {"cvss": 8.1, "sev": "HIGH",     "name": "Missing Authorization"},
    "863": {"cvss": 8.1, "sev": "HIGH",     "name": "Incorrect Authorization"},
    "269": {"cvss": 8.8, "sev": "HIGH",     "name": "Improper Privilege Management"},
    # Exposição de dados
    "22":  {"cvss": 7.5, "sev": "HIGH",     "name": "Path Traversal"},
    "23":  {"cvss": 7.5, "sev": "HIGH",     "name": "Relative Path Traversal"},
    "200": {"cvss": 5.3, "sev": "MEDIUM",   "name": "Information Disclosure"},
    "312": {"cvss": 5.5, "sev": "MEDIUM",   "name": "Cleartext Storage of Sensitive Info"},
    "319": {"cvss": 5.9, "sev": "MEDIUM",   "name": "Cleartext Transmission"},
    "359": {"cvss": 6.5, "sev": "MEDIUM",   "name": "Privacy Violation"},
    # XSS / client-side
    "79":  {"cvss": 6.1, "sev": "MEDIUM",   "name": "Cross-Site Scripting (XSS)"},
    "80":  {"cvss": 6.1, "sev": "MEDIUM",   "name": "Basic XSS"},
    "116": {"cvss": 5.4, "sev": "MEDIUM",   "name": "Improper Encoding/Escaping"},
    "1021":{"cvss": 4.7, "sev": "MEDIUM",   "name": "Clickjacking"},
    # CSRF / sessão
    "352": {"cvss": 8.8, "sev": "HIGH",     "name": "Cross-Site Request Forgery"},
    "384": {"cvss": 7.1, "sev": "HIGH",     "name": "Session Fixation"},
    "613": {"cvss": 5.4, "sev": "MEDIUM",   "name": "Insufficient Session Expiration"},
    # Criptografia / TLS
    "326": {"cvss": 7.5, "sev": "HIGH",     "name": "Inadequate Encryption Strength"},
    "327": {"cvss": 7.5, "sev": "HIGH",     "name": "Broken Crypto Algorithm"},
    "330": {"cvss": 7.5, "sev": "HIGH",     "name": "Insufficient Random Values"},
    "295": {"cvss": 7.4, "sev": "HIGH",     "name": "Improper Certificate Validation"},
    # Configuração / exposição
    "16":  {"cvss": 5.3, "sev": "MEDIUM",   "name": "Configuration"},
    "693": {"cvss": 5.3, "sev": "MEDIUM",   "name": "Missing Security Header"},
    "1004":{"cvss": 4.0, "sev": "MEDIUM",   "name": "Cookie Without HttpOnly"},
    "1395":{"cvss": 6.1, "sev": "MEDIUM",   "name": "Vulnerable JavaScript Library"},
    "404": {"cvss": 5.3, "sev": "MEDIUM",   "name": "Improper Resource Shutdown"},
    "497": {"cvss": 4.3, "sev": "MEDIUM",   "name": "Exposure of System Data"},
    "525": {"cvss": 3.7, "sev": "LOW",      "name": "Browser Caching Sensitive Info"},
}

def cwe_enrich(cweid_str):
    """Dado CWE-89 ou 89, retorna dict com cvss/sev/name ou None."""
    if not cweid_str: return None
    cwe_num = re.sub(r"[^0-9]", "", str(cweid_str))
    return CWE_CVSS_TABLE.get(cwe_num)

# ── Mapa de impacto prático por CWE (linguagem para tech lead) ──
IMPACT_MAP = {
    "89":  "Um atacante pode ler, modificar ou apagar dados do banco de dados, incluindo dados de usuários e transações.",
    "78":  "Um atacante pode executar comandos arbitrários no servidor, comprometendo toda a infraestrutura.",
    "79":  "Scripts maliciosos podem ser executados no navegador de usuários, roubando sessões e credenciais.",
    "352": "Um atacante pode forçar usuários autenticados a executar ações não autorizadas (ex: transferências, alteração de dados).",
    "22":  "Um atacante pode acessar arquivos arbitrários do servidor, incluindo configurações e chaves privadas.",
    "287": "Acesso não autorizado à aplicação, permitindo personificar qualquer usuário incluindo administradores.",
    "306": "Endpoints críticos acessíveis sem autenticação, expondo dados e funcionalidades a qualquer pessoa.",
    "284": "Usuários podem acessar recursos ou dados de outros usuários (IDOR, escalada de privilégios).",
    "918": "O servidor pode ser usado como proxy para acessar serviços internos protegidos (AWS metadata, bancos de dados).",
    "611": "Processamento de XML externo pode vazar arquivos do servidor ou causar denial of service.",
    "502": "Deserialização de dados não confiáveis pode resultar em execução remota de código.",
    "326": "Comunicações criptografadas podem ser interceptadas e decifradas por atacantes na rede.",
    "327": "Algoritmos criptográficos fracos podem ser quebrados, expondo dados sensíveis.",
    "295": "Comunicações TLS podem ser interceptadas por ataques man-in-the-middle.",
    "1021":"Usuários podem ser induzidos a clicar em elementos invisíveis sobrepostos (clickjacking).",
    "319": "Dados transmitidos em texto claro podem ser interceptados por qualquer observador na rede.",
    "200": "Informações sobre tecnologias, versões ou estrutura interna expostas a atacantes.",
    "693": "Ausência de cabeçalhos de segurança deixa o browser do usuário sem proteções básicas contra XSS e injeção.",
    "1004":"Cookies de sessão acessíveis via JavaScript podem ser roubados por scripts maliciosos (XSS).",
    "1395":"Biblioteca JavaScript com vulnerabilidade conhecida e exploit público disponível.",
    "312": "Dados sensíveis armazenados sem criptografia podem ser acessados diretamente no banco de dados.",
    "384": "Um atacante pode fixar o identificador de sessão de um usuário e assumir sua conta após login.",
}

# ── Mapa de remediação específica por CWE ────────────────────
REMEDIATION_MAP = {
    "89":  "Use prepared statements (parametrized queries) em todas as queries SQL. Nunca concatene dados do usuário diretamente.",
    "79":  "Escape de output em contexto HTML/JS. Implemente Content-Security-Policy. Use bibliotecas como DOMPurify.",
    "352": "Implemente tokens CSRF (ex: SameSite=Strict em cookies, token por formulário). Frameworks como Spring, Django e Rails têm suporte nativo.",
    "22":  "Valide e normalize caminhos de arquivo. Use allowlist de diretórios permitidos. Evite concatenar input do usuário em caminhos.",
    "287": "Implemente autenticação forte com MFA. Use sessões seguras com expiração adequada.",
    "306": "Adicione autenticação a todos os endpoints. Use middleware de auth centralizado.",
    "284": "Valide no servidor que o usuário tem permissão para acessar o recurso solicitado. Não confie apenas no ID da URL.",
    "918": "Valide e filtre URLs de destino em qualquer funcionalidade de proxy/redirect. Use allowlist de hosts permitidos.",
    "693": "Configure cabeçalhos: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security.",
    "1004":"Adicione flag HttpOnly em todos os cookies de sessão. Use também Secure e SameSite=Strict.",
    "1395":"Atualize a biblioteca para a versão mais recente. Verifique release notes para breaking changes.",
    "326": "Use TLS 1.2+ com cipher suites modernas. Desabilite SSLv3, TLS 1.0, TLS 1.1 e RC4.",
    "319": "Force HTTPS em toda a aplicação. Implemente HSTS. Redirecione HTTP para HTTPS.",
    "352": "Tokens CSRF em formulários e headers X-CSRF-Token para APIs. Verifique Origin/Referer como camada adicional.",
    "312": "Criptografe dados sensíveis em repouso. Use bcrypt/Argon2 para senhas. Nunca armazene em texto claro.",
}

def cvss_to_sev(score):
    """Converte score CVSS para severidade pelo padrão NVD."""
    if score is None: return None
    score = float(score)
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score >= 0.1: return "low"
    return "info"

OUTDIR          = os.environ.get('OUTDIR','scan_output')
TARGET          = os.environ.get('TARGET','https://example.com')
DOMAIN          = os.environ.get('DOMAIN','example.com')
OPEN_PORTS      = os.environ.get('OPEN_PORTS','N/A')
ACTIVE_COUNT    = os.environ.get('ACTIVE_COUNT','0')
SUB_COUNT       = os.environ.get('SUB_COUNT','0')
OPENAPI_FOUND   = os.environ.get('OPENAPI_FOUND','0') == '1'
TLS_ISSUES      = int(os.environ.get('TLS_ISSUES','0'))
CONFIRMED_COUNT = int(os.environ.get('CONFIRMED_COUNT','0'))
SCAN_START_TS   = int(os.environ.get('SCAN_START_TS','0'))
JS_SECRETS      = int(os.environ.get('JS_SECRETS','0'))
JS_ENDPOINTS    = int(os.environ.get('JS_ENDPOINTS','0'))
JS_FRAMEWORKS   = int(os.environ.get('JS_FRAMEWORKS','0'))
JS_FILES        = int(os.environ.get('JS_FILES','0'))
KATANA_URLS     = int(os.environ.get('KATANA_URLS','0'))
WAF_DETECTED    = os.environ.get('WAF_DETECTED','') == '1'
WAF_NAME        = os.environ.get('WAF_NAME','')
EMAIL_ISSUES    = int(os.environ.get('EMAIL_ISSUES','0'))
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
                    "severity":sev,"description":(info.get("description","N/A") or "N/A"),
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
zap_low_groups = {}  # Low/Info: tabela compacta
zap_dedup      = {}  # Critical/High/Medium: card único por tipo
# Carregar request/response do XML ZAP para evidência completa
_zap_xml_evidence = {}  # name -> {request, response}
_zap_xml_path = os.path.join(OUTDIR,"raw","zap_evidencias.xml")
if os.path.exists(_zap_xml_path):
    try:
        import xml.etree.ElementTree as ET
        _xtree = ET.parse(_zap_xml_path)
        for _xalert in _xtree.findall(".//alertitem"):
            _xname = (_xalert.findtext("alert") or "").strip()
            if _xname and _xname not in _zap_xml_evidence:
                _xreq  = (_xalert.findtext("requestheader") or "").strip()
                _xreqb = (_xalert.findtext("requestbody") or "").strip()
                _xres  = (_xalert.findtext("responseheader") or "").strip()
                _xresb = (_xalert.findtext("responsebody") or "").strip()
                _xfull_req = _xreq + ("\n\n" + _xreqb if _xreqb else "")
                _xfull_res = _xres + ("\n\n" + _xresb if _xresb else "")  # evidência completa sem truncagem
                _zap_xml_evidence[_xname] = {
                    "request":  _xfull_req,
                    "response": _xfull_res
                }
    except Exception as _xe: errors.append(f"ZAP XML: {_xe}")

zap_file = os.path.join(OUTDIR,"raw","zap_alerts.json")
if os.path.exists(zap_file) and os.path.getsize(zap_file) > 0:
    try:
        zap_data = json.load(open(zap_file,"r",encoding="utf-8"))
        rmap = {"high":"high","medium":"medium","low":"low","informational":"info"}
        # Filtrar alertas de confiança "False Positive" ou "Low" confidence para Low/Info
        SKIP_CONFIDENCE = {"false positive"}
        for i,a in enumerate(zap_data.get("alerts",[])):
            try:
                sev_orig = rmap.get(a.get("risk","info").lower(),"info")
                conf = a.get("confidence","").lower()
                # Descartar apenas confirmados como falsos positivos
                if conf in SKIP_CONFIDENCE:
                    continue
                # Reclassificar severidade via CVSS do CWE (Opção C — tabela sintética)
                _cweid = str(a.get("cweid","") or "")
                _cwe_data = cwe_enrich(_cweid)
                sev_reclassified = False
                if _cwe_data:
                    sev_from_cvss = cvss_to_sev(_cwe_data["cvss"])
                    if sev_from_cvss and sev_from_cvss != sev_orig:
                        sev = sev_from_cvss
                        sev_reclassified = True
                    else:
                        sev = sev_orig
                else:
                    sev = sev_orig
                # Evidência completa: campos JSON + request/response do XML ZAP
                ev_parts_zap = []
                _alert_name = a.get("name","")
                _xml_ev = _zap_xml_evidence.get(_alert_name, {})
                if a.get("param",""):      ev_parts_zap.append(f"Parâmetro: {a['param']}")
                if a.get("attack",""):     ev_parts_zap.append(f"Vetor de Ataque:\n{a['attack']}")
                if a.get("evidence",""):   ev_parts_zap.append(f"Evidência:\n{a['evidence']}")
                if _xml_ev.get("request"): ev_parts_zap.append(f"--- REQUISIÇÃO HTTP ---\n{_xml_ev['request']}")
                if _xml_ev.get("response"):ev_parts_zap.append(f"--- RESPOSTA HTTP ---\n{_xml_ev['response']}")
                if a.get("other",""):      ev_parts_zap.append(f"Detalhe adicional:\n{a['other']}")
                ev = "\n\n".join(ev_parts_zap)  # sem truncagem — evidência completa
                # Extrair CVE do campo reference; fallback para CWE
                _refs = a.get("reference","") or ""
                _cves = re.findall(r"CVE-\d{4}-\d{4,7}", _refs, re.IGNORECASE)
                _cve_str = ", ".join(sorted(set(c.upper() for c in _cves))) if _cves \
                    else f"CWE-{a.get('cweid','N/A')}"
                f_entry = {"source":"OWASP ZAP","name":a.get("name","Alerta"),
                    "severity":sev,
                    "severity_orig":sev_orig,
                    "severity_reclassified":sev_reclassified,
                    "cvss_synthetic":_cwe_data["cvss"] if _cwe_data else None,
                    "description":(a.get("description","N/A") or "N/A"),
                    "cve": f"{_cve_str} | Conf: {a.get('confidence','?')}",
                    "url":a.get("url",TARGET),
                    "remediation":a.get("solution","Revisar.") or "Revisar.",
                    "evidence":ev,
                    "param":(a.get("param","") or ""),
                    "attack":(a.get("attack","") or ""),
                    "other":(a.get("other","") or "")}
                # Estratégia de deduplicação por severidade:
                # Critical/High → card único por nome (melhor evidência + lista de URLs)
                # Medium        → card único por nome (melhor evidência + lista de URLs)
                # Low/Info      → tabela compacta agrupada
                name = a.get("name","Alerta")
                url  = a.get("url","")
                if sev in ("low","info"):
                    if name not in zap_low_groups:
                        zap_low_groups[name] = {"count":0,"urls":[],"finding":f_entry,
                            "cve": _cve_str, "conf":a.get("confidence","?"),
                            "sev": sev}
                    zap_low_groups[name]["count"] += 1
                    if url and url not in zap_low_groups[name]["urls"]:
                        zap_low_groups[name]["urls"].append(url)
                else:
                    # Deduplicar Medium/High/Critical por nome
                    # Manter o finding com maior evidência; acumular URLs distintas
                    if name not in zap_dedup:
                        zap_dedup[name] = {"finding": f_entry, "urls": [], "count": 0, "sev": sev}
                    # Promover para maior severidade encontrada
                    sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
                    if sev_order.get(sev,5) < sev_order.get(zap_dedup[name]["sev"],5):
                        zap_dedup[name]["finding"] = f_entry
                        zap_dedup[name]["sev"] = sev
                    # Preferir finding com evidência real
                    if f_entry.get("evidence") and not zap_dedup[name]["finding"].get("evidence"):
                        zap_dedup[name]["finding"] = f_entry
                    zap_dedup[name]["count"] += 1
                    if url and url not in zap_dedup[name]["urls"]:
                        zap_dedup[name]["urls"].append(url)
            except Exception as e: errors.append(f"ZAP alerta {i}: {e}")
    except json.JSONDecodeError as e: errors.append(f"ZAP JSON malformado: {e}")
    except Exception as e: errors.append(f"ZAP: {e}")

# Converter zap_dedup em zap_findings, injetando lista de URLs afetadas
for name, grp in zap_dedup.items():
    f = dict(grp["finding"])  # cópia
    affected = grp["urls"]
    f["severity"] = grp["sev"]  # severidade mais alta encontrada
    f["affected_count"] = grp["count"]
    f["affected_urls"] = affected
    # Se mais de uma URL, adicionar lista às outras informações do card
    if len(affected) > 1:
        extra = f"\n\n[{len(affected)} URLs afetadas]\n" + "\n".join(f"  • {u}" for u in affected[:20])
        if len(affected) > 20:
            extra += f"\n  ... e mais {len(affected)-20} URL(s)"
        f["other"] = (f.get("other","") + extra).strip()
    zap_findings.append(f)

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

# ── WAF & Email Security ───────────────────────────────────
email_security = {}
_esf = os.path.join(OUTDIR,'raw','email_security.json')
if os.path.exists(_esf):
    try: email_security = json.load(open(_esf))
    except Exception as e: errors.append(f'email_security: {e}')

# ── Scan metadata (comportamento + evasão) ───────────────────
scan_meta = {}
_smf = os.path.join(OUTDIR,'raw','scan_metadata.json')
if os.path.exists(_smf):
    try: scan_meta = json.load(open(_smf))
    except Exception as e: errors.append(f'scan_metadata: {e}')

# ── JS Analysis ──────────────────────────────────────────────
js_analysis = {}
js_file = os.path.join(OUTDIR,"raw","js_analysis.json")
if os.path.exists(js_file) and os.path.getsize(js_file) > 0:
    try: js_analysis = json.load(open(js_file,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"js_analysis: {e}")
js_secrets    = js_analysis.get("secrets",[])
js_endpoints  = js_analysis.get("endpoints",[])
js_frameworks = js_analysis.get("frameworks",[])
js_files_list = js_analysis.get("js_files",[])
js_probes     = js_analysis.get("endpoint_probes",[])
js_comments   = js_analysis.get("sensitive_comments",[])

# ── CVE enrichment (NVD + EPSS) ──────────────────────────────
cve_enrichment = {}
cve_db_file = os.path.join(OUTDIR,"raw","cve_enrichment.json")
if os.path.exists(cve_db_file) and os.path.getsize(cve_db_file) > 0:
    try: cve_enrichment = json.load(open(cve_db_file,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"cve_enrichment: {e}")

# KEV matches — CVEs encontrados no catálogo CISA
kev_matches = {}
_kev_f = os.path.join(OUTDIR,"raw","kev_matches.json")
if os.path.exists(_kev_f):
    try: kev_matches = json.load(open(_kev_f,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"kev_matches: {e}")
kev_count = len(kev_matches)

# Reclassificar achados Nuclei usando CVSS real do NVD quando disponível
for f in findings:
    cve_field = f.get('cve','')
    cve_ids_f = re.findall(r'CVE-\d{4}-\d{4,7}', cve_field, re.IGNORECASE)
    best_cvss = None
    for cid in [c.upper() for c in cve_ids_f]:
        ev = cve_enrichment.get(cid,{})
        cvss_val = ev.get('cvss_v3') or ev.get('cvss_v2')
        if cvss_val and (best_cvss is None or float(cvss_val) > best_cvss):
            best_cvss = float(cvss_val)
    if best_cvss is not None:
        new_sev = cvss_to_sev(best_cvss)
        if new_sev and new_sev != f['severity']:
            f['severity_orig'] = f['severity']
            f['severity'] = new_sev
            f['severity_reclassified'] = True
            f['cvss_real'] = best_cvss
        else:
            f.setdefault('severity_orig', f['severity'])
            f.setdefault('severity_reclassified', False)
    else:
        f.setdefault('severity_orig', f['severity'])
        f.setdefault('severity_reclassified', False)


# Stats — contagem de CARDS únicos por severidade (padrão relatórios profissionais)
# Cada tipo de vulnerabilidade = 1, independente de quantas URLs afeta
all_f = sorted(findings + zap_findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x["severity"],5))
stats = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
for f in all_f:
    if f["severity"] in stats: stats[f["severity"]] += 1
# Low/Info: cada grupo = 1 card (tipo único)
for grp in zap_low_groups.values():
    sev = grp["finding"]["severity"]
    if sev in stats: stats[sev] += 1
total = sum(stats.values())

# Ocorrências reais — usadas apenas para o risk score (reflete severidade total do ambiente)
occurrences = dict(stats)
for grp in zap_low_groups.values():
    sev = grp["finding"]["severity"]
    if sev in occurrences: occurrences[sev] += (grp["count"] - 1)
for grp in zap_dedup.values():
    sev = grp["sev"]
    if sev in occurrences: occurrences[sev] += (grp["count"] - 1)

# ── Risk score: KEV > EPSS > CVSS (metodologia 2026) ───────────
# Base: ocorrências ponderadas por severidade CVSS
base_risk = (occurrences["critical"]*10) + (occurrences["high"]*5) + (occurrences["medium"]*2) + occurrences["low"]

# Camada 1 — KEV: exploração ativa confirmada (peso máximo)
# Um CVE no KEV é automaticamente urgente independente do CVSS
kev_bonus = 0
kev_count = sum(1 for ev in cve_enrichment.values() if ev.get("in_kev"))
if kev_count > 0:
    kev_bonus = min(kev_count * 25, 50)  # +25 por CVE no KEV, cap 50

# Camada 2 — EPSS: probabilidade de exploração nos próximos 30 dias
epss_bonus = 0
for ev in cve_enrichment.values():
    epss = ev.get("epss_score") or 0
    if epss >= 0.5:    epss_bonus += 15   # exploit muito provável (>50%)
    elif epss >= 0.1:  epss_bonus += 7    # exploit provável (>10%)
    elif epss >= 0.01: epss_bonus += 2    # exploit possível (>1%)
# Bônus JS: secrets e frameworks vulneráveis agravam o risco
HIGH_JS_TYPES = {"AWS Access Key","AWS Secret","Private Key","Stripe Live Key","GitHub Token","GitLab PAT","OpenAI Key","Anthropic Key","Hardcoded Password","DB Connection String"}
js_high   = [s for s in js_secrets if s.get("type","") in HIGH_JS_TYPES]
js_medium = [s for s in js_secrets if s.get("type","") not in HIGH_JS_TYPES]
js_vuln_fw = [f for f in js_frameworks if f.get("vulnerable")]
js_bonus = min(len(js_high)*15 + len(js_medium)*5 + len(js_vuln_fw)*8, 30)
risk = min(base_risk + kev_bonus + epss_bonus + js_bonus, 100)
stxt,scol = ("CRÍTICO — Ação Imediata","#7a2e2e") if stats["critical"] else \
            ("ALTO — Atenção Urgente","#b34e4e") if stats["high"] else \
            ("MÉDIO — Correção Planejada","#d4833a") if stats["medium"] else \
            ("BAIXO — Monitoramento","#4a7c8c")
rdate = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
import time as _time
duration_secs = int(_time.time()) - SCAN_START_TS if SCAN_START_TS else 0
duration_str = f"{duration_secs//3600}h {(duration_secs%3600)//60}m {duration_secs%60}s" if duration_secs > 0 else "N/A"

def badge(sev):
    labels = {"critical":"CRÍTICO","high":"ALTO","medium":"MÉDIO","low":"BAIXO","info":"INFO"}
    c={"critical":"#7a2e2e","high":"#b34e4e","medium":"#d4833a","low":"#4a7c8c","info":"#6e8f72"}.get(sev,"#999")
    return f'<span style="background:{c};color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{labels.get(sev, labels.get(sev.lower(), sev.upper()))}</span>'

def trows(items,empty="Sem resultados"):
    if not items: return f'<tr><td style="color:#999;font-style:italic">{empty}</td></tr>'
    return "".join(f'<tr><td style="font-family:monospace;font-size:12px">{html.escape(i)}</td></tr>' for i in items[:50])

def render_finding(f):
    # Enriquecer CVE com dados NVD/EPSS se disponível
    cve_val = f.get('cve','N/A')
    enrich_rows = ''
    # Extrair CVE IDs do campo cve
    cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', cve_val, re.IGNORECASE)
    for cve_id in [c.upper() for c in cve_ids]:
        ev = cve_enrichment.get(cve_id, {})
        if ev:
            cvss = ev.get('cvss_v3') or ev.get('cvss_v2')
            epss = ev.get('epss_score')
            epss_pct = ev.get('epss_percentile')
            sev = ev.get('severity','')
            desc_nvd = ev.get('description','')
            cvss_color = '#7a2e2e' if cvss and cvss>=9 else '#b34e4e' if cvss and cvss>=7 else '#d4833a' if cvss and cvss>=4 else '#27ae60'
            epss_color = '#7a2e2e' if epss and epss>=0.5 else '#d4833a' if epss and epss>=0.1 else '#27ae60'
            enrich_rows += f'<tr><th>{html.escape(cve_id)}</th><td>'
            _SEV_PT = {"CRITICAL":"CRÍTICO","HIGH":"ALTO","MEDIUM":"MÉDIO","LOW":"BAIXO"}
            sev_pt = _SEV_PT.get(str(sev).upper(), sev)
            # KEV badge — máxima prioridade, exibido antes de CVSS/EPSS
            in_kev = ev.get("in_kev", False)
            kev_info = ev.get("kev", {})
            if in_kev:
                kev_due = kev_info.get("due_date","")
                kev_added = kev_info.get("date_added","")
                kev_prod = f"{kev_info.get('vendor','')} {kev_info.get('product','')}".strip()
                enrich_rows += (f'<span style="background:#7a0000;color:white;padding:2px 10px;'
                    f'border-radius:4px;font-size:12px;font-weight:bold;'
                    f'border:2px solid #ff4444;letter-spacing:.3px">'
                    f'🔴 EXPLORAÇÃO ATIVA — CISA KEV</span> ')
                if kev_due: enrich_rows += f'<span style="background:#b34e4e;color:white;padding:1px 6px;border-radius:3px;font-size:11px">Prazo CISA: {html.escape(kev_due)}</span> '
                if kev_prod: enrich_rows += f'<br><small style="color:#7a0000;font-weight:bold">Adicionado ao KEV em {html.escape(kev_added)} — {html.escape(kev_prod)}</small> '
            if cvss: enrich_rows += f'<span style="background:{cvss_color};color:white;padding:1px 6px;border-radius:3px;font-size:12px;font-weight:bold">CVSS {cvss} {html.escape(sev_pt)}</span> '
            if epss is not None: enrich_rows += f'<span style="background:{epss_color};color:white;padding:1px 6px;border-radius:3px;font-size:12px">EPSS {epss:.4f} ({epss_pct*100:.1f}° percentil)</span> '
            if desc_nvd: enrich_rows += f'<br><small style="color:#555">{html.escape(desc_nvd)}</small>'
            enrich_rows += '</td></tr>'
    # Fallback CWE sintético — quando não há CVE NVD disponível
    if not cve_ids or not enrich_rows:
        cwe_match = re.search(r'CWE-?(\d+)', cve_val, re.IGNORECASE)
        if cwe_match:
            cwe_data = cwe_enrich(cwe_match.group(1))
            if cwe_data:
                cvss = cwe_data["cvss"]
                _SEV_PT = {"CRITICAL":"CRÍTICO","HIGH":"ALTO","MEDIUM":"MÉDIO","LOW":"BAIXO"}
                sev_label = _SEV_PT.get(cwe_data["sev"], cwe_data["sev"])
                cwe_name = cwe_data["name"]
                cvss_color = '#7a2e2e' if cvss>=9 else '#b34e4e' if cvss>=7 else '#d4833a' if cvss>=4 else '#27ae60'
                enrich_rows += (f'<tr><th>CWE-{cwe_match.group(1)}</th><td>'
                    f'<span style="background:{cvss_color};color:white;padding:1px 6px;border-radius:3px;font-size:12px;font-weight:bold">CVSS ~{cvss} {sev_label}</span> '
                    f'<span style="background:#636e72;color:white;padding:1px 6px;border-radius:3px;font-size:11px">Estimativa baseada em CWE</span>'
                    f'<br><small style="color:#555">{html.escape(cwe_name)}</small>'
                    f'</td></tr>')
    # Badge de reclassificação — mostrar quando severidade original difere da atual
    sev_orig = f.get('severity_orig', f.get('severity',''))
    was_reclassified = f.get('severity_reclassified', False)
    reclassify_badge = ''
    if was_reclassified and sev_orig and sev_orig != f.get('severity',''):
        labels = {'critical':'CRÍTICO','high':'ALTO','medium':'MÉDIO','low':'BAIXO','info':'INFO'}
        orig_label = labels.get(sev_orig, sev_orig.upper())
        reclassify_badge = (f'<span style="background:#2d3436;color:#dfe6e9;'
            f'padding:2px 7px;border-radius:4px;font-size:10px;margin-left:6px">'
            f'↑ Reclassificado de {orig_label} (CVE/CWE)</span>')

    rows = f"""
    <tr><th style="width:120px">CVE/CWE</th><td>{html.escape(str(f.get('cve','N/A')))}</td></tr>
    {enrich_rows}
    <tr><th>URL</th><td><code>{html.escape(f.get('url',''))}</code></td></tr>
    <tr><th>Descrição</th><td>{html.escape(f.get('description',''))}</td></tr>"""
    # Impacto prático — extrair CWE do campo cve para lookup no IMPACT_MAP
    _cwe_for_impact = re.search(r'CWE-?(\d+)', f.get("cve",""), re.IGNORECASE)
    _impact = IMPACT_MAP.get(_cwe_for_impact.group(1), "") if _cwe_for_impact else ""
    _remediation_specific = REMEDIATION_MAP.get(_cwe_for_impact.group(1), "") if _cwe_for_impact else ""
    if _impact:
        rows += (f'\n    <tr><th style="background:#fff3cd;color:#856404">⚠ Impacto</th>'
            f'<td style="background:#fff3cd;color:#856404;font-weight:500">{html.escape(_impact)}</td></tr>')
    if _remediation_specific:
        rows += (f'\n    <tr><th style="background:#d4edda;color:#155724">✓ Como Corrigir</th>'
            f'<td style="background:#d4edda;color:#155724">{html.escape(_remediation_specific)}</td></tr>')
    if f.get('param'):
        rows += f"\n    <tr><th>Parâmetro</th><td><code>{html.escape(f['param'])}</code></td></tr>"
    if f.get('attack'):
        rows += f"\n    <tr><th>Ataque</th><td><code>{html.escape(f['attack'])}</code></td></tr>"
    # Exibir evidência dividida em blocos legíveis
    _ev_full = f.get("evidence","")
    if _ev_full:
        _req_match  = re.search(r"--- REQUISIÇÃO HTTP ---\n(.*?)(?=---|$)", _ev_full, re.DOTALL)
        _res_match  = re.search(r"--- RESPOSTA HTTP ---\n(.*?)(?=---|$)", _ev_full, re.DOTALL)
        _ev_other   = re.sub(r"--- (REQUISIÇÃO|RESPOSTA) HTTP ---\n.*?(?=---|$)", "", _ev_full, flags=re.DOTALL).strip()
        if _ev_other:
            rows += f'\n    <tr><th>Evidência</th><td><div class="evidence-box">{html.escape(_ev_other)}</div></td></tr>'
        if _req_match:
            rows += f'\n    <tr><th>Requisição HTTP</th><td><div class="evidence-box">{html.escape(_req_match.group(1).strip())}</div></td></tr>'
        if _res_match:
            rows += f'\n    <tr><th>Resposta HTTP</th><td><div class="evidence-box">{html.escape(_res_match.group(1).strip())}</div></td></tr>'
    if f.get('affected_count', 0) > 1:
        n = f['affected_count']
        urls_sample = f.get('affected_urls', [])
        url_list = ''.join(f'<li><code>{html.escape(u)}</code></li>' for u in urls_sample)
        rows += (f'\n    <tr><th>URLs Afetadas</th>'
            f'<td><strong>{n} ocorrência(s)</strong> do mesmo tipo de alerta:<ul style="margin:6px 0 0;padding-left:18px">{url_list}</ul></td></tr>')
    other_val = f.get('other','')
    if other_val and '[URLs afetadas]' not in other_val:
        rows += f"\n    <tr><th>Detalhe</th><td>{html.escape(other_val)}</td></tr>"
    rows += f"\n    <tr><th>Recomendação</th><td>{html.escape(f.get('remediation',''))}</td></tr>"
    src_cls = 'source-nuclei' if f.get('source') == 'Nuclei' else 'source-zap'
    return f'''<div class="vuln {f['severity']}">
  <h3>{html.escape(f.get('name',''))} <span class="source-badge {src_cls}">{f.get('source','')}</span> {badge(f['severity'])}{reclassify_badge}</h3>
  <table>{rows}
  </table></div>'''

vhtml = '<div class="info-box"><p>✅ Nenhuma vulnerabilidade encontrada no escopo analisado.</p></div>' if not all_f else     "".join(render_finding(f) for f in all_f)

# Tabela compacta para Low/Info agrupados
low_table_html = ""
if zap_low_groups:
    rows_low = "".join(
        f'<tr><td>{html.escape(name)}</td>'
        f'<td style="text-align:center">{grp["count"]}</td>'
        f'<td style="text-align:center">{badge(grp.get("sev", grp["finding"]["severity"]))}</td>'
        f'<td>{html.escape(grp["cve"])}</td>'
        f'<td>{html.escape(grp["conf"])}</td>'
        f'<td style="font-size:11px;color:#555">{"<br>".join(html.escape(u) for u in grp["urls"])}</td>'
        f'<td style="font-size:11px">{html.escape(grp["finding"]["remediation"] or "")}</td></tr>'
        for name, grp in sorted(zap_low_groups.items())
    )
    low_table_html = f'''<h2>4. Achados Baixo / Informativo — ZAP ({len(zap_low_groups)} tipos distintos, {sum(g["count"] for g in zap_low_groups.values())} ocorrências no total)</h2>
    <p style="color:#666;font-size:13px">Agrupados por tipo para reduzir ruído. Validar manualmente antes de reportar.</p>
    <table>
      <tr style="background:#f5f5f5"><th>Tipo de Alerta</th><th>Qtd</th><th>Sev</th><th>CVE / CWE</th><th>Confiança</th><th>URLs (amostra)</th><th>Recomendação</th></tr>
      {rows_low}
    </table>'''

# ── Gerar HTML: WAF & Email Security ────────────────────────
waf_email_html = ''

# WAF banner
if WAF_DETECTED and WAF_NAME:
    waf_email_html += (f'<div style="background:#fff3cd;border-left:5px solid #d4833a;'
        f'padding:14px 16px;border-radius:4px;margin:16px 0">'
        f'<strong style="color:#856404">🛡 WAF Detectado: {html.escape(WAF_NAME)}</strong>'
        f'<p style="margin:6px 0 0;font-size:13px;color:#555">'
        f'O alvo está protegido por um Web Application Firewall. Achados do active scan '
        f'podem ter falsos negativos — vulnerabilidades de injeção podem ter sido bloqueadas '
        f'durante o scan sem serem detectadas.</p></div>')

# Email security
if email_security:
    sev_color = {'high':'#b34e4e','medium':'#d4833a','low':'#4a7c8c','none':'#27ae60'}
    sev_label = {'high':'ALTO','medium':'MÉDIO','low':'BAIXO','none':'OK','NOT_FOUND':'INFO'}
    email_rows = ''
    for proto, data in [('SPF', email_security.get('spf',{})),
                         ('DMARC', email_security.get('dmarc',{})),
                         ('DKIM',  email_security.get('dkim',{}))]:
        sev  = data.get('severity','none')
        stat = data.get('status','?')
        det  = data.get('detail','')
        rec  = data.get('recommendation','')
        val  = data.get('value','')
        sc   = sev_color.get(sev,'#999')
        sl   = sev_label.get(stat, sev_label.get(sev,'?'))
        email_rows += (f'<tr>'
            f'<td style="font-weight:bold;width:80px">{proto}</td>'
            f'<td style="text-align:center"><span style="background:{sc};color:white;'
            f'padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{sl}</span></td>'
            f'<td>{html.escape(det)}</td>'
            f'<td style="font-size:11px;color:#555">{html.escape(rec) if rec else ("<code>"+html.escape(val)+"</code>" if val else "—")}</td>'
            f'</tr>')
    waf_email_html += (f'<h3>Segurança de Email — {html.escape(DOMAIN)}</h3>'
        '<table><tr style="background:#f5f5f5">'
        '<th>Protocolo</th><th>Status</th><th>Detalhe</th><th>Recomendação / Valor</th></tr>'
        + email_rows + '</table>')

if waf_email_html:
    waf_email_html = f'<h2>Infraestrutura & Segurança DNS</h2>' + waf_email_html

# ── Gerar HTML: Comportamento do Scan ─────────────────────────
scan_behavior_html = ""
if scan_meta:
    evasion_active = scan_meta.get("evasion_active", False)
    waf_n          = scan_meta.get("waf_name", "")
    techniques     = scan_meta.get("evasion_techniques", [])
    rl             = scan_meta.get("nuclei_rate_limit", 50)
    conc           = scan_meta.get("nuclei_concurrency", 10)
    delay          = scan_meta.get("nuclei_delay")
    ua             = scan_meta.get("user_agent", "")
    nuc_count      = scan_meta.get("nuclei_results_after_evasion")
    zap_count      = scan_meta.get("zap_results_after_evasion")

    TECH_LABELS = {
        "rate_limit_reduced":     ("🐢", "Rate limit reduzido",     f"Nuclei: {rl} req/s com delay randômico — imita tráfego humano"),
        "user_agent_rotation":    ("🔄", "User-Agent rotation",     f"UA de browser real: {ua[:60]}..." if len(ua)>60 else f"UA: {ua}"),
        "origin_spoofing":        ("🎭", "Origin spoofing",         "X-Forwarded-For: 127.0.0.1 + X-Real-IP: 127.0.0.1 injetados"),
        "payload_alterations":    ("🔀", "Payload alterations",     "Nuclei testou variações de encoding automaticamente (-pa)"),
        "waf_response_bypass":    ("⏭", "WAF response bypass",     "Respostas 403/406/429 ignoradas — scan não interrompe em bloqueios"),
        "zap_threads_reduced":    ("🧵", "ZAP threads reduzidas",   "Active scan com 2 threads — reduz assinatura de scan automatizado"),
    }

    if evasion_active:
        tech_rows = "".join(
            f'<tr>'
            f'<td style="font-size:18px;text-align:center;width:36px">{icon}</td>'
            f'<td style="font-weight:600;width:180px">{label}</td>'
            f'<td style="color:#555;font-size:13px">{desc}</td>'
            f'<td style="text-align:center"><span style="background:#27ae60;color:white;'
            f'padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">ATIVO</span></td>'
            f'</tr>'
            for t in techniques for icon, label, desc in [TECH_LABELS.get(t, ("","",""))]
            if label
        )

        results_row = ""
        if nuc_count is not None:
            results_row += (f'<div style="display:inline-block;background:#f0f7ff;'
                f'border:1px solid #388bfd;border-radius:8px;padding:12px 20px;margin:6px 8px 6px 0">'
                f'<div style="font-size:28px;font-weight:bold;color:#1a3a4f">{nuc_count}</div>'
                f'<div style="font-size:12px;color:#555">achados Nuclei\ncom evasão</div></div>')
        if zap_count is not None:
            results_row += (f'<div style="display:inline-block;background:#f0f7ff;'
                f'border:1px solid #388bfd;border-radius:8px;padding:12px 20px;margin:6px 8px 6px 0">'
                f'<div style="font-size:28px;font-weight:bold;color:#1a3a4f">{zap_count}</div>'
                f'<div style="font-size:12px;color:#555">alertas ZAP\ncom evasão</div></div>')

        scan_behavior_html = (
            f'<h2>🔬 Comportamento do Scan & Evasão Passiva</h2>'
            f'<div style="background:#fff8e6;border-left:5px solid #d4833a;'
            f'padding:16px;border-radius:4px;margin-bottom:16px">'
            f'<strong style="color:#856404">⚠ WAF Detectado: {html.escape(waf_n)}</strong>'
            f'<p style="margin:6px 0 0;font-size:13px;color:#555">'
            f'O scanner detectou um WAF e ativou automaticamente o modo de evasão passiva. '
            f'As técnicas abaixo foram aplicadas para maximizar a cobertura e reduzir falsos negativos.</p></div>'
            f'<h3 style="color:#1a3a4f;margin-bottom:8px">Técnicas de Evasão Passiva Aplicadas</h3>'
            f'<table style="margin-bottom:16px"><tr style="background:#f5f5f5">'
            f'<th></th><th style="text-align:left">Técnica</th>'
            f'<th style="text-align:left">Detalhe</th><th>Status</th></tr>'
            + tech_rows +
            f'</table>'
            + (f'<h3 style="color:#1a3a4f;margin-bottom:8px">Resultados com Evasão Ativa</h3>'
               f'<div style="margin-bottom:8px">{results_row}</div>'
               f'<p style="font-size:12px;color:#888;margin:4px 0">Resultados obtidos após aplicação das técnicas de evasão. '
               f'Comparar com scans sem evasão não é aplicável pois o WAF teria bloqueado requests anteriores.</p>'
               if results_row else "")
        )
    else:
        # Sem WAF — registrar que scan foi direto
        scan_behavior_html = (
            f'<h2>🔬 Comportamento do Scan</h2>'
            f'<div style="background:#f0fff4;border-left:5px solid #27ae60;'
            f'padding:14px 16px;border-radius:4px">'
            f'<strong style="color:#1a7a4a">✓ Nenhum WAF Detectado — Scan Direto</strong>'
            f'<p style="margin:6px 0 0;font-size:13px;color:#555">'
            f'O alvo não possui WAF identificado. O scan rodou com configurações padrão '
            f'(Nuclei {rl} req/s, concurrency {conc}). '
            f'Resultados têm alta confiança — sem filtros intermediários.</p></div>'
        )

errsec = "" if not errors else \
    '<h2>⚠ Avisos de Processamento</h2><div class="info-box" style="border-left-color:#d4833a"><ul>' + \
    "".join(f"<li><code>{html.escape(e)}</code></li>" for e in errors) + "</ul></div>"

# ── Gerar HTML: Análise JS ───────────────────────────────────
js_html = ""
if js_analysis:
    HIGH_JS_TYPES = {"AWS Access Key","AWS Secret","Private Key","Stripe Live Key",
        "GitHub Token","GitLab PAT","OpenAI Key","Anthropic Key","Hardcoded Password",
        "DB Connection String","Firebase Key","Slack Token"}
    def js_sev(t): return "high" if t in HIGH_JS_TYPES else "medium"
    def js_sev_color(s): return {"high":"#b34e4e","medium":"#d4833a"}.get(s,"#4a7c8c")
    def js_badge(t):
        s=js_sev(t); c=js_sev_color(s)
        lbl={"high":"ALTO","medium":"MÉDIO"}.get(s,"BAIXO")
        return f'<span style="background:{c};color:white;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:bold">{lbl}</span>'

    # Stat bar JS
    js_accessible = [p for p in js_probes if p.get("status")==200]
    js_exposed_api = [p for p in js_probes if p.get("status")==200 and p.get("is_json")]
    js_vuln_fw = [f for f in js_frameworks if f.get("vulnerable")]
    js_html = f'''<h2>JS / Frontend — Análise de Segurança</h2>
    <div class="info-box">
      <table>
        <tr><th style="width:200px">Arquivos JS analisados</th><td>{len(js_files_list)}</td></tr>
        <tr><th>Secrets / credenciais</th><td><span style="color:#b34e4e;font-weight:bold">{sum(1 for s in js_secrets if js_sev(s["type"])=="high")}</span> alto &nbsp;|&nbsp; <span style="color:#d4833a">{sum(1 for s in js_secrets if js_sev(s["type"])=="medium")}</span> médio</td></tr>
        <tr><th>Endpoints descobertos</th><td>{len(js_endpoints)} &nbsp;|&nbsp; {len(js_accessible)} acessíveis sem autenticação</td></tr>
        <tr><th>Frameworks detectados</th><td>{len(js_frameworks)} ({len(js_vuln_fw)} com CVE conhecida)</td></tr>
        <tr><th>Comentários sensíveis</th><td>{len(js_comments)}</td></tr>
      </table>
    </div>'''

    # Secrets
    if js_secrets:
        from collections import defaultdict
        by_type = defaultdict(list)
        for s in js_secrets: by_type[s["type"]].append(s)
        js_html += "<h3>Secrets e Credenciais Detectadas</h3>"
        for stype, items in sorted(by_type.items(), key=lambda x: 0 if js_sev(x[0])=="high" else 1):
            c = js_sev_color(js_sev(stype))
            js_html += (f'<div style="border-left:5px solid {c};padding:14px 16px;margin:12px 0;'
                f'background:#ffffff;border-radius:6px;border:1px solid #e0e0e0;box-shadow:0 1px 3px rgba(0,0,0,.06)">'
                f'<div style="margin-bottom:10px">'
                f'<strong style="font-size:14px">{html.escape(stype)}</strong> {js_badge(stype)}'
                f' <span style="color:#888;font-size:12px;margin-left:6px">({len(items)} ocorrência(s))</span>'
                f'</div>'
                f'<table style="width:100%;border-collapse:collapse">'
                f'<tr>'
                f'<th style="background:#f5f5f5;color:#1a3a4f;font-weight:700;font-size:12px;'
                f'padding:8px 12px;text-align:left;border:1px solid #ddd;width:35%">Valor / Pattern</th>'
                f'<th style="background:#f5f5f5;color:#1a3a4f;font-weight:700;font-size:12px;'
                f'padding:8px 12px;text-align:left;border:1px solid #ddd">Contexto no Código</th>'
                f'</tr>')
            for item in items:
                v    = item["value"]
                ctx  = item.get("context", "")
                furl = item.get("url", "")
                js_html += (
                    f'<tr>'
                    f'<td style="padding:8px 12px;border:1px solid #eee;vertical-align:top;background:#fafafa">'
                    f'<code style="font-size:11px;color:#c0392b;background:#fff5f5;padding:3px 6px;'
                    f'border-radius:3px;word-break:break-all;display:block">{html.escape(v)}</code>'
                    + (f'<div style="font-size:10px;color:#888;margin-top:5px">📄 {html.escape(furl)}</div>' if furl else "")
                    + f'</td>'
                    f'<td style="padding:8px 12px;border:1px solid #eee;vertical-align:top">'
                    f'<pre style="margin:0;font-size:10px;font-family:monospace;background:#f8f9fa;'
                    f'color:#333;padding:6px 8px;border-radius:3px;white-space:pre-wrap;'
                    f'word-break:break-all;border:1px solid #e0e0e0;max-height:160px;'
                    f'overflow-y:auto">{html.escape(ctx) if ctx else "—"}</pre>'
                    + f'</td></tr>')
            js_html += "</table></div>"

    # Frameworks
    if js_frameworks:
        seen_fw = {}
        fw_rows = ""
        for fw in js_frameworks:
            k = (fw["framework"],fw["version"])
            if k in seen_fw: continue
            seen_fw[k]=True
            vuln_html = ('<span style="color:#b34e4e;font-weight:bold">⚠ ' +
                ', '.join(v["cve"] for v in fw.get("vulns",[])) + '</span>')\
                if fw.get("vulnerable") else '<span style="color:#27ae60">✓ OK</span>'
            fw_rows += (f'<tr><td><strong>{html.escape(fw["framework"])}</strong></td>'
                f'<td><code>{html.escape(fw["version"])}</code></td>'
                f'<td>{vuln_html}</td></tr>')
        js_html += ('<h3>Frameworks Detectados</h3>'
            '<table><tr style="background:#f5f5f5"><th>Framework</th><th>Versão</th><th>Status</th></tr>'
            + fw_rows + '</table>')

    # Endpoints acessíveis
    if js_accessible:
        ep_rows = "".join(
            f'<tr><td><code style="font-size:11px;word-break:break-all">{html.escape(p["url"])}</code></td>'
            f'<td style="text-align:center"><span style="background:#27ae60;color:white;'
            f'padding:1px 6px;border-radius:3px;font-size:11px">{p["status"]}</span></td>'
            f'<td style="font-size:11px">{"JSON API" if p.get("is_json") else "HTML"}</td></tr>'
            for p in js_accessible[:15])
        js_html += ('<h3>Endpoints Acessíveis Sem Autenticação</h3>'
            '<table><tr style="background:#f5f5f5"><th>URL</th><th>HTTP</th><th>Tipo</th></tr>'
            + ep_rows + '</table>')

    # Comentários sensíveis
    if js_comments:
        comm_rows = "".join(
            f'<tr><td style="padding:6px 10px;border-bottom:1px solid #eee">'
            f'<code style="font-size:11px;background:#f8f9fa;color:#c0392b;'
            f'padding:3px 6px;border-radius:3px;display:block;white-space:pre-wrap;'
            f'word-break:break-all;border:1px solid #e0e0e0">{html.escape(c["comment"])}</code>'
            f'<div style="font-size:10px;color:#888;margin-top:3px">📄 {html.escape(c.get("url",""))}</div>'
            f'</td></tr>'
            for c in js_comments[:10])
        js_html += ('<h3>Comentários Sensíveis no Código</h3>'
            '<table style="width:100%;border-collapse:collapse;border:1px solid #eee;border-radius:6px">'
            + comm_rows + '</table>')

# ── Gerar HTML: TLS ─────────────────────────────────────────
SEV_TLS_CLASS = {"critical":"tls-critical","high":"tls-high","medium":"tls-warn","low":"tls-warn","info":"tls-ok"}
if tls_findings:
    TLS_SEV_PT = {"CRITICAL":"CRÍTICO","HIGH":"ALTO","WARN":"AVISO","LOW":"BAIXO","OK":"OK","INFO":"INFO"}
    tls_rows = "".join(
        f'<tr><td style="font-family:monospace;font-size:12px">{html.escape(f["id"])}</td>'
        f'<td class="{SEV_TLS_CLASS.get(f["sev"],"tls-ok")}">{html.escape(TLS_SEV_PT.get(f["sev_raw"].upper(),f["sev_raw"]))}</td>'
        f'<td>{html.escape(f["finding"])}</td>'
        f'<td>{html.escape(f["cve"] or "—")}</td></tr>'
        for f in tls_findings
    )
    tls_html = f'''<h2>TLS / SSL — {len(tls_findings)} problema(s) identificado(s)</h2>
    <table>
      <tr style="background:#f5f5f5"><th>Identificador</th><th>Severidade</th><th>Achado</th><th>CVE</th></tr>
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
        f'{"✓ CONFIRMADO" if c["confirmed"] else "✗ NÃO CONFIRMADO"}</span></td>'
        f'<td style="text-align:center"><code>{html.escape(c["http_status"])}</code></td>'
        f'<td><div class="evidence-box">{html.escape(c["response_snippet"]) if c["response_snippet"] else "—"}</div></td>'
        f'</tr>'
        for c in confirmations
    )
    n_conf = sum(1 for c in confirmations if c["confirmed"])
    confirm_html = f'''<h2>Confirmação Ativa de Exploits ({n_conf} de {len(confirmations)} confirmados)</h2>
    <p style="color:#666;font-size:13px">Cada achado do Nuclei foi re-executado com o curl original para verificar se a vulnerabilidade permanece ativa no momento do scan.</p>
    <table>
      <tr style="background:#f5f5f5"><th>Template</th><th>URL</th><th>Status</th><th>HTTP</th><th>Resposta Completa</th></tr>
      {conf_rows}
    </table>'''
else:
    confirm_html = ""


# ── Gerar HTML: Plano de Ação Priorizado ─────────────────────────
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4}

# Coletar todos os achados acionáveis por prazo
imediato  = [f for f in all_f if f["severity"] in ("critical","high")]
sprint    = [f for f in all_f if f["severity"] == "medium"]
backlog   = [f for f in zap_low_groups.values() if f["sev"] in ("low","info")]

def action_card(title, icon, color, bg, items, prazo, descricao):
    if not items: return ""
    rows = ""
    seen_names = set()
    for item in items[:10]:
        name = item.get("name","") if isinstance(item,dict) and "name" in item else item.get("finding",{}).get("name","")
        if name in seen_names: continue
        seen_names.add(name)
        count = item.get("affected_count",1) if isinstance(item,dict) and "affected_count" in item else item.get("count",1)
        sev_f = item.get("severity","") if "severity" in item else item.get("sev","")
        count_str = f" <span style='color:#666;font-size:11px'>({count} ocorrência(s))</span>" if count > 1 else ""
        rows += f"<li style='margin:4px 0'><strong>{html.escape(name)}</strong>{count_str}</li>"
    return f"""<div style="border-left:5px solid {color};padding:16px;margin:12px 0;background:{bg};border-radius:4px">
  <h3 style="margin:0 0 6px;color:{color}">{icon} {html.escape(title)} <span style="font-size:12px;font-weight:normal;color:#666">— Prazo: {prazo}</span></h3>
  <p style="margin:0 0 10px;font-size:13px;color:#555">{descricao}</p>
  <ul style="margin:0;padding-left:20px;font-size:13px">{rows}</ul>
</div>"""

plan_parts = []
plan_parts.append(action_card(
    "Ação Imediata","🔴","#7a2e2e","#fff0f0",
    imediato,"esta semana",
    "Vulnerabilidades críticas e altas com potencial de comprometimento direto. Paralisar deploy se necessário."
))
plan_parts.append(action_card(
    "Próximo Sprint","🟡","#d4833a","#fff8f0",
    sprint,"próximas 2 semanas",
    "Achados médios que reduzem superfície de ataque. Incluir nas próximas histórias do time."
))
plan_parts.append(action_card(
    "Backlog de Segurança","🔵","#4a7c8c","#f0f8ff",
    backlog,"próximos 30 dias",
    "Melhorias de hardening e headers. Agendar como dívida técnica de segurança."
))

action_plan_html = ""
if any(plan_parts):
    action_plan_html = f"""<h2>Plano de Ação para o Time</h2>
<div class="info-box">
  <p>Priorização baseada em CVSS + EPSS. Achados com maior probabilidade de exploração ativa foram priorizados.</p>
</div>
{"".join(plan_parts)}"""

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
</style></head><body><div class="container">
<div class="header"><h1>SWARM — Relatório de Segurança</h1>
<p>Alvo: <strong>{html.escape(TARGET)}</strong> | Domínio: {html.escape(DOMAIN)}</p>
<p>Data: {rdate} &nbsp;|&nbsp; Duração: {duration_str} &nbsp;|&nbsp; <strong>CONFIDENCIAL</strong></p></div>
<div class="content">
<h2>1. Sumário Executivo</h2>
<div class="stats">
{f'<div class="stat-card" style="background:#7a0000;border:2px solid #ff4444"><div class="number">{kev_count}</div><div>🔴 KEV</div></div>' if kev_count > 0 else ""}
<div class="stat-card critical"><div class="number">{stats['critical']}</div><div>CRÍTICO</div></div>
<div class="stat-card high"><div class="number">{stats['high']}</div><div>ALTO</div></div>
<div class="stat-card medium"><div class="number">{stats['medium']}</div><div>MÉDIO</div></div>
<div class="stat-card low"><div class="number">{stats['low']}</div><div>BAIXO</div></div>
<div class="stat-card info"><div class="number">{stats['info']}</div><div>INFO</div></div></div>
{f'<div style="background:#7a0000;color:white;padding:14px 18px;border-radius:6px;margin:12px 0;border-left:6px solid #ff4444"><strong style="font-size:14px">🔴 {kev_count} CVE(S) COM EXPLORAÇÃO ATIVA CONFIRMADA — CISA KEV</strong><br><span style="font-size:12px;opacity:.9">Estes CVEs estão no catálogo Known Exploited Vulnerabilities da CISA. Independente do score CVSS, exigem ação imediata: ' + ", ".join(f"<code style=\'background:rgba(255,255,255,.15);padding:1px 4px;border-radius:3px\'>{html.escape(cid)}</code>" for cid in list(kev_matches.keys())[:10]) + (f" e mais {len(kev_matches)-10}" if len(kev_matches)>10 else "") + "</span></div>" if kev_count > 0 else ""}
<div class="info-box">
<p><strong>Índice de Risco (0–100):</strong> {risk} <small style="color:#888;font-size:11px">(metodologia: KEV + EPSS + CVSS + JS)</small></p>
<div class="risk-bar-wrap"><div class="risk-bar"></div></div>
<p><strong>Total de Achados:</strong> {total} &nbsp;|&nbsp; <strong>Status:</strong> <span style="color:{scol};font-weight:bold">{stxt}</span></p>
<p><strong>Duração total do scan:</strong> {duration_str}</p>
<p><strong>Ferramentas:</strong> Nuclei + OWASP ZAP{"+ wafw00f" if WAF_DETECTED or os.path.exists(os.path.join(OUTDIR,"raw","waf.json")) else ""}{"+ Katana" if KATANA_URLS > 0 else ""}{"+ JS/Secrets" if js_analysis else ""}{"+ testssl" if TLS_ISSUES >= 0 and os.path.exists(os.path.join(OUTDIR,"raw","testssl.json")) else ""}{"+ OpenAPI" if OPENAPI_FOUND else ""}</p>
<p><strong>Exploits verificados ativamente:</strong> {CONFIRMED_COUNT} re-executados com resposta capturada</p>
{'<p style="background:#fff3cd;padding:8px 12px;border-radius:4px;margin:8px 0;font-size:13px"><strong style="color:#856404">🛡 WAF: '+html.escape(WAF_NAME)+'</strong> — active scan pode ter falsos negativos.</p>' if WAF_DETECTED and WAF_NAME else ""}
{'<p style="color:#b34e4e;font-size:13px">⚠ <strong>'+str(EMAIL_ISSUES)+' problema(s) de segurança de email</strong> detectado(s).</p>' if EMAIL_ISSUES > 0 else ""}
</div>
<h2>2. Superfície de Ataque</h2>
<table>
<tr><th style="width:220px">Subdomínios descobertos</th><td>{SUB_COUNT}</td></tr>
<tr><th>Subdomínios ativos (HTTP)</th><td>{ACTIVE_COUNT}</td></tr>
<tr><th>Portas abertas</th><td><code>{html.escape(OPEN_PORTS)}</code></td></tr>
{f'<tr><th>URLs (Katana JS crawl)</th><td>{KATANA_URLS} URL(s) descobertas com rendering JS</td></tr>' if KATANA_URLS > 0 else ""}</table>
<h3>Hosts Ativos (httpx)</h3><table><tr><th>Resultado</th></tr>{trows(httpx_lines,"httpx não executado ou sem resultados detectados")}</table>
<h3>Portas Abertas e Serviços (nmap)</h3><table><tr><th>Porta / Serviço</th></tr>{trows(nmap_lines,"nmap não executado ou sem portas abertas")}</table>
<h2>3. Vulnerabilidades Identificadas</h2>{vhtml}

<!-- Comportamento do Scan -->
{scan_behavior_html}

<!-- WAF + Email Security -->
{waf_email_html}

<!-- TLS Section -->
{tls_html}

<!-- Exploit Confirmations -->
{confirm_html}


<!-- JS Analysis -->
{js_html}
{errsec}
{low_table_html}

<!-- Plano de Ação -->
{action_plan_html}
<h2>5. Arquivos de Evidência</h2><div class="info-box"><ul>
<li><code>raw/subdomains.txt</code> — Subdomínios descobertos</li>
<li><code>raw/httpx_results.txt</code> — Hosts HTTP ativos e tecnologias</li>
<li><code>raw/nmap.txt</code> — Scan de portas e serviços</li>
<li><code>raw/nuclei.json</code> — Achados do Nuclei (JSONL bruto)</li>
<li><code>raw/zap_alerts.json</code> — Alertas do OWASP ZAP (JSON bruto)</li>
<li><code>raw/zap_evidencias.xml</code> — Relatório completo do ZAP (XML)</li>
{"<li><code>raw/testssl.json</code> — Análise TLS/SSL (testssl)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","testssl.json")) else ""}
{"<li><code>raw/kev_matches.json</code> — CVEs com exploração ativa confirmada (CISA KEV)</li>" if kev_matches else ""}
{"<li><code>raw/cve_enrichment.json</code> — Dados CVE (CVSS + EPSS) do NVD/FIRST</li>" if cve_enrichment else ""}
{"<li><code>raw/exploit_confirmations.json</code> — Resultados de confirmação ativa de exploits</li>" if confirmations else ""}
{"<li><code>raw/openapi_spec.json</code> — Especificação OpenAPI/Swagger importada</li>" if OPENAPI_FOUND else ""}
{"<li><code>raw/scan_metadata.json</code> — Comportamento e configuração de evasão do scan</li>" if scan_meta else ""}
{"<li><code>raw/waf.json</code> — Detecção de WAF (wafw00f)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","waf.json")) else ""}
{"<li><code>raw/email_security.json</code> — SPF/DMARC/DKIM</li>" if email_security else ""}
{"<li><code>raw/katana_urls.txt</code> — URLs descobertas pelo Katana (JS crawl)</li>" if KATANA_URLS > 0 else ""}
{"<li><code>raw/js_analysis.json</code> — Análise JS/Secrets completa</li>" if js_analysis else ""}
{"<li><code>raw/js_files/</code> — Arquivos JS para análise forense</li>" if js_files_list else ""}
</ul>
<p><strong>Nota:</strong> Todos os achados devem ser validados manualmente antes de reportar ao cliente ou equipe de desenvolvimento.</p></div></div>
<div class="footer"><p><strong>CONFIDENCIAL — USO INTERNO</strong></p>
<p>SWARM — Scanner Automatizado de Segurança</p></div></div></body></html>"""

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

# Abrir relatório apenas em modo single-target (batch abre o consolidado no final)
[ "${SWARM_BATCH:-0}" = "0" ] && \
    [ -n "$DISPLAY" ] && command -v xdg-open &>/dev/null && \
    xdg-open "$OUTDIR/relatorio_swarm.html" 2>/dev/null

exit 0

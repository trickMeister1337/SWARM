#!/bin/bash
# ==============================================================================
# SWARM — Instalador
# ==============================================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

SWARM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SWARM_DIR/install.log"
ERRORS=0
STEPS_OK=0
STEPS_TOTAL=5

> "$LOG_FILE"
log() { echo "$(date '+%H:%M:%S') $*" >> "$LOG_FILE"; }

# ── Funções de output ─────────────────────────────────────────────────────────
step() {
    local n=$1; shift
    echo ""
    echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${CYAN}│  PASSO ${n}/${STEPS_TOTAL}  ${BOLD}$*${NC}${CYAN}  │${NC}"
    echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}
ok()   { echo -e "  ${GREEN}[✓]${NC}  $*"; log "OK: $*"; STEPS_OK=$((STEPS_OK+1)); }
warn() { echo -e "  ${YELLOW}[!]${NC}  $*"; log "WARN: $*"; }
err()  { echo -e "  ${RED}[✗]${NC}  $*"; log "ERR: $*"; ERRORS=$((ERRORS+1)); }
info() { echo -e "  ${BLUE}[…]${NC}  $*"; log "INFO: $*"; }
done_step() { echo ""; echo -e "  ${GREEN}▸ Concluído${NC}"; }

# ── Banner ────────────────────────────────────────────────────────────────────
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
echo -e "  ${BOLD}Instalador de Dependências${NC}"
echo -e "  ${BLUE}Kali Linux · Ubuntu · WSL${NC}"
echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# ── Detectar ambiente ─────────────────────────────────────────────────────────
step 1 "Detectando ambiente"

IS_WSL=0; IS_KALI=0; IS_UBUNTU=0

if grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; then
    IS_WSL=1; ok "WSL detectado"
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    if echo "$ID $ID_LIKE" | grep -qi kali; then
        IS_KALI=1; ok "Kali Linux detectado ($VERSION_ID)"
    elif echo "$ID $ID_LIKE" | grep -qi ubuntu; then
        IS_UBUNTU=1; ok "Ubuntu/Debian detectado ($VERSION_ID)"
    else
        warn "Distribuição: $NAME — continuando com instalação padrão"
    fi
fi

CHROMIUM_PKG="chromium"
TESTSSL_PKG="testssl"
if [ "$IS_UBUNTU" -eq 1 ] || [ "$IS_WSL" -eq 1 ]; then
    CHROMIUM_PKG="chromium-browser"
    apt-cache show testssl &>/dev/null 2>&1 || TESTSSL_PKG="testssl.sh"
fi

if ! command -v apt-get &>/dev/null; then
    err "apt-get não encontrado — este instalador requer Debian/Ubuntu/Kali"
    exit 1
fi

[ "$EUID" -eq 0 ] && SUDO="" || SUDO="sudo"
done_step

# ── Pacotes do sistema ────────────────────────────────────────────────────────
step 2 "Instalando pacotes do sistema"

info "Atualizando repositórios..."
$SUDO apt-get update -qq >> "$LOG_FILE" 2>&1 && ok "Repositórios atualizados" || warn "Falha ao atualizar — continuando"

APT_PACKAGES=(curl python3 python3-pip jq nmap git golang-go)
info "Instalando pacotes base..."
$SUDO apt-get install -y -qq "${APT_PACKAGES[@]}" >> "$LOG_FILE" 2>&1

# Pacotes opcionais — instala um por vez, falhas não param o processo
declare -A OPT_PKGS=(
    ["zaproxy"]="OWASP ZAP (scanner dinâmico)"
    ["$TESTSSL_PKG"]="testssl (análise TLS)"
    ["$CHROMIUM_PKG"]="chromium (JS headless para Katana)"
)
for pkg in zaproxy "$TESTSSL_PKG" "$CHROMIUM_PKG"; do
    [ -z "$pkg" ] && continue
    info "Instalando $pkg..."
    if $SUDO apt-get install -y -qq "$pkg" >> "$LOG_FILE" 2>&1; then
        printf "  ${GREEN}[✓]${NC}  %-24s ${GREEN}OK${NC}\n" "$pkg"
    else
        # Tentar snap como fallback para zaproxy e chromium
        if [ "$pkg" = "zaproxy" ] && command -v snap &>/dev/null; then
            info "Tentando snap install zaproxy..."
            $SUDO snap install zaproxy --classic >> "$LOG_FILE" 2>&1 \
                && printf "  ${GREEN}[✓]${NC}  %-24s ${GREEN}OK (snap)${NC}\n" "zaproxy" \
                || printf "  ${YELLOW}[○]${NC}  %-24s ${YELLOW}opcional — instale manualmente: sudo snap install zaproxy --classic${NC}\n" "zaproxy"
        elif [ "$pkg" = "$CHROMIUM_PKG" ] && command -v snap &>/dev/null; then
            info "Tentando snap install chromium..."
            $SUDO snap install chromium >> "$LOG_FILE" 2>&1 \
                && printf "  ${GREEN}[✓]${NC}  %-24s ${GREEN}OK (snap)${NC}\n" "chromium" \
                || printf "  ${YELLOW}[○]${NC}  %-24s ${YELLOW}opcional — Katana rodará sem JS rendering${NC}\n" "chromium"
        else
            printf "  ${YELLOW}[○]${NC}  %-24s ${YELLOW}não disponível neste sistema — opcional${NC}\n" "$pkg"
        fi
    fi
done

for pkg in curl python3 python3-pip jq nmap git golang-go; do
    command -v "$pkg" &>/dev/null \
        && printf "  ${GREEN}[✓]${NC}  %-20s ${GREEN}OK${NC}\n" "$pkg" \
        || { printf "  ${RED}[✗]${NC}  %-20s ${RED}não instalado${NC}\n" "$pkg"; ERRORS=$((ERRORS+1)); }
done

command -v zaproxy &>/dev/null || command -v zap.sh &>/dev/null \
    && printf "  ${GREEN}[✓]${NC}  %-20s ${GREEN}OK${NC}\n" "zaproxy" \
    || printf "  ${YELLOW}[○]${NC}  %-20s ${YELLOW}opcional${NC}\n" "zaproxy"

command -v testssl &>/dev/null || command -v testssl.sh &>/dev/null \
    && printf "  ${GREEN}[✓]${NC}  %-20s ${GREEN}OK${NC}\n" "testssl" \
    || printf "  ${YELLOW}[○]${NC}  %-20s ${YELLOW}opcional — tente: sudo apt install testssl.sh${NC}\n" "testssl"

command -v chromium &>/dev/null || command -v chromium-browser &>/dev/null \
    && printf "  ${GREEN}[✓]${NC}  %-20s ${GREEN}OK${NC}\n" "chromium" \
    || printf "  ${YELLOW}[○]${NC}  %-20s ${YELLOW}opcional (Katana JS rendering)${NC}\n" "chromium"
done_step

# ── Python ────────────────────────────────────────────────────────────────────
step 3 "Instalando dependências Python"

if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" 2>/dev/null; then
    ok "Python $(python3 --version | cut -d' ' -f2)"
else
    err "Python 3.8+ necessário"
fi

PIP_FLAGS="--break-system-packages --quiet"
for pkg in requests pdfminer.six wafw00f; do
    info "Instalando $pkg..."
    pip3 install "$pkg" $PIP_FLAGS >> "$LOG_FILE" 2>&1 \
        && printf "  ${GREEN}[✓]${NC}  %-20s ${GREEN}OK${NC}\n" "pip: $pkg" \
        || printf "  ${YELLOW}[!]${NC}  %-20s ${YELLOW}falhou — ver install.log${NC}\n" "pip: $pkg"
done
done_step

# ── Ferramentas Go ────────────────────────────────────────────────────────────
step 4 "Instalando ferramentas Go (ProjectDiscovery)"

export PATH="$PATH:$HOME/go/bin:/usr/local/go/bin"

if ! command -v go &>/dev/null; then
    err "Go não encontrado — reinstale golang-go e tente novamente"
else
    ok "Go $(go version | awk '{print $3}')"
    GO_TOOLS=(
        "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "katana:github.com/projectdiscovery/katana/cmd/katana@latest"
    )
    for entry in "${GO_TOOLS[@]}"; do
        tool="${entry%%:*}"; pkg="${entry#*:}"
        info "Instalando $tool..."
        if go install "$pkg" >> "$LOG_FILE" 2>&1; then
            printf "  ${GREEN}[✓]${NC}  %-20s ${GREEN}OK${NC}\n" "$tool"
        else
            printf "  ${RED}[✗]${NC}  %-20s ${RED}falhou — ver install.log${NC}\n" "$tool"
            ERRORS=$((ERRORS+1))
        fi
    done

    if command -v nuclei &>/dev/null; then
        info "Atualizando templates Nuclei..."
        nuclei -update-templates >> "$LOG_FILE" 2>&1 \
            && ok "Templates Nuclei atualizados" \
            || warn "Falha ao atualizar templates"
    fi
fi
done_step

# ── Configurar PATH ───────────────────────────────────────────────────────────
step 5 "Configurando PATH e permissões"

SHELL_RC="$HOME/.bashrc"
[ -n "$ZSH_VERSION" ] && SHELL_RC="$HOME/.zshrc"

add_to_rc() {
    grep -qF "$1" "$SHELL_RC" 2>/dev/null || echo "$1" >> "$SHELL_RC"
}

add_to_rc 'export PATH=$PATH:$HOME/go/bin'
add_to_rc 'export PATH=$PATH:$HOME/.local/bin'
ok "PATH: \$HOME/go/bin e \$HOME/.local/bin adicionados ao $SHELL_RC"

if [ "$IS_WSL" -eq 1 ]; then
    add_to_rc 'export DISPLAY=""'
    add_to_rc 'export JAVA_TOOL_OPTIONS="-Djava.awt.headless=true"'
    ok "WSL: variáveis headless configuradas"
fi

chmod +x "$SWARM_DIR/swarm.sh"         && ok "swarm.sh executável"
[ -f "$SWARM_DIR/swarm_batch.sh" ] && chmod +x "$SWARM_DIR/swarm_batch.sh" && ok "swarm_batch.sh executável"
[ -f "$SWARM_DIR/test_swarm.sh"  ] && chmod +x "$SWARM_DIR/test_swarm.sh"  && ok "test_swarm.sh executável"
done_step

# ── Resultado ─────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [ "$ERRORS" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}✓  Instalação concluída com sucesso!${NC}"
    echo ""
    echo -e "  ${BOLD}Próximos passos:${NC}"
    echo ""
    echo -e "  1.  Recarregar o terminal (ou executar o comando abaixo):"
    echo -e "      ${CYAN}source ~/.bashrc${NC}"
    echo ""
    echo -e "  2.  Validar instalação:"
    echo -e "      ${CYAN}bash test_swarm.sh${NC}"
    echo ""
    echo -e "  3.  Executar o primeiro scan:"
    echo -e "      ${CYAN}bash swarm.sh https://target.com${NC}"
    echo ""
    echo -e "  4.  Scan em múltiplos alvos:"
    echo -e "      ${CYAN}bash swarm_batch.sh targets.txt${NC}"
else
    echo -e "  ${YELLOW}${BOLD}⚠  Instalação concluída com $ERRORS erro(s)${NC}"
    echo ""
    echo -e "  Verifique ${CYAN}install.log${NC} para detalhes dos erros."
    echo -e "  Ferramentas opcionais com erro não impedem o uso — as fases"
    echo -e "  correspondentes serão puladas automaticamente durante o scan."
    echo ""
    echo -e "  Quando resolver os erros, execute novamente: ${CYAN}bash install.sh${NC}"
fi

echo ""
log "Instalação finalizada. Erros: $ERRORS"

#!/bin/bash
# ==============================================================================
# SWARM — Instalador
# Detecta o ambiente e instala todas as dependências necessárias.
# Uso: bash install.sh
# ==============================================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

SWARM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SWARM_DIR/install.log"
ERRORS=0

log()  { echo "$(date '+%H:%M:%S') $*" >> "$LOG_FILE"; }
ok()   { echo -e "${GREEN}[✓]${NC} $*"; log "OK: $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; log "WARN: $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; log "ERR: $*"; ERRORS=$((ERRORS+1)); }
info() { echo -e "${BLUE}[*]${NC} $*"; log "INFO: $*"; }
section() { echo -e "\n${CYAN}${BOLD}══ $* ══${NC}"; }

> "$LOG_FILE"

echo -e "${GREEN}${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           SWARM — Instalador de Dependências                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Detectar ambiente ──────────────────────────────────────────────────────────
section "Detectando ambiente"

IS_WSL=0
IS_KALI=0
IS_UBUNTU=0

if grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; then
    IS_WSL=1
    ok "WSL detectado"
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    if echo "$ID $ID_LIKE" | grep -qi kali; then
        IS_KALI=1
        ok "Kali Linux detectado ($VERSION_ID)"
    elif echo "$ID $ID_LIKE" | grep -qi ubuntu; then
        IS_UBUNTU=1
        ok "Ubuntu/Debian detectado ($VERSION_ID)"
    else
        warn "Distribuição: $NAME — continuando com instalação padrão"
    fi
fi

# Pacote de chromium varia por distro
CHROMIUM_PKG="chromium"
TESTSSL_PKG="testssl"
if [ "$IS_UBUNTU" -eq 1 ] || [ "$IS_WSL" -eq 1 ]; then
    CHROMIUM_PKG="chromium-browser"
    # testssl.sh no Ubuntu
    if ! apt-cache show testssl &>/dev/null 2>&1; then
        TESTSSL_PKG="testssl.sh"
    fi
fi

# ── Verificar pré-requisitos ───────────────────────────────────────────────────
section "Verificando pré-requisitos"

if ! command -v apt-get &>/dev/null; then
    err "apt-get não encontrado — este instalador requer Debian/Ubuntu/Kali"
    exit 1
fi

if [ "$EUID" -eq 0 ]; then
    SUDO=""
    warn "Rodando como root"
else
    SUDO="sudo"
    ok "Rodando como usuário normal (sudo disponível)"
fi

# ── Pacotes do sistema ─────────────────────────────────────────────────────────
section "Instalando pacotes do sistema"

info "Atualizando repositórios..."
$SUDO apt-get update -qq >> "$LOG_FILE" 2>&1 && ok "Repositórios atualizados" || warn "Falha ao atualizar — continuando"

APT_PACKAGES=(
    curl python3 python3-pip jq nmap git
    zaproxy golang-go
    "$TESTSSL_PKG"
    "$CHROMIUM_PKG"
)

info "Instalando: ${APT_PACKAGES[*]}"
$SUDO apt-get install -y -qq "${APT_PACKAGES[@]}" >> "$LOG_FILE" 2>&1

for pkg in curl python3 python3-pip jq nmap git golang-go; do
    command -v "$pkg" &>/dev/null && ok "$pkg" || err "$pkg não instalado"
done

# ZAP pode ser zaproxy ou zap.sh
if command -v zaproxy &>/dev/null || command -v zap.sh &>/dev/null; then
    ok "OWASP ZAP"
else
    warn "OWASP ZAP não encontrado — instale manualmente: sudo apt install zaproxy"
fi

# testssl pode ser testssl ou testssl.sh
if command -v testssl &>/dev/null || command -v testssl.sh &>/dev/null; then
    ok "testssl"
else
    warn "testssl não encontrado — tente: sudo apt install testssl.sh"
fi

# chromium
if command -v chromium &>/dev/null || command -v chromium-browser &>/dev/null; then
    ok "chromium"
else
    warn "chromium não encontrado (opcional para Katana JS rendering)"
fi

# ── Python ─────────────────────────────────────────────────────────────────────
section "Instalando dependências Python"

PIP_FLAGS="--break-system-packages --quiet"
if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" 2>/dev/null; then
    ok "Python $(python3 --version | cut -d' ' -f2)"
else
    err "Python 3.8+ necessário"
fi

for pkg in requests pdfminer.six; do
    info "pip install $pkg"
    pip3 install "$pkg" $PIP_FLAGS >> "$LOG_FILE" 2>&1 && ok "Python: $pkg" || warn "Python: $pkg não instalado"
done

# ── Go e ferramentas ProjectDiscovery ──────────────────────────────────────────
section "Instalando ferramentas Go (ProjectDiscovery)"

# Adicionar go/bin ao PATH desta sessão
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
        tool="${entry%%:*}"
        pkg="${entry#*:}"
        info "Instalando $tool..."
        if go install "$pkg" >> "$LOG_FILE" 2>&1; then
            ok "$tool"
        else
            err "$tool — falha na instalação (ver install.log)"
        fi
    done

    # Atualizar templates Nuclei
    if command -v nuclei &>/dev/null; then
        info "Atualizando templates Nuclei..."
        nuclei -update-templates >> "$LOG_FILE" 2>&1 && ok "Templates Nuclei atualizados" || warn "Falha ao atualizar templates"
    fi
fi

# ── Configurar PATH permanente ────────────────────────────────────────────────
section "Configurando PATH"

SHELL_RC="$HOME/.bashrc"
[ -n "$ZSH_VERSION" ] && SHELL_RC="$HOME/.zshrc"

add_to_rc() {
    local line="$1"
    grep -qF "$line" "$SHELL_RC" 2>/dev/null || echo "$line" >> "$SHELL_RC"
}

add_to_rc 'export PATH=$PATH:$HOME/go/bin'
ok "PATH: \$HOME/go/bin adicionado ao $SHELL_RC"

if [ "$IS_WSL" -eq 1 ]; then
    add_to_rc 'export DISPLAY=""'
    add_to_rc 'export JAVA_TOOL_OPTIONS="-Djava.awt.headless=true"'
    ok "WSL: variáveis headless configuradas"
fi

# ── Permissões ────────────────────────────────────────────────────────────────
section "Configurando permissões"

chmod +x "$SWARM_DIR/swarm.sh" && ok "swarm.sh executável"
[ -f "$SWARM_DIR/test_swarm.sh" ] && chmod +x "$SWARM_DIR/test_swarm.sh" && ok "test_swarm.sh executável"

# ── Verificação final ─────────────────────────────────────────────────────────
section "Verificação final"

echo ""
TOOLS_OK=0; TOOLS_MISSING=0

check_tool() {
    local tool="$1" label="${2:-$1}"
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}[✓]${NC} $label"
        TOOLS_OK=$((TOOLS_OK+1))
    else
        echo -e "  ${YELLOW}[○]${NC} $label (opcional)"
        TOOLS_MISSING=$((TOOLS_MISSING+1))
    fi
}

check_tool curl      "curl (obrigatório)"
check_tool python3   "python3 (obrigatório)"
check_tool subfinder "subfinder"
check_tool httpx     "httpx"
check_tool nmap      "nmap"
check_tool nuclei    "nuclei"
check_tool katana    "katana"
check_tool testssl   "testssl" || check_tool testssl.sh "testssl.sh"
command -v zaproxy &>/dev/null && echo -e "  ${GREEN}[✓]${NC} zaproxy" && TOOLS_OK=$((TOOLS_OK+1)) || \
    echo -e "  ${YELLOW}[○]${NC} zaproxy (opcional)" && TOOLS_MISSING=$((TOOLS_MISSING+1))
command -v chromium &>/dev/null || command -v chromium-browser &>/dev/null && \
    echo -e "  ${GREEN}[✓]${NC} chromium" && TOOLS_OK=$((TOOLS_OK+1)) || \
    echo -e "  ${YELLOW}[○]${NC} chromium (opcional — Katana JS rendering)"

echo ""

# ── Resultado ─────────────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}══ RESULTADO ══${NC}"
echo ""

if [ "$ERRORS" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  ✓ Instalação concluída com sucesso!${NC}"
    echo ""
    echo -e "  Para validar: ${CYAN}bash test_swarm.sh${NC}"
    echo -e "  Para escanear: ${CYAN}bash swarm.sh https://target.com${NC}"
    echo ""
    echo -e "  ${YELLOW}Importante: feche e reabra o terminal (ou execute: source ~/.bashrc)${NC}"
    echo -e "  ${YELLOW}para que as ferramentas Go fiquem disponíveis no PATH.${NC}"
else
    echo -e "${YELLOW}${BOLD}  ⚠ Instalação concluída com $ERRORS erro(s)${NC}"
    echo ""
    echo -e "  Verifique ${CYAN}install.log${NC} para detalhes."
    echo -e "  As ferramentas marcadas como opcionais não impedem o uso do SWARM."
    echo -e "  As fases sem ferramentas instaladas são puladas automaticamente."
fi

echo ""
log "Instalação finalizada. Erros: $ERRORS"

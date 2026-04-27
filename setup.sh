#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  SWARM RED — Instalador Universal (Linux / WSL)
# ═══════════════════════════════════════════════════════════════════════════════
#  Instala TODAS as dependências automaticamente. Zero passos manuais.
#  Detecta distro (apt/dnf/pacman/zypper) e WSL automaticamente.
#
#  Uso: bash setup.sh [--force]
#
#  O flag --force reinstala tudo mesmo se já presente.
#  Log completo: ~/.swarm-red-install.log
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

readonly LOGFILE="$HOME/.swarm-red-install.log"
readonly VENV_DIR="$HOME/.swarm-red-venv"
FORCE=false
[[ "${1:-}" == "--force" ]] && FORCE=true

# Cores
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'
BLD='\033[1m'; DIM='\033[2m'; RST='\033[0m'

# Contadores
INSTALLED=0; SKIPPED=0; FAILED=0; TOTAL=0

# ═══════════════════════════════════════════════════════════════════════════════
#  LOGGING
# ═══════════════════════════════════════════════════════════════════════════════
exec > >(tee -a "$LOGFILE") 2>&1
echo "════════════════════════════════════════" >> "$LOGFILE"
echo "SWARM RED Installer — $(date)" >> "$LOGFILE"
echo "════════════════════════════════════════" >> "$LOGFILE"

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
    echo -e "  ${YLW}Instalador Universal — Linux / WSL${RST}"
    echo -e "  ${DIM}Log: $LOGFILE${RST}"
    echo ""
}

info()  { echo -e "  ${GRN}[✓]${RST} $*"; }
warn()  { echo -e "  ${YLW}[!]${RST} $*"; }
fail()  { echo -e "  ${RED}[✗]${RST} $*"; }
step()  { echo -e "\n${CYN}─── $* ───${RST}"; }
has()   { command -v "$1" &>/dev/null; }

track_result() {
    local name="$1" result="$2"
    ((TOTAL++))
    if [ "$result" = "ok" ]; then
        info "$name instalado com sucesso"
        ((INSTALLED++))
    elif [ "$result" = "skip" ]; then
        info "$name já instalado"
        ((SKIPPED++))
    else
        fail "$name — falha na instalação"
        ((FAILED++))
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  DETECÇÃO DE SISTEMA
# ═══════════════════════════════════════════════════════════════════════════════
DISTRO_ID="unknown"; DISTRO_NAME="Unknown"; PKG_FAMILY="unknown"; IS_WSL=false

detect_system() {
    step "Detectando sistema"

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_NAME="${PRETTY_NAME:-unknown}"
    elif has lsb_release; then
        DISTRO_ID=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        DISTRO_NAME=$(lsb_release -sd)
    fi

    case "$DISTRO_ID" in
        ubuntu|debian|kali|linuxmint|pop|parrot|raspbian|zorin|elementary)
            PKG_FAMILY="apt" ;;
        fedora|rhel|centos|rocky|alma|ol|amzn)
            PKG_FAMILY="dnf"
            has dnf || PKG_FAMILY="yum"
            ;;
        arch|manjaro|endeavouros|garuda)
            PKG_FAMILY="pacman" ;;
        opensuse*|sles)
            PKG_FAMILY="zypper" ;;
        *)
            has apt-get && PKG_FAMILY="apt"
            has dnf     && PKG_FAMILY="dnf"
            has yum     && PKG_FAMILY="yum"
            has pacman  && PKG_FAMILY="pacman"
            has zypper  && PKG_FAMILY="zypper"
            ;;
    esac

    grep -qiE "(microsoft|wsl)" /proc/version 2>/dev/null && IS_WSL=true

    info "Distro:  $DISTRO_NAME ($DISTRO_ID)"
    info "Pacotes: $PKG_FAMILY"
    info "WSL:     $IS_WSL"

    if [ "$PKG_FAMILY" = "unknown" ]; then
        fail "Gerenciador de pacotes não detectado."
        fail "Instale manualmente: python3, curl, git, nmap, jq, nikto, hydra"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  INSTALADORES BASE
# ═══════════════════════════════════════════════════════════════════════════════
pkg_update() {
    step "Atualizando índice de pacotes"
    case "$PKG_FAMILY" in
        apt)    sudo apt-get update -qq 2>/dev/null ;;
        dnf)    sudo dnf check-update -q 2>/dev/null || true ;;
        yum)    sudo yum check-update -q 2>/dev/null || true ;;
        pacman) sudo pacman -Sy --noconfirm 2>/dev/null ;;
        zypper) sudo zypper refresh -q 2>/dev/null ;;
    esac
    info "Índice atualizado"
}

pkg_install() {
    case "$PKG_FAMILY" in
        apt)    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" 2>/dev/null ;;
        dnf)    sudo dnf install -y -q "$@" 2>/dev/null ;;
        yum)    sudo yum install -y -q "$@" 2>/dev/null ;;
        pacman) sudo pacman -S --noconfirm --needed "$@" 2>/dev/null ;;
        zypper) sudo zypper install -y -n "$@" 2>/dev/null ;;
    esac
}

pkg_install_any() {
    local names=("$@")
    for name in "${names[@]}"; do
        pkg_install "$name" 2>/dev/null && return 0
    done
    return 1
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FERRAMENTAS BASE
# ═══════════════════════════════════════════════════════════════════════════════
install_base_tools() {
    step "Ferramentas base"

    local base_pkgs=()
    case "$PKG_FAMILY" in
        apt)     base_pkgs=(git curl jq wget whois dnsutils python3 python3-pip python3-venv build-essential libffi-dev) ;;
        dnf|yum) base_pkgs=(git curl jq wget whois bind-utils python3 python3-pip gcc libffi-devel) ;;
        pacman)  base_pkgs=(git curl jq wget whois bind python python-pip base-devel) ;;
        zypper)  base_pkgs=(git curl jq wget whois bind-utils python3 python3-pip gcc libffi-devel) ;;
    esac

    local missing=()
    for pkg in git curl jq wget python3; do
        if ! has "$pkg" || [ "$FORCE" = true ]; then
            missing+=("$pkg")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        warn "Instalando: ${missing[*]}"
        pkg_install "${base_pkgs[@]}" || true
    fi

    for tool in git curl jq wget python3; do
        has "$tool" && track_result "$tool" "skip" || track_result "$tool" "fail"
    done
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PYTHON VENV
# ═══════════════════════════════════════════════════════════════════════════════
install_python_env() {
    step "Python venv + dependências"

    if [ -f "$VENV_DIR/bin/python3" ] && [ "$FORCE" = false ]; then
        track_result "python-venv" "skip"
    else
        if ! python3 -m venv --help &>/dev/null; then
            case "$PKG_FAMILY" in
                apt) pkg_install python3-venv ;;
                *)   : ;;
            esac
        fi

        rm -rf "$VENV_DIR"
        python3 -m venv "$VENV_DIR"

        if [ -f "$VENV_DIR/bin/python3" ]; then
            track_result "python-venv" "ok"
        else
            track_result "python-venv" "fail"
            return 1
        fi
    fi

    warn "Instalando pacotes Python no venv..."
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip 2>/dev/null
    "$VENV_DIR/bin/pip" install --quiet \
        requests jinja2 python-docx pdfminer.six colorama 2>/dev/null

    if "$VENV_DIR/bin/python3" -c "import requests, jinja2, docx, pdfminer, colorama" 2>/dev/null; then
        info "Pacotes Python: requests, jinja2, python-docx, pdfminer, colorama"
    else
        fail "Alguns pacotes Python não instalaram corretamente"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  NMAP
# ═══════════════════════════════════════════════════════════════════════════════
install_nmap() {
    step "Nmap"
    if has nmap && [ "$FORCE" = false ]; then
        track_result "nmap" "skip"; return 0
    fi
    pkg_install nmap
    has nmap && track_result "nmap" "ok" || track_result "nmap" "fail"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  SQLMAP (3 tentativas: pacote → git clone → pip)
# ═══════════════════════════════════════════════════════════════════════════════
install_sqlmap() {
    step "sqlmap"
    if has sqlmap && [ "$FORCE" = false ]; then
        track_result "sqlmap" "skip"; return 0
    fi

    # Tentativa 1: pacote do sistema
    pkg_install sqlmap 2>/dev/null

    # Tentativa 2: clone do GitHub
    if ! has sqlmap; then
        warn "Pacote não disponível — clonando do GitHub..."
        sudo rm -rf /opt/sqlmap 2>/dev/null
        if sudo git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap 2>/dev/null; then
            sudo chmod +x /opt/sqlmap/sqlmap.py
            sudo ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap
        fi
    fi

    # Tentativa 3: pip
    if ! has sqlmap; then
        warn "Clone falhou — tentando via pip..."
        "$VENV_DIR/bin/pip" install sqlmap --quiet 2>/dev/null
        [ -f "$VENV_DIR/bin/sqlmap" ] && sudo ln -sf "$VENV_DIR/bin/sqlmap" /usr/local/bin/sqlmap 2>/dev/null || true
    fi

    has sqlmap && track_result "sqlmap" "ok" || track_result "sqlmap" "fail"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  HYDRA (3 tentativas: pacote → pacote alt → compilar)
# ═══════════════════════════════════════════════════════════════════════════════
install_hydra() {
    step "Hydra"
    if has hydra && [ "$FORCE" = false ]; then
        track_result "hydra" "skip"; return 0
    fi

    # Tentativa 1: pacote
    pkg_install_any hydra thc-hydra 2>/dev/null

    # Tentativa 2: compilar
    if ! has hydra; then
        warn "Pacote não disponível — compilando do source..."
        local build_dir="/tmp/hydra-build-$$"
        (
            set -e
            mkdir -p "$build_dir" && cd "$build_dir"
            case "$PKG_FAMILY" in
                apt)     pkg_install libssl-dev libssh-dev libidn11-dev libpcre3-dev libmysqlclient-dev libpq-dev 2>/dev/null || true ;;
                dnf|yum) pkg_install openssl-devel libssh-devel libidn-devel pcre-devel mysql-devel postgresql-devel 2>/dev/null || true ;;
                pacman)  pkg_install openssl libssh libidn pcre mariadb-libs postgresql-libs 2>/dev/null || true ;;
            esac
            git clone --depth 1 https://github.com/vanhauser-thc/thc-hydra.git .
            ./configure --prefix=/usr/local 2>/dev/null
            make -j"$(nproc)" 2>/dev/null
            sudo make install 2>/dev/null
        ) 2>/dev/null
        rm -rf "$build_dir"
    fi

    has hydra && track_result "hydra" "ok" || track_result "hydra" "fail"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  NIKTO (2 tentativas: pacote → git clone)
# ═══════════════════════════════════════════════════════════════════════════════
install_nikto() {
    step "Nikto"
    if has nikto && [ "$FORCE" = false ]; then
        track_result "nikto" "skip"; return 0
    fi

    # Tentativa 1: pacote
    pkg_install nikto 2>/dev/null

    # Tentativa 2: clone
    if ! has nikto; then
        warn "Pacote não disponível — clonando do GitHub..."
        has perl || pkg_install_any perl perl-base 2>/dev/null || true
        sudo rm -rf /opt/nikto 2>/dev/null
        if sudo git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto 2>/dev/null; then
            if [ -f /opt/nikto/program/nikto.pl ]; then
                sudo chmod +x /opt/nikto/program/nikto.pl
                sudo ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto
            fi
        fi
    fi

    has nikto && track_result "nikto" "ok" || track_result "nikto" "fail"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  SEARCHSPLOIT (3 tentativas: pacote → git clone + config → wrapper API)
# ═══════════════════════════════════════════════════════════════════════════════
install_searchsploit() {
    step "searchsploit (ExploitDB)"
    if has searchsploit && [ "$FORCE" = false ]; then
        track_result "searchsploit" "skip"; return 0
    fi

    # Tentativa 1: pacote do sistema (Kali/Parrot/Debian)
    if [ "$DISTRO_ID" = "kali" ] || [ "$DISTRO_ID" = "parrot" ]; then
        pkg_install exploitdb 2>/dev/null
    else
        pkg_install_any exploitdb exploit-db 2>/dev/null || true
    fi

    # Tentativa 2: clone do repositório oficial + configuração completa
    if ! has searchsploit; then
        warn "Pacote não disponível — clonando ExploitDB do GitLab..."

        local EXPLOITDB_DIR="/opt/exploitdb"
        sudo rm -rf "$EXPLOITDB_DIR" 2>/dev/null

        if sudo git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git "$EXPLOITDB_DIR" 2>/dev/null; then
            sudo chmod +x "$EXPLOITDB_DIR/searchsploit"
            sudo ln -sf "$EXPLOITDB_DIR/searchsploit" /usr/local/bin/searchsploit

            # Configurar .searchsploit_rc
            cat > "$HOME/.searchsploit_rc" << RCEOF
## searchsploit — gerado por SWARM RED setup.sh
package_array=()
package_array+=("exploitdb")
path_array=()
path_array+=("${EXPLOITDB_DIR}")
colour_tag_2="blue"
colour_tag_1="red"
colour_id="cyan"
colour_results="white"
colour_title="green"
colour_default="reset"
RCEOF
            info "Configuração criada: $HOME/.searchsploit_rc"
        fi
    fi

    # Tentativa 3: wrapper Python que busca via ExploitDB web
    if ! has searchsploit; then
        warn "Clone falhou — criando wrapper com busca ExploitDB web..."

        sudo tee /usr/local/bin/searchsploit > /dev/null << 'WRAPPER'
#!/usr/bin/env python3
"""searchsploit wrapper — busca ExploitDB via web (fallback SWARM RED)"""
import sys, json, re, urllib.request, urllib.parse

def search(query):
    encoded = urllib.parse.quote_plus(query)

    # Tentar JSON output via site
    url = f"https://www.exploit-db.com/search?q={encoded}"
    headers = {"User-Agent": "searchsploit-swarmred/1.0", "Accept": "application/json"}

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="ignore")

        # Parsear resultados
        titles = re.findall(
            r'href="/exploits/(\d+)"[^>]*>\s*([^<]+)', html
        )

        if "--json" in sys.argv:
            results = [{"id": eid, "Title": title.strip()} for eid, title in titles[:30]]
            json.dump({"RESULTS_EXPLOIT": results}, sys.stdout, indent=2)
            print()
        elif titles:
            print(f"\n  Exploit DB — {len(titles)} resultado(s) para: {query}\n")
            print(f"  {'EDB-ID':>10}  |  {'Título'}")
            print(f"  {'-'*10}  |  {'-'*55}")
            for eid, title in titles[:30]:
                print(f"  {eid:>10}  |  {title.strip()[:55]}")
            print(f"\n  Detalhes: https://www.exploit-db.com/search?q={encoded}")
        else:
            print(f"  Nenhum exploit encontrado para: {query}")

    except Exception as e:
        if "--json" in sys.argv:
            json.dump({"RESULTS_EXPLOIT": [], "error": str(e)}, sys.stdout)
            print()
        else:
            print(f"  Erro na busca: {e}")
            print(f"  Busque manualmente: https://www.exploit-db.com/search?q={encoded}")

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print("Uso: searchsploit <termo> [--json]")
        sys.exit(1)
    search(" ".join(args))
WRAPPER
        sudo chmod +x /usr/local/bin/searchsploit
        info "Wrapper searchsploit criado em /usr/local/bin/searchsploit"
    fi

    has searchsploit && track_result "searchsploit" "ok" || track_result "searchsploit" "fail"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  POSTGRESQL (dependência Metasploit DB)
# ═══════════════════════════════════════════════════════════════════════════════
install_postgresql() {
    step "PostgreSQL (para Metasploit DB)"
    if has psql && [ "$FORCE" = false ]; then
        track_result "postgresql" "skip"
    else
        case "$PKG_FAMILY" in
            apt)     pkg_install postgresql postgresql-client 2>/dev/null ;;
            dnf|yum) pkg_install postgresql-server postgresql 2>/dev/null ;;
            pacman)  pkg_install postgresql 2>/dev/null ;;
            zypper)  pkg_install postgresql postgresql-server 2>/dev/null ;;
        esac
        has psql && track_result "postgresql" "ok" || track_result "postgresql" "fail"
    fi

    # Garantir que está rodando
    if has psql; then
        if [ "$IS_WSL" = true ]; then
            sudo service postgresql start 2>/dev/null \
                || sudo /etc/init.d/postgresql start 2>/dev/null \
                || true
        else
            sudo systemctl enable postgresql 2>/dev/null || true
            sudo systemctl start postgresql 2>/dev/null \
                || sudo service postgresql start 2>/dev/null \
                || true
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  METASPLOIT (3 tentativas: pacote → Rapid7 installer → snap)
# ═══════════════════════════════════════════════════════════════════════════════
install_metasploit() {
    step "Metasploit Framework"
    if has msfconsole && [ "$FORCE" = false ]; then
        track_result "metasploit" "skip"; return 0
    fi

    # Tentativa 1: pacote (Kali/Parrot)
    if [ "$DISTRO_ID" = "kali" ] || [ "$DISTRO_ID" = "parrot" ]; then
        pkg_install metasploit-framework 2>/dev/null
    fi

    # Tentativa 2: instalador oficial Rapid7
    if ! has msfconsole; then
        warn "Instalando via script oficial Rapid7..."
        local installer="/tmp/msfinstall_$$"
        if curl -fsSL -o "$installer" \
            "https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb" 2>/dev/null; then
            chmod 755 "$installer"
            sudo "$installer" 2>/dev/null || true
            rm -f "$installer"
        fi

        # Adicionar ao PATH se instalou em /opt
        if [ -f /opt/metasploit-framework/bin/msfconsole ]; then
            export PATH="/opt/metasploit-framework/bin:$PATH"
        fi
    fi

    # Tentativa 3: snap
    if ! has msfconsole && has snap; then
        warn "Tentando via snap..."
        sudo snap install metasploit-framework 2>/dev/null || true
    fi

    if has msfconsole; then
        track_result "metasploit" "ok"
        # Inicializar DB
        if has msfdb; then
            warn "Inicializando banco do Metasploit..."
            if [ "$IS_WSL" = true ]; then
                # WSL precisa que PostgreSQL esteja rodando
                if has pg_isready && ! pg_isready -q 2>/dev/null; then
                    sudo service postgresql start 2>/dev/null || true
                    sleep 2
                fi
            fi
            sudo msfdb init 2>/dev/null || true
            info "Banco do Metasploit inicializado"
        fi
    else
        track_result "metasploit" "fail"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PATH + WSL CONFIG
# ═══════════════════════════════════════════════════════════════════════════════
configure_path() {
    step "Configurando PATH"
    local extra_paths=(
        "/opt/metasploit-framework/bin"
        "/opt/exploitdb"
        "$HOME/go/bin"
        "$HOME/.local/bin"
        "/usr/local/bin"
    )

    local shell_rc="$HOME/.bashrc"
    [ -f "$HOME/.zshrc" ] && shell_rc="$HOME/.zshrc"

    local added=0
    for p in "${extra_paths[@]}"; do
        if [ -d "$p" ] && ! grep -qF "$p" "$shell_rc" 2>/dev/null; then
            echo "export PATH=\"$p:\$PATH\"" >> "$shell_rc"
            export PATH="$p:$PATH"
            ((added++))
        fi
    done

    [ "$added" -gt 0 ] && info "$added path(s) adicionado(s) em $shell_rc" || info "PATH já configurado"
}

configure_wsl() {
    [ "$IS_WSL" = false ] && return 0
    step "Configuração específica WSL"

    local shell_rc="$HOME/.bashrc"
    [ -f "$HOME/.zshrc" ] && shell_rc="$HOME/.zshrc"

    if ! grep -q "JAVA_TOOL_OPTIONS" "$shell_rc" 2>/dev/null; then
        cat >> "$shell_rc" << 'ENVEOF'

# SWARM RED — Headless config para WSL
export JAVA_TOOL_OPTIONS="-Djava.awt.headless=true"
ENVEOF
        info "Variáveis headless configuradas"
    fi

    if [ -f /run/systemd/system ]; then
        info "systemd ativo no WSL"
    else
        warn "systemd não detectado — serviços iniciados manualmente"
        warn "Para habilitar: /etc/wsl.conf → [boot] systemd=true"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  VERIFICAÇÃO FINAL
# ═══════════════════════════════════════════════════════════════════════════════
verify_install() {
    echo ""
    echo -e "${CYN}═══════════════════════════════════════════════════════════════${RST}"
    echo -e "${CYN}  VERIFICAÇÃO FINAL${RST}"
    echo -e "${CYN}═══════════════════════════════════════════════════════════════${RST}"
    echo ""

    local tools=(
        "python3:Obrigatório"
        "curl:Obrigatório"
        "git:Obrigatório"
        "msfconsole:Metasploit"
        "sqlmap:SQL Injection"
        "nmap:Port scanning"
        "hydra:Brute force"
        "nikto:Web scanner"
        "searchsploit:ExploitDB"
        "jq:JSON processing"
    )

    local ok=0 missing=0

    for entry in "${tools[@]}"; do
        local tool="${entry%%:*}"
        local desc="${entry##*:}"

        if has "$tool"; then
            local path ver=""
            path=$(which "$tool" 2>/dev/null)
            case "$tool" in
                python3)    ver="$(python3 --version 2>/dev/null)" ;;
                msfconsole) ver="$(msfconsole --version 2>/dev/null | head -1)" ;;
                nmap)       ver="$(nmap --version 2>/dev/null | head -1 | grep -oP 'Nmap \S+' || true)" ;;
                jq)         ver="$(jq --version 2>/dev/null)" ;;
            esac
            echo -e "  ${GRN}[✓]${RST} ${BLD}$tool${RST}  ${DIM}($desc)${RST}  →  $path ${DIM}$ver${RST}"
            ((ok++))
        else
            echo -e "  ${RED}[✗]${RST} ${BLD}$tool${RST}  ${DIM}($desc)${RST}  →  NÃO ENCONTRADO"
            ((missing++))
        fi
    done

    echo ""
    if [ -f "$VENV_DIR/bin/python3" ]; then
        local pip_count
        pip_count=$("$VENV_DIR/bin/pip" list 2>/dev/null | wc -l)
        echo -e "  ${GRN}[✓]${RST} ${BLD}Python venv${RST}  →  $VENV_DIR  ${DIM}($pip_count pacotes)${RST}"
    else
        echo -e "  ${RED}[✗]${RST} ${BLD}Python venv${RST}  →  NÃO ENCONTRADO"
        ((missing++))
    fi

    echo ""
    echo -e "${CYN}═══════════════════════════════════════════════════════════════${RST}"
    echo -e "  ${GRN}Instalados: $ok${RST}  |  ${RED}Faltando: $missing${RST}  |  Total: $((ok + missing))"
    echo -e "${CYN}═══════════════════════════════════════════════════════════════${RST}"
    echo ""

    if [ "$missing" -eq 0 ]; then
        echo -e "  ${GRN}${BLD}✅ Instalação completa!${RST}"
    elif [ "$missing" -le 2 ]; then
        echo -e "  ${YLW}${BLD}⚠  Quase completo — $missing ferramenta(s) faltando${RST}"
        echo -e "  ${DIM}O SWARM RED funciona sem elas (fases correspondentes desabilitadas)${RST}"
    else
        echo -e "  ${RED}${BLD}❌ $missing ferramentas faltando${RST}"
        echo -e "  ${DIM}Verifique o log: $LOGFILE${RST}"
    fi

    echo ""
    echo -e "  ${DIM}Próximo passo:${RST}  ${BLD}bash swarm_red.sh --help${RST}"
    echo -e "  ${DIM}Testar:${RST}         ${BLD}bash test_swarm_red.sh${RST}"
    echo -e "  ${DIM}Integração:${RST}     ${BLD}bash test_integration.sh${RST}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════
main() {
    banner
    detect_system

    [ "$FORCE" = true ] && warn "Modo --force: reinstalando tudo" && echo ""

    pkg_update
    install_base_tools
    install_python_env
    install_nmap
    install_sqlmap
    install_hydra
    install_nikto
    install_searchsploit
    install_postgresql
    install_metasploit
    configure_path
    configure_wsl
    verify_install
}

main "$@"

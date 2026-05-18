# SWARM RED v7.0

> Motor de pentest blackbox modular — descobre, enumera e explora automaticamente aplicações web e serviços de rede. Funciona standalone ou integrado com output do SWARM.

[![Shell](https://img.shields.io/badge/Shell-Bash-4EAA25?logo=gnu-bash)](https://www.gnu.org/software/bash/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Author](https://img.shields.io/badge/Author-trickMeister1337-red)](https://github.com/trickMeister1337)

---

## ⚠ Aviso Legal

**Uso exclusivo em ambientes com autorização formal documentada (Rules of Engagement).**

O script exige confirmação `EU AUTORIZO` antes de qualquer execução ativa.
Use apenas em sistemas que você possui ou tem permissão explícita por escrito para testar.
Uso não autorizado é crime (Art. 154-A CP / CFAA / Computer Misuse Act).

---

## Visão Geral

O SWARM RED opera em dois modos:

| Modo | Comando | Quando usar |
|---|---|---|
| **Blackbox** | `bash swarm_red.sh -t https://alvo.com` | Pentest standalone a partir de uma URL |
| **Integração SWARM** | `bash swarm_red.sh -d scan_alvo_YYYYMMDD/` | Exploração dirigida por scan SWARM existente |

Em modo Blackbox, o SWARM RED executa todas as 8 fases autonomamente — do recon até o relatório.
Em modo Integração, consome os findings do SWARM (nuclei, nmap, ZAP) e direciona a exploração com maior precisão.

---

## Pipeline de 8 Fases

```
  ┌─────────────────────────────────────────────────────────────┐
  │                   SWARM RED v7.0                            │
  │                                                             │
  │  [1] RECON       subfinder → subdomínios                    │
  │       ↓          httpx    → hosts ativos                    │
  │  [2] SURFACE     nmap     → portas/serviços/versões         │
  │       ↓                                                     │
  │  [3] CRAWL       katana   → endpoints + JS                  │
  │       ↓          ffuf     → directory fuzzing               │
  │  [4] INGEST      Scorer   → priorização por parâmetros      │
  │       ↓          CVEs     → extração de nuclei/ZAP          │
  │  [5] SQLi        sqlmap   → testes com tamper adaptativo    │
  │       ↓                                                     │
  │  [6] XSS         dalfox   → XSS paralelo por URL            │
  │       ↓                                                     │
  │  [7] BRUTE       hydra    → SSH/FTP/MySQL/RDP/SMB           │
  │       ↓                                                     │
  │  [8] SERVICES    nikto    → web vuln scanner                │
  │       ↓          msfconsole → exploits por CVE              │
  │       ↓          searchsploit → lookup local                │
  │       ↓                                                     │
  │  [REL] RELATÓRIO → HTML Big4-style + MITRE ATT&CK           │
  └─────────────────────────────────────────────────────────────┘
```

### Fase 1 — Recon (somente Blackbox)
Subfinder enumera subdomínios. httpx filtra hosts ativos com detecção de tecnologia e status code. Popula `recon/subdomains.txt` e `data/live_hosts.txt`.

### Fase 2 — Surface
Nmap (`-sV -O --open -T4`) em todos os hosts ativos. Em modo Integração, reutiliza `nmap.txt` existente do SWARM.

### Fase 3 — Crawl (somente Blackbox)
katana com crawling JavaScript (`-jc -kf all -fx`). ffuf com wordlist SecLists ou fallback interno. Consolida todas as URLs em `crawl/all_urls.txt`.

### Fase 4 — Ingestão e Priorização
Scorer inline em Python. URLs pontuadas por: parâmetros sensíveis (`id`, `user`, `token`, `cmd`, `redirect`...) +5, path crítico (`/api`, `/admin`, `/auth`...) +4, múltiplos parâmetros +3, presença de `?` +2, em escopo +1. Arquivos de mídia filtrados.

### Fase 5 — SQL Injection
sqlmap com tamper scripts (`space2comment`, `between`, `charencode`). Confirmação real via parsing de `identified the following injection point`. Salva evidências completas (DBMS, usuário, tabelas, dados dumpados) no CSV.

### Fase 6 — XSS
dalfox em paralelo com workers configuráveis. Output JSON consolidado. Confirma via `--silence --no-color --format json`. Mapeia parâmetro + payload confirmado.

### Fase 7 — Brute Force
Hydra em todos os serviços open (SSH, FTP, MySQL, PostgreSQL, RDP, SMB). Duas rodadas: senhas comuns primeiro, depois rockyou/fasttrack no perfil lab/staging.

### Fase 8 — Services + Relatório
Nikto filtrado por severidade. Metasploit com resource script auto-gerado por CVE. SearchSploit para lookup local. Relatório HTML Big4-style com seções MITRE ATT&CK.

---

## Instalação

### Requisitos de Sistema

- Linux (Ubuntu/Debian/Kali) ou WSL2 (Ubuntu 20.04+)
- bash ≥ 4.4
- Python 3.8+
- Go 1.21+ (para ferramentas ProjectDiscovery)

### Instalação Automática (recomendado)

```bash
git clone https://github.com/trickMeister1337/SWARM-RED.git
cd SWARM-RED
bash setup.sh
```

O `setup.sh` detecta automaticamente sua distribuição Linux e instala todas as dependências:

| Distro | Gerenciador |
|---|---|
| Ubuntu / Debian / Kali | `apt-get` |
| Fedora / RHEL | `dnf` |
| Arch / Manjaro | `pacman` |
| openSUSE | `zypper` |

**O que é instalado:**
- Ferramentas de sistema: `nmap`, `hydra`, `nikto`, `sqlmap`, `curl`, `jq`, `git`, `python3-pip`
- Go (detecta amd64/arm64, baixa binário oficial se não instalado via pkg manager)
- Ferramentas Go: `subfinder`, `httpx`, `katana`, `nuclei`, `ffuf`, `dalfox`, `waybackurls`
- Python: `arjun` (via pip3 com `--break-system-packages` para Ubuntu 22.04+)
- Metasploit Framework (via repositório oficial)
- Wordlist: SecLists em `/opt/SecLists`

### Instalação Manual (dependências individuais)

```bash
# Ferramentas Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/hahwul/dalfox/v2@latest

# Python
pip3 install arjun --break-system-packages

# Adicionar Go ao PATH (inclua no ~/.bashrc ou ~/.zshrc)
export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"
```

### Atualizar ferramentas

```bash
nuclei -update && nuclei -update-templates
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/hahwul/dalfox/v2@latest
```

---

## Uso

### Modo Blackbox (standalone)

```bash
# Básico
bash swarm_red.sh -t https://alvo.com

# Com perfil e autenticação
bash swarm_red.sh -t https://alvo.com -p staging \
    --auth-cookie "session=abc123; csrf=xyz" \
    --auth-header "Authorization: Bearer <token>"

# Escopo explícito (múltiplos domínios)
bash swarm_red.sh -t https://alvo.com \
    --scope api.alvo.com \
    --scope app.alvo.com

# Escopo via arquivo
bash swarm_red.sh -t https://alvo.com --scope-file escopo.txt

# Apenas fases específicas
bash swarm_red.sh -t https://alvo.com --only sqli,xss

# Pular fases
bash swarm_red.sh -t https://alvo.com --skip brute,services

# Simular sem executar (dry-run)
bash swarm_red.sh -t https://alvo.com --dry-run

# Retomar após interrupção
bash swarm_red.sh -t https://alvo.com --resume --output-dir swarm_red_alvo_20260514_120000

# Output em diretório customizado
bash swarm_red.sh -t https://alvo.com --output-dir /mnt/pentest/alvo
```

### Modo Integração SWARM

```bash
# Após um scan SWARM
bash swarm_red.sh -d scan_alvo.com_20260514_120000

# Com perfil de produção
bash swarm_red.sh -d scan_alvo.com_20260514_120000 -p production

# Sem Metasploit
bash swarm_red.sh -d scan_alvo.com_20260514_120000 --no-msf

# LHOST customizado para payloads Metasploit
bash swarm_red.sh -d scan_alvo.com_20260514_120000 --lhost 10.10.10.5 --lport 9001
```

### Referência completa de opções

```
SWARM RED v7.0 — Blackbox Pentest Engine

MODOS:
  bash swarm_red.sh -t https://target.com [-p profile]  # Blackbox
  bash swarm_red.sh -d scan_dir           [-p profile]  # Integração SWARM

OPÇÕES:
  -t, --target URL          URL alvo (modo blackbox)
  -d, --dir SCAN_DIR        Diretório de scan SWARM (modo integração)
  -p, --profile PROFILE     lab | staging | production  (padrão: lab)
  --scope DOMAIN            Domínio em escopo (pode repetir)
  --scope-file FILE         Arquivo com domínios/IPs em escopo (um por linha)
  --auth-cookie COOKIE      Cookie de autenticação ("session=abc123")
  --auth-header HEADER      Header de auth ("Authorization: Bearer token")
  --skip FASES              Fases a pular (vírgula): recon,surface,crawl,sqli,xss,brute,services
  --only FASES              Executar apenas estas fases (vírgula)
  --dry-run                 Simular sem executar ferramentas
  --resume                  Retomar do último checkpoint
  --no-msf                  Desabilitar Metasploit
  --lhost IP                IP para payloads Metasploit (padrão: auto-detect)
  --lport PORT              Porta Metasploit (padrão: 4444)
  --threads N               Override de threads por fase
  --output-dir DIR          Diretório de saída customizado
```

---

## Perfis de Execução

Configurados em `lib/profiles.conf`. Selecione com `-p <perfil>`.

| Parâmetro | lab | staging | production |
|---|---|---|---|
| sqlmap level | 5 | 3 | 1 |
| sqlmap risk | 3 | 2 | 1 |
| sqlmap threads | 10 | 5 | 1 |
| sqlmap dump | ✅ | ✅ | ❌ |
| MSF payload | reverse_tcp | reverse_tcp | NONE |
| Brute force | ✅ | ✅ | ❌ |
| Nikto | ✅ | ✅ | ❌ |
| XSS workers | 5 | 3 | 1 |
| Recon threads | 100 | 50 | 20 |
| Crawl depth | 5 | 3 | 2 |
| Max exploits | 999 | 50 | 10 |

**lab** — Ambiente descartável, sem restrições. Use em VMs isoladas ou labs de treinamento.

**staging** — Homologação/pré-produção. Agressividade alta mas com limites razoáveis.

**production** — Janela de manutenção aprovada. Impacto mínimo, apenas confirmação de vulnerabilidades críticas. Sem brute force, sem dump de dados.

---

## Estrutura de Output

```
swarm_red_alvo.com_20260514_120000/
├── data/
│   ├── live_hosts.txt          # Hosts ativos (recon)
│   ├── nmap.txt                # Output nmap completo
│   ├── open_services.txt       # Portas abertas (port/proto/service)
│   ├── targets_scored.txt      # URLs priorizadas (score|url)
│   ├── cves_found.txt          # CVEs extraídos do nuclei
│   └── zap_high_crit.txt       # Findings ZAP High/Critical
├── recon/
│   ├── subdomains.txt          # Subdomínios descobertos
│   └── live_hosts_httpx.txt    # httpx output com tech-detect
├── crawl/
│   ├── katana_urls.txt         # URLs do katana
│   ├── ffuf_results.json       # Output raw do ffuf
│   └── all_urls.txt            # URLs consolidadas
├── sqlmap/
│   └── <hash>_output.log       # Log por URL testada
├── xss/
│   ├── xss_confirmed.txt       # XSS confirmados (XSS|HIGH|url|param|payload)
│   └── xss_all_results.json    # Output dalfox consolidado
├── hydra/
│   └── <service>_<port>.log    # Log hydra por serviço
├── nikto/
│   └── nikto_filtered.json     # Findings filtrados por severidade
├── metasploit/
│   ├── swarm_red.rc            # Resource script gerado
│   ├── msf_output.log          # Output bruto msfconsole
│   ├── hosts.csv               # Hosts confirmados
│   ├── services.csv            # Serviços confirmados
│   ├── vulns.csv               # Vulnerabilidades confirmadas
│   └── creds.csv               # Credenciais encontradas
├── searchsploit/
│   └── CVE-XXXX-XXXXX.json     # Lookup por CVE
├── exploits_confirmed.csv       # Todos os findings confirmados
│                                # Formato: TYPE|SEV|TARGET|detail...
├── swarm_red.log                # Log cronológico completo (trilha de auditoria)
├── .swarm_red_state             # Checkpoints de fase (para --resume)
└── relatorio_swarm_red.html     # Relatório HTML Big4-style
```

### Formato do exploits_confirmed.csv

```
SQLI|CRITICAL|https://alvo.com/login?id=1|DBMS=MySQL|Type=UNION|<logfile>
XSS|HIGH|https://alvo.com/search?q=<script>|param=q|payload=<svg/onload=alert(1)>
BRUTE|HIGH|ssh://alvo.com:22|user=admin|pass=admin123
```

---

## Relatório

O relatório HTML gerado (`relatorio_swarm_red.html`) é estruturado no padrão Big4 com:

- **Badge de modo** (BLACKBOX / SWARM) e perfil de execução
- **Sumário executivo** com métricas de cobertura
- **Superfície de ataque** — subdomínios, portas, serviços, tecnologias
- **Narrativa de ataque** — linha do tempo das fases executadas
- **Findings confirmados** — com evidência técnica, CVSS, MITRE ATT&CK
- **Análise de CVEs** — com EPSS e KEV quando disponível
- **Análise ZAP** — findings High/Critical do OWASP ZAP
- **Brute force** — credenciais encontradas por serviço
- **Nikto** — web vulnerabilities filtradas por severidade
- **Recomendações** — por categoria de vulnerabilidade

---

## Arquitetura

```
swarm-red/
├── swarm_red.sh          # Orquestrador principal (thin)
├── setup.sh              # Instalador universal multi-distro
├── test_swarm_red.sh     # Suite de testes (55 testes)
├── lib/
│   ├── recon.sh          # Fase 1: subfinder + httpx
│   ├── crawl.sh          # Fase 3: katana + ffuf
│   ├── sqli.sh           # Fase 5: sqlmap
│   ├── xss.sh            # Fase 6: dalfox
│   ├── brute.sh          # Fase 7: hydra
│   ├── msf.sh            # Fase 8: metasploit
│   ├── web.sh            # Fase 8: nikto
│   ├── evidence.py       # Coleta e consolidação de evidências
│   ├── report_generator.py  # Geração do relatório HTML
│   └── profiles.conf     # Configuração de perfis (arrays bash)
└── LICENSE
```

Cada fase é um módulo independente: pode ser testado isoladamente, substituído ou desabilitado via `--skip`. O orquestrador chama cada módulo com parâmetros explícitos (sem variáveis globais entre módulos).

### Sistema de Checkpoints

Cada fase grava seu estado em `.swarm_red_state`. Com `--resume`, fases já concluídas são puladas automaticamente. Útil quando a execução é interrompida:

```bash
# Scan interrompido na fase XSS
bash swarm_red.sh -t https://alvo.com --resume --output-dir swarm_red_alvo_20260514/
# → recon, surface, crawl, sqli já concluídos são pulados
# → retoma na fase XSS
```

---

## Uso Corporativo

### Multi-alvo sequencial

```bash
# Arquivo targets.txt com um alvo por linha
while IFS= read -r target; do
    [[ -z "$target" || "$target" == "#"* ]] && continue
    echo "EU AUTORIZO" | bash swarm_red.sh -t "$target" -p staging --output-dir "results/$(date +%Y%m%d)/$target"
    sleep 30
done < targets.txt
```

### Integração com CI/CD (dry-run de validação)

```bash
bash swarm_red.sh -t https://staging.app.com --dry-run | grep -E "FAIL|ERROR" && exit 1 || exit 0
```

### Escopo restrito (subdomain em escopo específico)

```bash
cat > escopo.txt << 'EOF'
api.empresa.com
app.empresa.com
admin.empresa.com
EOF

bash swarm_red.sh -t https://empresa.com \
    --scope-file escopo.txt \
    -p production \
    --skip brute
```

---

## Testes

```bash
# Suite completa (55 testes)
bash test_swarm_red.sh

# Verificação de sintaxe individual
bash -n swarm_red.sh && echo OK
bash -n lib/sqli.sh && echo OK

# Teste de dry-run blackbox
echo "EU AUTORIZO" | bash swarm_red.sh -t https://example.com --dry-run

# Teste de dry-run SWARM integration
bash swarm_red.sh -d scan_target_20260514_120000/ --dry-run
```

---

## Dependências

### Obrigatórias

| Ferramenta | Versão | Propósito |
|---|---|---|
| `bash` | ≥ 4.4 | Runtime (arrays associativos) |
| `python3` | ≥ 3.8 | Scoring, evidências, relatório |
| `curl` | qualquer | Verificações HTTP |

### Opcionais (fase desabilitada graciosamente se ausente)

| Ferramenta | Fase | Instalação |
|---|---|---|
| `subfinder` | Recon | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `httpx` | Recon / Surface | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `nmap` | Surface | `apt install nmap` |
| `katana` | Crawl | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `ffuf` | Crawl | `go install github.com/ffuf/ffuf/v2@latest` |
| `sqlmap` | SQLi | `apt install sqlmap` |
| `dalfox` | XSS | `go install github.com/hahwul/dalfox/v2@latest` |
| `hydra` | Brute Force | `apt install hydra` |
| `nikto` | Web Scanner | `apt install nikto` |
| `msfconsole` | Metasploit | `bash setup.sh` (instala via repositório oficial) |
| `searchsploit` | CVE lookup | `apt install exploitdb` |

---

## Licença

MIT — veja [LICENSE](LICENSE).

---

*SWARM RED v7.0 — Para uso exclusivo em atividades de segurança ofensiva autorizadas.*

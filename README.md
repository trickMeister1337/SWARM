# SWARM

> Scanner de segurança web automatizado — pipeline de 8 fases desde a descoberta de subdomínios até análise de secrets em JavaScript, entregando um relatório HTML completo em Português orientado a tech leads.

[![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Python](https://img.shields.io/badge/Language-Python-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-E95420?style=flat-square&logo=linux&logoColor=white)](https://ubuntu.com/)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen?style=flat-square)](test_swarm.sh)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

---

## Arquitetura

![SWARM Architecture](docs/architecture.svg)

---

## O que o SWARM faz

Um comando. Um relatório. Cobertura completa.

```bash
bash swarm.sh https://target.com
```

O SWARM encadeia 10+ ferramentas de segurança em um pipeline automatizado — descoberta de subdomínios, mapeamento de superfície, análise TLS, scan de vulnerabilidades com templates CVE, confirmação ativa de exploits, crawling JavaScript-aware com Katana, análise dinâmica com OWASP ZAP, detecção de secrets em JS, enriquecimento CVE/EPSS — e consolida tudo em um único relatório HTML em Português.

### Para quem é

| Perfil | O que recebe |
|---|---|
| **Analista de segurança** | Evidência completa (request/response brutos, curl commands), CVSS + EPSS, deduplicação, TLS findings |
| **Tech lead** | Impacto em linguagem de negócio, orientação de correção específica por tecnologia, plano de ação em 3 horizontes |
| **Gestor de segurança** | Índice de risco 0–100 ponderado por EPSS, duração do scan, sumário executivo |

---

## Pipeline de 8 Fases

```
FASE 1   Subfinder ────────────────── Subdomínios
FASE 2   httpx + nmap ─────────────── Hosts ativos + portas
FASE 3   testssl ───────────────┐
                  (background)  │ paralelo
FASE 4   Nuclei ────────────────┘
         CVE + misconfig + default-login + exposure
FASE 5   Confirmação ativa (apenas C/A/M)
         re-executa curl de cada achado Nuclei
FASE 6   OWASP ZAP
         Katana JS crawl → ZAP Spider → Active Scan
         OpenAPI/Swagger auto-import
FASE 7   JS / Secrets
         20 padrões de secrets + endpoints + frameworks
FASE 8   Relatório HTML
         PT-BR · self-contained · abre offline
```

---

## Cobertura

### Reconhecimento
- **Enumeração de subdomínios** — subfinder com fallback automático para domínio principal
- **Mapeamento HTTP** — hosts ativos, status codes, tecnologias (httpx)
- **Scan de portas** — 80, 443, 8000, 8080, 8443, 8888, 3000, 9090

### TLS / SSL
- Versões de protocolo (SSLv3, TLS 1.0/1.1/1.2/1.3)
- Cipher suites fracos e configurações inseguras
- Validade de certificado, cadeia de confiança, HSTS
- CVEs conhecidos: Heartbleed, POODLE, BEAST, ROBOT, DROWN

### Scan de Vulnerabilidades (Nuclei)
- **CVE templates** — vulnerabilidades em versões específicas de software
- **Default credentials** — Node-RED, Grafana, Jupyter, Jenkins, e outros
- **Misconfiguration** — configs expostos, debug endpoints, stack traces
- **Exposure** — S3 buckets públicos, repos Git expostos, arquivos de backup
- **Confirmação ativa** — re-executa o curl do Nuclei (só C/A/M) para verificar se ainda é explorável

### Análise Dinâmica (Katana + OWASP ZAP)
- **Katana** — crawl com rendering JavaScript headless via chromium (`-jc -jsl`)
- Injeção das URLs descobertas no contexto ZAP antes do spider
- **OpenAPI/Swagger auto-import** — detecta e importa specs de API antes de escanear
- **Active Scan** — XSS, SQLi, CSRF, bypass de auth, IDOR
- **Deduplicação** — um card por tipo de alerta com lista de todas as URLs afetadas
- **Reclassificação CVSS** — tabela CWE→CVSS sintético com 37 entradas sobreescreve severidade do ZAP
- **Detecção de scan travado** — aborta active scan após 90s em 0% com diagnóstico

### Inteligência CVE
- **NVD** — CVSS v3, descrição oficial por CVE
- **EPSS** — probabilidade de exploração nos próximos 30 dias (FIRST.org)
- **Retry com backoff** — trata rate limiting do NVD (6s → 12s → 24s)
- **Ponderação no risk score** — EPSS alto eleva o índice de risco

### JavaScript & Secrets
- **Descoberta de arquivos JS** — `<script src>`, webpack chunks, imports dinâmicos
- **20 padrões de secrets**: AWS, Google, GitHub, GitLab, OpenAI, Anthropic, JWT, Stripe, Firebase, DB connection strings, chaves privadas, Slack, senhas hardcoded, URLs de rede interna
- **Detecção de frameworks** — React, Angular, Vue.js, jQuery, Next.js com versão
- **Versões vulneráveis** — alerta com CVE para bibliotecas desatualizadas
- **Extração de endpoints** — `fetch()`, `axios`, URLs literais em JS
- **Probing ativo** — testa endpoints extraídos, identifica APIs sem autenticação
- **Comentários sensíveis** — `TODO`/`FIXME`/`password` no código-fonte

### Relatório em PT-BR
- Todos os labels em português: **CRÍTICO / ALTO / MÉDIO / BAIXO / INFO**
- **Linha de impacto** por achado — o que um atacante consegue fazer em linguagem direta
- **Como corrigir** — orientação específica por tecnologia (não boilerplate genérico)
- **Badge de reclassificação** — mostra quando CWE/CVE alterou a severidade original do ZAP
- **Contador de cards únicos** — exibe tipos distintos de vulnerabilidade, não ocorrências brutas
- **Plano de ação** — 3 horizontes: esta semana / próximo sprint / backlog 30 dias
- **Duração total** — no header e sumário executivo

---

## O que o SWARM NÃO cobre

| Lacuna | Motivo | Alternativa |
|---|---|---|
| **Scan autenticado** | ZAP roda sem token de sessão | Configurar ZAP manualmente com Bearer token |
| **SCA de dependências backend** | Sem acesso a `package.json`, `pom.xml` | Snyk, Dependabot, OWASP Dependency Check |
| **Subdomain takeover** | Fora do escopo atual | `nuclei -tags takeover` separado |
| **Ataques de rede** | Foco em aplicação web | Scanner de rede separado |
| **Serviços internos** | Requer acesso à rede | Executar de dentro da rede |

---

## Instalação

```bash
# Clone o repositório
git clone https://github.com/trickMeister1337/swarm.git
cd swarm

# Instalar tudo automaticamente
bash install.sh
```

O instalador detecta o ambiente (Kali, Ubuntu, WSL) e instala todas as dependências.

### Instalação manual — Kali Linux

```bash
# Pacotes do sistema
sudo apt update && sudo apt install -y \
    curl python3 python3-pip jq nmap git \
    zaproxy testssl chromium golang-go

# Python
pip3 install requests pdfminer.six --break-system-packages

# Ferramentas Go (ProjectDiscovery)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
nuclei -update-templates

# PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc
```

### Instalação manual — Ubuntu / WSL

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y \
    curl python3 python3-pip jq nmap git \
    zaproxy testssl chromium-browser golang-go

pip3 install requests pdfminer.six --break-system-packages

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
nuclei -update-templates

echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
echo 'export DISPLAY=""' >> ~/.bashrc
echo 'export JAVA_TOOL_OPTIONS="-Djava.awt.headless=true"' >> ~/.bashrc
source ~/.bashrc
```

> **WSL:** se `testssl` não for encontrado: `sudo apt install testssl.sh`

---

## Uso

```bash
# Validar instalação (142 testes)
bash test_swarm.sh

# Executar scan completo
bash swarm.sh https://target.com
```

### Estrutura de output

```
scan_target.com_20260418_143022/
├── relatorio_swarm.html            ← abrir no browser, funciona offline
└── raw/
    ├── subdomains.txt              ← subfinder
    ├── httpx_results.txt           ← hosts HTTP ativos + tecnologias
    ├── nmap.txt                    ← scan de portas
    ├── testssl.json                ← análise TLS/SSL
    ├── nuclei.json                 ← achados Nuclei (JSONL)
    ├── exploit_confirmations.json  ← confirmações ativas de exploits
    ├── cve_enrichment.json         ← CVSS + EPSS do NVD/FIRST
    ├── katana_urls.txt             ← URLs descobertas pelo Katana (JS crawl)
    ├── zap_alerts.json             ← alertas do OWASP ZAP (JSON)
    ├── zap_evidencias.xml          ← relatório completo ZAP (XML)
    ├── openapi_spec.json           ← spec OpenAPI importada (se encontrada)
    ├── js_urls.txt                 ← arquivos JS descobertos
    ├── js_analysis.json            ← secrets, endpoints, frameworks
    └── js_files/                   ← arquivos JS para análise forense
```

---

## Seções do Relatório

| # | Seção | Conteúdo |
|---|---|---|
| 1 | Sumário Executivo | Índice de risco 0–100, contadores por severidade (cards únicos), duração |
| 2 | Superfície de Ataque | Subdomínios, hosts ativos, portas, URLs Katana |
| 3 | Vulnerabilidades Identificadas | Cards C/A/M com CVE, CVSS, EPSS, impacto, como corrigir |
| 4 | TLS / SSL | Achados testssl com severidade e CVE |
| 5 | Confirmação Ativa | Resultados de re-execução dos exploits Nuclei |
| 6 | JS / Secrets | Secrets detectados (mascarados), frameworks, endpoints expostos |
| 7 | Achados Baixo / Info | Tabela compacta agrupada por tipo |
| 8 | Plano de Action | Esta semana / Próximo sprint / Backlog 30 dias |
| 9 | Arquivos de Evidência | Links para todos os arquivos raw |

---

## Configuração

Edite as variáveis no topo do `swarm.sh`:

```bash
ZAP_PORT=8080
ZAP_HOST="127.0.0.1"
ZAP_SPIDER_TIMEOUT=0    # 0 = sem timeout (aguarda 100%)
ZAP_SCAN_TIMEOUT=0      # 0 = sem timeout (aguarda 100%)
NUCLEI_RATE_LIMIT=50    # req/s
NUCLEI_CONCURRENCY=10   # templates em paralelo
```

| Ambiente | Rate limit recomendado |
|---|---|
| Produção / sensível | 20–30 |
| Staging (padrão) | 50 |
| Lab interno | 100–150 |

---

## Referência de Ferramentas

| Ferramenta | Fase | Função | Obrigatória |
|---|---|---|---|
| `curl` | Todas | Requisições HTTP, API ZAP | ✅ Sim |
| `python3` | Todas | Análise e relatório | ✅ Sim |
| `subfinder` | 1 | Enumeração de subdomínios | Opcional |
| `httpx` | 2 | Mapeamento HTTP | Opcional |
| `nmap` | 2 | Scan de portas | Opcional |
| `testssl` | 3 | Análise TLS/SSL | Opcional |
| `nuclei` | 4 | Scan de vulnerabilidades | Opcional |
| `katana` | 6 | Crawl JS-aware para SPAs | Opcional |
| `zaproxy` | 6 | Scan dinâmico de aplicação | Opcional |
| `chromium` | 6 | Rendering JS headless para Katana | Opcional |
| `jq` | Misc | Processamento JSON | Opcional |

> SWARM adiciona `~/go/bin` ao PATH automaticamente no startup — não é necessário executar `source ~/.bashrc` antes de rodar.

---

## Katana + ZAP: Crawl de SPAs

SPAs com React, Angular e Vue.js renderizam conteúdo via JavaScript. Um spider tradicional vê apenas `<div id="root"></div>` e para. O SWARM resolve isso com crawl em duas etapas:

1. **Katana** roda primeiro com Chrome headless (`-jc -jsl`), executa JavaScript e segue links gerados dinamicamente até profundidade 5
2. Todas as URLs descobertas são injetadas no contexto do ZAP via `core/action/accessUrl`
3. **ZAP Spider** roda depois do Katana para complementar com descoberta de formulários
4. O Active Scan roda sobre a superfície combinada Katana + Spider

Sem Katana ou chromium instalados, o SWARM usa apenas o ZAP spider com aviso.

---

## Aviso Legal

> **O SWARM destina-se exclusivamente a testes de segurança autorizados.**
>
> O uso contra sistemas que você não possui ou para os quais não tem permissão escrita explícita é ilegal e antiético. Os autores não assumem qualquer responsabilidade pelo uso indevido. Sempre obtenha autorização formal antes de executar avaliações de segurança.

---

## Contribuindo

1. Fork do repositório
2. Criar branch (`git checkout -b feature/sua-feature`)
3. Garantir que todos os 142 testes passam: `bash test_swarm.sh`
4. Abrir pull request com descrição clara

---

## Licença

MIT License — veja [LICENSE](LICENSE) para detalhes.

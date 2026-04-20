# SWARM

![Bash](https://img.shields.io/badge/Shell_Script-121011?style=for-the-badge&logo=gnu-bash&logoColor=white) ![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)

## Visão Geral

O **SWARM** é uma ferramenta robusta de automação para avaliação de segurança (Security Assessment Tool), projetada para auxiliar consultores e equipes de segurança na identificação de vulnerabilidades em aplicações web e infraestruturas associadas. Este script Bash orquestra uma série de ferramentas de código aberto e processos de análise, desde a descoberta de subdomínios até a geração de relatórios detalhados, com suporte a varreduras em alvos únicos ou múltiplos, incluindo execução paralela para otimização de tempo.

O que o SWARM faz
Um comando. Um relatório. Cobertura completa.
bashbash swarm.sh https://target.com
O SWARM encadeia 10+ ferramentas de segurança em um pipeline automatizado — descoberta de subdomínios, mapeamento de superfície, análise TLS, scan de vulnerabilidades com templates CVE, confirmação ativa de exploits, crawling JavaScript-aware com Katana, análise dinâmica com OWASP ZAP, detecção de secrets em JS, enriquecimento CVE/EPSS — e consolida tudo em um único relatório HTML em Português.
Para quem é
PerfilO que recebeAnalista de segurançaEvidência completa (request/response brutos, curl commands), CVSS + EPSS, deduplicação, TLS findingsTech leadImpacto em linguagem de negócio, orientação de correção específica por tecnologia, plano de ação em 3 horizontesGestor de segurançaÍndice de risco 0–100 ponderado por EPSS, duração do scan, sumário executivo

Pipeline de 11 Fases
FASE 1   Subfinder ────────────────── Subdomínios
FASE 2   httpx + nmap ─────────────── Hosts ativos + portas
FASE 3   testssl ───────────────┐
                  (background)  │ paralelo
FASE 4   Nuclei ────────────────┘
         CVE + misconfig + default-login + exposure
         + takeover + cors
FASE 5   Confirmação ativa (apenas C/A/M)
FASE 6   Enriquecimento CVE / EPSS (NVD + FIRST.org)
FASE 7   Detecção de WAF (wafw00f)
FASE 8   Segurança de Email (SPF / DMARC / DKIM)
FASE 9   OWASP ZAP
         Katana JS crawl → Spider → Active Scan
FASE 10  JS / Secrets
         20 padrões + endpoints + frameworks
FASE 11  Relatório HTML
         PT-BR · self-contained · abre offline

Cobertura
Reconhecimento

Enumeração de subdomínios — subfinder com fallback automático para domínio principal
Mapeamento HTTP — hosts ativos, status codes, tecnologias (httpx)
Scan de portas — 80, 443, 8000, 8080, 8443, 8888, 3000, 9090

TLS / SSL

Versões de protocolo (SSLv3, TLS 1.0/1.1/1.2/1.3)
Cipher suites fracos e configurações inseguras
Validade de certificado, cadeia de confiança, HSTS
CVEs conhecidos: Heartbleed, POODLE, BEAST, ROBOT, DROWN

Scan de Vulnerabilidades (Nuclei)

CVE templates — vulnerabilidades em versões específicas de software
Default credentials — Node-RED, Grafana, Jupyter, Jenkins, e outros
Misconfiguration — configs expostos, debug endpoints, stack traces
Exposure — S3 buckets públicos, repos Git expostos, arquivos de backup
Confirmação ativa — re-executa o curl do Nuclei (só C/A/M) para verificar se ainda é explorável

Análise Dinâmica (Katana + OWASP ZAP)

Katana — crawl com rendering JavaScript headless via chromium (-jc -jsl)
Injeção das URLs descobertas no contexto ZAP antes do spider
OpenAPI/Swagger auto-import — detecta e importa specs de API antes de escanear
Active Scan — XSS, SQLi, CSRF, bypass de auth, IDOR
Deduplicação — um card por tipo de alerta com lista de todas as URLs afetadas
Reclassificação CVSS — tabela CWE→CVSS sintético com 37 entradas sobreescreve severidade do ZAP
Detecção de scan travado — aborta active scan após 90s em 0% com diagnóstico

Inteligência CVE

NVD — CVSS v3, descrição oficial por CVE
EPSS — probabilidade de exploração nos próximos 30 dias (FIRST.org)
Retry com backoff — trata rate limiting do NVD (6s → 12s → 24s)
Ponderação no risk score — EPSS alto eleva o índice de risco

JavaScript & Secrets

Descoberta de arquivos JS — <script src>, webpack chunks, imports dinâmicos
20 padrões de secrets: AWS, Google, GitHub, GitLab, OpenAI, Anthropic, JWT, Stripe, Firebase, DB connection strings, chaves privadas, Slack, senhas hardcoded, URLs de rede interna
Detecção de frameworks — React, Angular, Vue.js, jQuery, Next.js com versão
Versões vulneráveis — alerta com CVE para bibliotecas desatualizadas
Extração de endpoints — fetch(), axios, URLs literais em JS
Probing ativo — testa endpoints extraídos, identifica APIs sem autenticação
Comentários sensíveis — TODO/FIXME/password no código-fonte

Relatório em PT-BR

Todos os labels em português: CRÍTICO / ALTO / MÉDIO / BAIXO / INFO
Linha de impacto por achado — o que um atacante consegue fazer em linguagem direta
Como corrigir — orientação específica por tecnologia (não boilerplate genérico)
Badge de reclassificação — mostra quando CWE/CVE alterou a severidade original do ZAP
Contador de cards únicos — exibe tipos distintos de vulnerabilidade, não ocorrências brutas
Plano de ação — 3 horizontes: esta semana / próximo sprint / backlog 30 dias
Duração total — no header e sumário executivo


O que o SWARM NÃO cobre
LacunaMotivoAlternativaScan autenticadoZAP roda sem token de sessãoConfigurar ZAP manualmente com Bearer tokenSCA de dependências backendSem acesso a package.json, pom.xmlSnyk, Dependabot, OWASP Dependency CheckSubdomain takeoverFora do escopo atualnuclei -tags takeover separadoAtaques de redeFoco em aplicação webScanner de rede separadoServiços internosRequer acesso à redeExecutar de dentro da rede

Instalação
bash# Clone o repositório
git clone https://github.com/trickMeister1337/swarm.git
cd swarm

# Instalar tudo automaticamente
bash install.sh
O instalador detecta o ambiente (Kali, Ubuntu, WSL) e instala todas as dependências.
Instalação manual — Kali Linux
bash# Pacotes do sistema
sudo apt update && sudo apt install -y \
    curl python3 python3-pip jq nmap git \
    zaproxy testssl chromium golang-go

# Python
pip3 install requests pdfminer.six wafw00f --break-system-packages

# Ferramentas Go (ProjectDiscovery)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
nuclei -update-templates

# PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc
Instalação manual — Ubuntu / WSL
bashsudo apt update && sudo apt upgrade -y
sudo apt install -y \
    curl python3 python3-pip jq nmap git \
    zaproxy testssl chromium-browser golang-go

pip3 install requests pdfminer.six wafw00f --break-system-packages

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
nuclei -update-templates

echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
echo 'export DISPLAY=""' >> ~/.bashrc
echo 'export JAVA_TOOL_OPTIONS="-Djava.awt.headless=true"' >> ~/.bashrc
source ~/.bashrc

WSL: se testssl não for encontrado: sudo apt install testssl.sh


Uso
bash# Validar instalação (158 testes)
bash test_swarm.sh

# Executar scan completo
bash swarm.sh https://target.com
Estrutura de output
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

Seções do Relatório
#SeçãoConteúdo1Sumário ExecutivoÍndice de risco 0–100, contadores por severidade (cards únicos), duração2Superfície de AtaqueSubdomínios, hosts ativos, portas, URLs Katana3Vulnerabilidades IdentificadasCards C/A/M com CVE, CVSS, EPSS, impacto, como corrigir4TLS / SSLAchados testssl com severidade e CVE5Confirmação AtivaResultados de re-execução dos exploits Nuclei6JS / SecretsSecrets detectados (mascarados), frameworks, endpoints expostos7Achados Baixo / InfoTabela compacta agrupada por tipo8Plano de AçãoEsta semana / Próximo sprint / Backlog 30 dias9Arquivos de EvidênciaLinks para todos os arquivos raw

Configuração
Edite as variáveis no topo do swarm.sh:
bashZAP_PORT=8080
ZAP_HOST="127.0.0.1"
ZAP_SPIDER_TIMEOUT=0    # 0 = sem timeout (aguarda 100%)
ZAP_SCAN_TIMEOUT=0      # 0 = sem timeout (aguarda 100%)
NUCLEI_RATE_LIMIT=50    # req/s
NUCLEI_CONCURRENCY=10   # templates em paralelo
AmbienteRate limit recomendadoProdução / sensível20–30Staging (padrão)50Lab interno100–150

Referência de Ferramentas
FerramentaFaseFunçãoObrigatóriacurlTodasRequisições HTTP, API ZAP✅ Simpython3TodasAnálise e relatório✅ Simsubfinder1Enumeração de subdomíniosOpcionalhttpx2Mapeamento HTTPOpcionalnmap2Scan de portasOpcionaltestssl3Análise TLS/SSLOpcionalnuclei4Scan de vulnerabilidadesOpcionalkatana6Crawl JS-aware para SPAsOpcionalzaproxy6Scan dinâmico de aplicaçãoOpcionalchromium6Rendering JS headless para KatanaOpcionaljqMiscProcessamento JSONOpcional

SWARM adiciona ~/go/bin ao PATH automaticamente no startup — não é necessário executar source ~/.bashrc antes de rodar.


Katana + ZAP: Crawl de SPAs
SPAs com React, Angular e Vue.js renderizam conteúdo via JavaScript. Um spider tradicional vê apenas <div id="root"></div> e para. O SWARM resolve isso com crawl em duas etapas:

Katana roda primeiro com Chrome headless (-jc -jsl), executa JavaScript e segue links gerados dinamicamente até profundidade 5
Todas as URLs descobertas são injetadas no contexto do ZAP via core/action/accessUrl
ZAP Spider roda depois do Katana para complementar com descoberta de formulários
O Active Scan roda sobre a superfície combinada Katana + Spider

Sem Katana ou chromium instalados, o SWARM usa apenas o ZAP spider com aviso.

Aviso Legal

O SWARM destina-se exclusivamente a testes de segurança autorizados.
O uso contra sistemas que você não possui ou para os quais não tem permissão escrita explícita é ilegal e antiético. Os autores não assumem qualquer responsabilidade pelo uso indevido. Sempre obtenha autorização formal antes de executar avaliações de segurança.


Contribuindo

Fork do repositório
Criar branch (git checkout -b feature/sua-feature)
Garantir que todos os 158 testes passam: bash test_swarm.sh
Abrir pull request com descrição clara


Licença
MIT License — veja LICENSE para detalhes.

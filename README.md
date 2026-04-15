🐝 SWARM - Consultant Edition
Ferramenta automatizada de avaliação de segurança para aplicações web

https://img.shields.io/badge/license-MIT-blue.svg
https://img.shields.io/badge/shell-bash-green.svg
https://img.shields.io/badge/tools-nuclei%2520%257C%2520zap%2520%257C%2520nmap%2520%257C%2520testssl-blue

SWARM é um orquestrador de segurança que integra ferramentas populares (Nuclei, OWASP ZAP, Nmap, testssl, httpx, subfinder) em um fluxo automatizado de reconhecimento, varredura de vulnerabilidades, coleta de evidências e geração de relatórios executivos. Projetado para consultores de segurança e equipes red team.

✨ Funcionalidades
Descoberta de subdomínios com subfinder

Mapeamento de superfície com httpx e nmap

Análise TLS/SSL com testssl.sh (rodando em paralelo)

Varredura de vulnerabilidades com nuclei (tags: cve, tech, exposure, misconfig)

Confirmação ativa de exploits – reexecuta os achados do Nuclei com curl original

Enriquecimento CVE/EPSS – consulta NVD e FIRST.org para CVSS e probabilidade de exploração

Scan ativo com OWASP ZAP – spider + active scan, com suporte a OpenAPI/Swagger

Captura de screenshots (Chromium headless / wkhtmltoimage) do alvo e de URLs críticas

Análise de JavaScript – extrai secrets, endpoints, frameworks vulneráveis e comentários sensíveis

Relatório HTML executivo com:

Índice de risco (0–100)

Tabela de vulnerabilidades por severidade (Critical/High/Medium/Low/Info)

Planos de ação por prazo (imediato, sprint, backlog)

Evidências completas (requisições/respostas)

Capturas de tela e confirmações de exploits

📦 Pré‑requisitos
Ferramenta	Obrigatória	Instalação (Ubuntu/Debian)
bash	✅	já instalado
curl	✅	sudo apt install curl
python3	✅	sudo apt install python3
subfinder	❌	go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
httpx	❌	go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
nmap	❌	sudo apt install nmap
nuclei	❌	go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
zaproxy	❌	sudo apt install zaproxy (ou baixe do site oficial)
testssl.sh	❌	sudo apt install testssl.sh
chromium / wkhtmltoimage	❌	sudo apt install chromium ou wkhtmltopdf
Nota: As ferramentas Go (subfinder, httpx, nuclei) exigem go instalado e o diretório $HOME/go/bin no PATH. O script tenta adicionar automaticamente.

🚀 Instalação
bash
# Clone o repositório
git clone https://github.com/seu-usuario/swarm.git
cd swarm

# Dê permissão de execução
chmod +x swarm.sh

# (Opcional) Instale as dependências Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
🎯 Uso
bash
./swarm.sh <URL_ALVO>
Exemplo:

bash
./swarm.sh https://example.com
O script cria um diretório scan_example.com_YYYYMMDD_HHMMSS/ com todos os resultados.

Variáveis de ambiente (customização)
Variável	Padrão	Descrição
ZAP_PORT	8080	Porta do daemon do ZAP
NUCLEI_RATE_LIMIT	50	Requisições por segundo no Nuclei
NUCLEI_CONCURRENCY	10	Concorrência do Nuclei
ZAP_SPIDER_TIMEOUT	0	Timeout (s) para o spider (0 = sem timeout)
ZAP_SCAN_TIMEOUT	0	Timeout (s) para o active scan (0 = sem timeout)
Exemplo de execução com limite maior:

bash
NUCLEI_RATE_LIMIT=100 ./swarm.sh https://target.com
📁 Estrutura de saída
text
scan_dominio_timestamp/
├── relatorio_swarm.html          # Relatório HTML executivo
├── raw/
│   ├── subdomains.txt            # Subdomínios descobertos
│   ├── httpx_results.txt         # Hosts ativos + tech detect
│   ├── nmap.txt                  # Portas abertas e serviços
│   ├── nuclei.json               # Achados brutos do Nuclei (JSONL)
│   ├── zap_alerts.json           # Alertas do ZAP
│   ├── zap_evidencias.xml        # Relatório XML do ZAP
│   ├── testssl.json              # Resultados do testssl
│   ├── cve_enrichment.json       # Dados NVD/EPSS para CVEs encontrados
│   ├── exploit_confirmations.json # Confirmação ativa de exploits
│   ├── openapi_spec.json         # Spec OpenAPI/Swagger (se encontrada)
│   ├── js_analysis.json          # Secrets, endpoints, frameworks
│   ├── js_files/                 # Arquivos JS baixados (hash.md5.js)
│   └── screenshots/              # PNGs de evidência
⚙️ Fluxo de trabalho (9 fases)
Descoberta de subdomínios – subfinder

Mapeamento de superfície – httpx + nmap

Análise TLS (testssl) – roda em paralelo com a fase 4

Varredura Nuclei – tags cve,tech,exposure,default-login,misconfig

Confirmação ativa de exploits – reexecuta curl de cada achado Nuclei

Enriquecimento CVE/EPSS – API NVD e FIRST.org

OWASP ZAP – spider, active scan, importação OpenAPI

Screenshots – alvo principal + URLs críticas

Análise JavaScript – extração de secrets, endpoints, frameworks

Geração do relatório HTML – incluindo plano de ação e evidências

O ZAP é iniciado automaticamente em modo daemon e finalizado ao término do script (a menos que já estivesse em execução).

🛡️ Aviso legal
ATENÇÃO: Esta ferramenta deve ser utilizada APENAS em ambientes autorizados (aplicações de sua propriedade, com permissão por escrito do proprietário, ou em laboratórios de estudo). O uso não autorizado é ilegal e pode violar leis de proteção de dados, invasão de sistemas e direitos de propriedade intelectual. O autor não se responsabiliza por mau uso.

🤝 Contribuição
Pull requests são bem‑vindos! Para mudanças maiores, abra uma issue primeiro para discutir o que você gostaria de modificar.

Fork o projeto

Crie sua branch (git checkout -b feature/nova-feature)

Commit suas mudanças (git commit -m 'Adiciona nova feature')

Push para a branch (git push origin feature/nova-feature)

Abra um Pull Request

📄 Licença
Distribuído sob a licença MIT. Veja LICENSE para mais informações.

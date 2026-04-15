# 🐝 SWARM - Security Workflow and Risk Management

!\[License](https://img.shields.io/badge/license-MIT-blue.svg)
!\[Bash](https://img.shields.io/badge/language-Bash-4EAA25.svg)
!\[Security](https://img.shields.io/badge/focus-Security%20Assessment-red.svg)

O **SWARM** é uma ferramenta de automação de segurança ofensiva projetada para consultores e profissionais de segurança cibernética. Ele orquestra uma série de ferramentas líderes de mercado para realizar desde a descoberta de subdomínios até a análise profunda de vulnerabilidades web e infraestrutura, consolidando tudo em um **relatório HTML profissional e acionável**.

\---

## 🚀 Funcionalidades Principais

O SWARM automatiza um fluxo de trabalho de 9 fases, garantindo uma cobertura abrangente da superfície de ataque:

1. **Descoberta de Subdomínios**: Identificação de ativos usando `subfinder`.
2. **Mapeamento de Superfície**: Detecção de tecnologias e serviços ativos com `httpx`.
3. **Análise TLS/SSL**: Verificação de configurações de criptografia com `testssl`.
4. **Scan de Vulnerabilidades (Nuclei)**: Detecção de CVEs, exposições e configurações incorretas.
5. **Análise de Frontend (JS)**: Extração de segredos (API Keys, Tokens), endpoints e análise de frameworks vulneráveis em arquivos JavaScript.
6. **Dynamic Application Security Testing (DAST)**: Integração completa com o **OWASP ZAP** (Spider e Active Scan).
7. **Confirmação de Exploits**: Re-validação automática de achados para reduzir falsos positivos.
8. **Evidências Visuais**: Capturas de tela automáticas do alvo para documentação.
9. **Relatório Consolidado**: Geração de um dashboard HTML rico com plano de ação priorizado.

\---

## 🛠️ Ferramentas Integradas

O script atua como um orquestrador para as seguintes ferramentas (algumas obrigatórias, outras opcionais):

|Ferramenta|Função|Status|
|-|-|-|
|`curl`|Requisições HTTP e chamadas de API|**Obrigatório**|
|`python3`|Processamento de dados e lógica do relatório|**Obrigatório**|
|`subfinder`|Enumeração de subdomínios|Opcional|
|`httpx`|Sondagem HTTP e detecção de tecnologias|Opcional|
|`nuclei`|Scan de vulnerabilidades baseado em templates|Opcional|
|`zaproxy`|Scan dinâmico (DAST) e Spidering|Opcional|
|`testssl`|Auditoria de segurança TLS/SSL|Opcional|
|`nmap`|Scan de portas e serviços|Opcional|
|`chromium`|Captura de evidências visuais (Screenshots)|Opcional|

\---

## 📋 Pré-requisitos

Certifique-se de ter o ambiente configurado. Para melhores resultados, instale as ferramentas Go e adicione-as ao seu PATH:

```bash
# Exemplo de configuração do PATH para ferramentas Go
export PATH=$PATH:$HOME/go/bin
```

### Instalação Rápida (Ubuntu/Debian)

```bash
sudo apt update \&\& sudo apt install -y curl jq nmap testssl.sh python3-pip chromium-browser
```

\---

## 💻 Como Usar

O uso é extremamente simples. Basta fornecer a URL alvo:

```bash
chmod +x swarm.sh
./swarm.sh https://exemplo.com
```

### O que acontece em seguida?

1. O SWARM criará um diretório exclusivo para o scan: `scan\_dominio\_data\_hora/`.
2. Executará as fases de coleta e análise em paralelo onde possível.
3. Ao final, abrirá (ou indicará) o arquivo `report.html` com todos os resultados.

\---

## 📊 Relatório e Resultados

O diferencial do SWARM é o seu **Relatório Executivo**, que inclui:

* **Dashboard de Severidade**: Visão clara de achados Críticos, Altos, Médios e Baixos.
* **Plano de Ação**: Sugestões de correção divididas por "Ação Imediata", "Próximo Sprint" e "Backlog".
* **Análise de JS**: Tabela de segredos encontrados e frameworks desatualizados.
* **Evidências**: Screenshots e snippets de requisições/respostas que confirmam a vulnerabilidade.

\---

## 🛡️ Aviso Legal

*Esta ferramenta foi desenvolvida apenas para fins educacionais e de testes de segurança autorizados. O uso do SWARM contra alvos sem permissão prévia é ilegal. O desenvolvedor não se responsabiliza pelo uso indevido desta ferramenta.*

\---

<p align="center">Desenvolvido para agilizar o trabalho de consultoria em segurança.</p>


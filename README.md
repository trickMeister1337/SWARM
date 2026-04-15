# 🐝 SWARM - Security Workflow and Risk Management

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Bash](https://img.shields.io/badge/language-Bash-4EAA25.svg)
![Security](https://img.shields.io/badge/focus-Security%20Workflow%20and%20Risk%20Management-red.svg)

O **SWARM** é uma ferramenta de automação de segurança ofensiva projetada para consultores e profissionais de segurança cibernética. Ele orquestra uma série de ferramentas líderes de mercado para realizar desde a descoberta de subdomínios até a análise profunda de vulnerabilidades web e infraestrutura, consolidando tudo em um **relatório HTML profissional e acionável**.

---

## 📥 Como Obter o SWARM

Para começar a usar o SWARM, clone o repositório para sua máquina local:

```bash
git clone https://github.com/trickMeister1337/SWARM.git
cd SWARM
```

---

---

## 🚀 Funcionalidades Principais

O SWARM automatiza um fluxo de trabalho de 9 fases, garantindo uma cobertura abrangente da superfície de ataque:

1.  **Descoberta de Subdomínios**: Identificação de ativos usando `subfinder`.
2.  **Mapeamento de Superfície**: Detecção de tecnologias e serviços ativos com `httpx`.
3.  **Análise TLS/SSL**: Verificação de configurações de criptografia com `testssl`.
4.  **Scan de Vulnerabilidades (Nuclei)**: Detecção de CVEs, exposições e configurações incorretas.
5.  **Análise de Frontend (JS)**: Extração de segredos (API Keys, Tokens), endpoints e análise de frameworks vulneráveis em arquivos JavaScript.
6.  **Dynamic Application Security Testing (DAST)**: Integração completa com o **OWASP ZAP** (Spider e Active Scan).
7.  **Confirmação de Exploits**: Re-validação automática de achados para reduzir falsos positivos.
8.  **Evidências Visuais**: Capturas de tela automáticas do alvo para documentação.
9.  **Relatório Consolidado**: Geração de um dashboard HTML rico com plano de ação priorizado.

---

## 🛠️ Ferramentas Integradas

O script atua como um orquestrador para as seguintes ferramentas (algumas obrigatórias, outras opcionais):

| Ferramenta | Função | Status |
| :--- | :--- | :--- |
| `curl` | Requisições HTTP e chamadas de API | **Obrigatório** |
| `python3` | Processamento de dados e lógica do relatório | **Obrigatório** |
| `subfinder` | Enumeração de subdomínios | Opcional |
| `httpx` | Sondagem HTTP e detecção de tecnologias | Opcional |
| `nuclei` | Scan de vulnerabilidades baseado em templates | Opcional |
| `zaproxy` | Scan dinâmico (DAST) e Spidering | Opcional |
| `testssl` | Auditoria de segurança TLS/SSL | Opcional |
| `nmap` | Scan de portas e serviços | Opcional |
| `chromium` | Captura de evidências visuais (Screenshots) | Opcional |

---

## 📋 Pré-requisitos e Instalação

O SWARM depende de várias ferramentas de segurança de código aberto. Para garantir o funcionamento ideal, é crucial que você tenha as dependências instaladas e configuradas corretamente em seu sistema.

### 1. Instalação do Go (para ferramentas Go-based)

Muitas das ferramentas opcionais são escritas em Go. Se você ainda não tem o Go instalado, siga estas instruções:

```bash
# Baixar a versão mais recente do Go (verifique em golang.org/dl)
wget https://golang.org/dl/go1.22.2.linux-amd64.tar.gz

# Descompactar para /usr/local
sudo tar -C /usr/local -xzf go1.22.2.linux-amd64.tar.gz

# Adicionar Go ao PATH (adicione estas linhas ao seu ~/.bashrc ou ~/.zshrc)
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verificar a instalação
go version
```

### 2. Instalação das Ferramentas do Sistema (Ubuntu/Debian)

As ferramentas obrigatórias e algumas opcionais podem ser instaladas via gerenciador de pacotes:

```bash
sudo apt update
sudo apt install -y curl python3 python3-pip jq nmap testssl.sh chromium-browser
```

### 3. Instalação das Ferramentas Go-based (Opcionais, mas Altamente Recomendadas)

Para instalar `subfinder`, `httpx` e `nuclei`:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

### 4. Instalação do OWASP ZAP (Opcional)

O SWARM pode iniciar e controlar uma instância do OWASP ZAP. Você pode baixá-lo e instalá-lo manualmente ou usar o pacote `zaproxy` se disponível em seu sistema (geralmente em distribuições como Kali Linux).

```bash
# Exemplo de instalação no Kali Linux
sudo apt install zaproxy

# Para outras distribuições, baixe o pacote do site oficial:
# https://www.zaproxy.org/download/
```

---

---

## 💻 Como Usar

Após clonar o repositório e instalar todas as dependências, você pode executar o SWARM fornecendo a URL alvo como argumento:

```bash
# Navegue até o diretório do SWARM
cd SWARM

# Conceda permissão de execução ao script
chmod +x swarm.sh

# Execute o SWARM com a URL do seu alvo
./swarm.sh https://seualvo.com
```

### Parâmetros Opcionais

O script pode aceitar parâmetros adicionais para customizar o scan (verifique o script `swarm.sh` para opções avançadas).

### O que acontece durante a execução?

1.  **Criação de Diretório**: O SWARM criará um diretório exclusivo para cada scan, no formato `scan_dominio_data_hora/`, onde todos os resultados brutos e o relatório final serão armazenados.
2.  **Execução em Fases**: As 9 fases de avaliação de segurança serão executadas sequencialmente, com algumas etapas rodando em paralelo para otimizar o tempo.
3.  **Relatório Final**: Ao término do scan, um arquivo `report.html` será gerado dentro do diretório do scan, consolidando todas as descobertas de forma interativa e visualmente agradável.

---

---

## 📊 Relatório e Resultados

O diferencial do SWARM é o seu **Relatório Executivo**, que inclui:
- **Dashboard de Severidade**: Visão clara de achados Críticos, Altos, Médios e Baixos.
- **Plano de Ação**: Sugestões de correção divididas por "Ação Imediata", "Próximo Sprint" e "Backlog".
- **Análise de JS**: Tabela de segredos encontrados e frameworks desatualizados.
- **Evidências**: Screenshots e snippets de requisições/respostas que confirmam a vulnerabilidade.

---

## 🛡️ Aviso Legal

*Esta ferramenta foi desenvolvida apenas para fins educacionais e de testes de segurança autorizados. O uso do SWARM contra alvos sem permissão prévia é ilegal. O desenvolvedor não se responsabiliza pelo uso indevido desta ferramenta.*

---
<p align="center">Desenvolvido para agilizar o trabalho de consultoria em segurança.</p>

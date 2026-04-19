# SWARM

![Bash](https://img.shields.io/badge/Shell_Script-121011?style=for-the-badge&logo=gnu-bash&logoColor=white) ![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)

## Visão Geral

O **SWARM** é uma ferramenta robusta de automação para avaliação de segurança (Security Assessment Tool), projetada para auxiliar consultores e equipes de segurança na identificação de vulnerabilidades em aplicações web e infraestruturas associadas. Este script Bash orquestra uma série de ferramentas de código aberto e processos de análise, desde a descoberta de subdomínios até a geração de relatórios detalhados, com suporte a varreduras em alvos únicos ou múltiplos, incluindo execução paralela para otimização de tempo.

## Funcionalidades Detalhadas

O SWARM executa uma sequência de 8 fases distintas, cada uma focada em um aspecto específico da avaliação de segurança. A seguir, detalhamos cada fase e as ferramentas empregadas:

### Fase 1: Descoberta de Subdomínios

Esta fase inicial concentra-se em expandir o escopo da avaliação, identificando subdomínios associados ao alvo principal. A descoberta de subdomínios é crucial para encontrar superfícies de ataque adicionais que podem não ser óbvias.

*   **Ferramenta**: `subfinder`

### Fase 2: Mapeamento de Superfície

Após a descoberta de subdomínios, esta fase verifica a acessibilidade dos alvos e realiza um mapeamento inicial de portas e serviços expostos. Isso ajuda a entender a infraestrutura de rede e os pontos de entrada potenciais.

*   **Ferramentas**: `httpx`, `nmap`

### Fase 3: Análise TLS (testssl) — Paralelo com Nuclei

Focada na segurança da camada de transporte, esta fase avalia a configuração TLS/SSL dos servidores web. Verifica a presença de vulnerabilidades conhecidas, cifras fracas e configurações inadequadas que podem comprometer a confidencialidade e integridade da comunicação. Esta fase pode ser executada em paralelo com a Fase 4.

*   **Ferramenta**: `testssl`

### Fase 4: Scan de Vulnerabilidades (Nuclei) — Paralelo com testssl

Utilizando o `Nuclei`, esta fase realiza varreduras ativas e passivas para identificar uma vasta gama de vulnerabilidades e configurações incorretas em aplicações web e serviços. O `Nuclei` é altamente configurável e utiliza templates para detectar problemas específicos. Esta fase pode ser executada em paralelo com a Fase 3.

*   **Ferramenta**: `nuclei`

### Fase 5: Confirmação Ativa de Exploits (Nuclei)

Esta fase aprofunda a análise de vulnerabilidades, utilizando templates específicos do `Nuclei` para tentar confirmar a explorabilidade de certas falhas, minimizando falsos positivos e fornecendo evidências concretas de risco.

*   **Ferramenta**: `nuclei` (com templates de exploit)

### Fase 6: Coleta de Evidências (OWASP ZAP)

O OWASP ZAP (Zed Attack Proxy) é empregado nesta fase para realizar um crawling extensivo da aplicação web, identificar pontos de entrada e coletar evidências de vulnerabilidades através de seus scanners ativo e passivo. O ZAP é uma ferramenta essencial para a detecção de falhas como XSS, SQL Injection, CSRF, entre outras.

*   **Ferramenta**: `zaproxy` (OWASP ZAP)

### Fase 7: Análise de JavaScript & Secrets

Esta fase foca na análise de arquivos JavaScript para identificar endpoints ocultos, segredos expostos (chaves de API, credenciais) e bibliotecas vulneráveis. A análise de código client-side é crucial para descobrir informações sensíveis que podem ser exploradas.

*   **Ferramentas**: `katana`, `trufflehog`, `gitleaks`, `secretfinder`, `subjs`, `linkfinder` (e análise Python customizada)

### Fase 8: Geração de Relatório

A fase final consolida todos os achados das etapas anteriores em um relatório HTML interativo e de fácil compreensão. O relatório inclui um resumo das vulnerabilidades, detalhes técnicos, classificações de severidade (CVSS), impacto prático e recomendações de remediação, facilitando a comunicação dos riscos para diferentes públicos (técnicos e não-técnicos).

*   **Ferramentas**: `python3` (para processamento de dados e geração de HTML)

## Diagrama de Arquitetura

O diagrama a seguir ilustra o fluxo de execução do SWARM, desde a entrada dos alvos até a geração do relatório final, destacando as principais fases e ferramentas envolvidas.

![Diagrama de Arquitetura do SWARM](https://private-us-east-1.manuscdn.com/sessionFile/d3fQmeSKo5DWgkypYuDsVL/sandbox/4VhRdhLA5U2tWZUaFJy4oj-images_1776565159083_na1fn_L2hvbWUvdWJ1bnR1L2FyY2hpdGVjdHVyZV9iaWc0.png?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cHM6Ly9wcml2YXRlLXVzLWVhc3QtMS5tYW51c2Nkbi5jb20vc2Vzc2lvbkZpbGUvZDNmUW1lU0tvNURXZ2t5cFl1RHNWTC9zYW5kYm94LzRWaFJkaExBNVUydFdaVWFGSnk0b2otaW1hZ2VzXzE3NzY1NjUxNTkwODNfbmExZm5fTDJodmJXVXZkV0oxYm5SMUwyRnlZMmhwZEdWamRIVnlaVjlpYVdjMC5wbmciLCJDb25kaXRpb24iOnsiRGF0ZUxlc3NUaGFuIjp7IkFXUzpFcG9jaFRpbWUiOjE3OTg3NjE2MDB9fX1dfQ__&Key-Pair-Id=K2HSFNDJXOU9YS&Signature=d6H2fc0CnqanG9CD0dISEUaa4T8LNAwqqzkc4ymIWYhFMFAzFC697W4rT-bpdHFkWb3Mn3EcS1PndRChEsymSdp7E7gk7MuKqmL04bBwq9S26lCX7Zwc4Qe-eEBpF~acSX5YIElG57S5uHnCn00Lsd-nBOqWS1jOhuGkeC7DUQ2t8vNJw5c2JWUkMtUOS4Xq0WhUl64IF7aAVB5HlqtQmD5QHOsk~KTdZqLLN6OmRsC9rTzeYb2Xc0c2Qlt4A5~-bSyLyhDnslklJLEXU3pxSf2a8bYGN~EtjUvNYoL7rFb3LAvwdEOZJm5DhtNVwvsCR~CgaJu~MvtMrpFESdFdSg__)

## Como Usar

### Instalação

Para começar a usar o SWARM, siga os passos abaixo:

1.  **Clone o repositório** (substitua `trickMeister1337` pelo seu usuário GitHub se for um fork):
    ```bash
    git clone https://github.com/trickMeister1337/SWARM.git
    cd SWARM
    ```

2.  **Torne o script executável**:
    ```bash
    chmod +x swarm.sh
    ```

### Instalação de Dependências

O SWARM depende de várias ferramentas de segurança de código aberto. Algumas são obrigatórias para o funcionamento básico, enquanto outras são opcionais e habilitam fases de análise mais aprofundadas. Recomenda-se instalar todas as ferramentas opcionais para obter a cobertura completa.

#### Ferramentas Obrigatórias

*   **`curl`**: Geralmente pré-instalado na maioria dos sistemas Linux.
*   **`python3`**: Geralmente pré-instalado na maioria dos sistemas Linux.

#### Ferramentas Opcionais (Recomendadas)

Para instalar as ferramentas, você pode usar os gerenciadores de pacotes de sua distribuição ou seguir as instruções de instalação de cada ferramenta. Para ferramentas Go, o método `go install` é o mais comum.

**Exemplo de instalação de ferramentas Go:**

```bash
# Certifique-se de ter o Go instalado e configurado corretamente (GO111MODULE=on)
# Adicione $HOME/go/bin ao seu PATH
export PATH=$PATH:$HOME/go/bin

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

**Outras ferramentas:**

*   **`jq`**: Processador JSON em linha de comando.
    ```bash
    sudo apt install jq # Debian/Ubuntu
    sudo yum install jq # CentOS/RHEL
    brew install jq # macOS
    ```
*   **`nmap`**: Scanner de portas e descoberta de rede.
    ```bash
    sudo apt install nmap
    ```
*   **`zaproxy` (OWASP ZAP)**: Proxy de segurança para testes de aplicações web. Recomenda-se a instalação via Docker ou o pacote oficial.
    *   [Guia de Instalação do ZAP](https://www.zaproxy.org/docs/desktop/start/install/)
*   **`testssl`**: Ferramenta de linha de comando para verificar configurações TLS/SSL.
    ```bash
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git
    # Adicione o diretório testssl.sh ao seu PATH ou chame diretamente
    ```
*   **`trufflehog`**: Para encontrar credenciais e segredos em código.
    ```bash
    go install github.com/trufflesecurity/trufflehog@latest
    ```
*   **`gitleaks`**: Scanner de segredos para repositórios Git.
    ```bash
    go install github.com/zricethezav/gitleaks@latest
    ```
*   **`secretfinder`**: Ferramenta para encontrar segredos em arquivos JavaScript.
    ```bash
    pip3 install secretfinder
    ```
*   **`subjs`**: Para extrair URLs de arquivos JavaScript.
    ```bash
    go install github.com/lc/subjs@latest
    ```
*   **`linkfinder`**: Para encontrar endpoints em arquivos JavaScript.
    ```bash
    git clone https://github.com/GerbenJavado/LinkFinder.git
    cd LinkFinder
    pip3 install -r requirements.txt
    # python3 linkfinder.py -i <arquivo.js> -o <saida.html>
    ```

**Nota**: Ferramentas Go (como `subfinder`, `httpx`, `nuclei`, `katana`, `trufflehog`, `gitleaks`, `subjs`) devem ter seus binários no `$PATH` (ex: `$HOME/go/bin`). Certifique-se de que o diretório `go/bin` esteja no seu `PATH` após a instalação do Go.

### Scan de Alvo Único

Para realizar um scan em uma única URL:

```bash
./swarm.sh https://exemplo.com
```

### Scan de Múltiplos Alvos

Para escanear múltiplos alvos a partir de um arquivo de texto (uma URL por linha):

```bash
./swarm.sh -f targets.txt
```

Onde `targets.txt` é um arquivo com o seguinte formato:

```
# Comentários são ignorados
https://alvo1.com
alvo2.net
https://sub.alvo3.org
```

### Modo Paralelo (para Múltiplos Alvos)

Para executar scans em múltiplos alvos em paralelo (recomendado para ambientes de staging/laboratório devido ao consumo de recursos):

```bash
./swarm.sh -f targets.txt --parallel 3
```

Substitua `3` pelo número desejado de jobs paralelos (máximo de 5).

## Requisitos

O SWARM requer as seguintes ferramentas instaladas e acessíveis no PATH do sistema. Algumas são obrigatórias, outras opcionais e suas fases serão ignoradas se não encontradas.

### Obrigatórias

*   `curl`
*   `python3`

### Opcionais (recomendadas)

*   `jq`
*   `subfinder`
*   `httpx`
*   `nmap`
*   `nuclei`
*   `zaproxy` (OWASP ZAP)
*   `testssl`
*   `katana`
*   `trufflehog`
*   `gitleaks`
*   `secretfinder`
*   `subjs`
*   `linkfinder`

## Demandas Atendidas

O SWARM atende a diversas demandas no contexto de avaliações de segurança e consultoria:

*   **Automação de Varreduras**: Reduz o esforço manual e o tempo necessário para executar múltiplas ferramentas de segurança.
*   **Cobertura Abrangente**: Integra diversas técnicas de descoberta e análise (subdomínios, portas, TLS, vulnerabilidades web, segredos em JS) em um único fluxo.
*   **Relatórios Detalhados**: Gera relatórios claros e acionáveis, com informações técnicas e contexto de impacto para diferentes stakeholders.
*   **Suporte a Múltiplos Alvos**: Facilita a gestão de varreduras em portfólios de aplicações ou grandes infraestruturas.
*   **Otimização de Recursos**: Permite a execução paralela de scans, otimizando o uso de recursos e o tempo total da avaliação.
*   **Flexibilidade**: Utiliza ferramentas de código aberto, permitindo personalização e extensão conforme as necessidades específicas do consultor.
*   **Identificação de Superfície de Ataque**: Ajuda a mapear a superfície de ataque completa de uma organização, incluindo ativos menos conhecidos.

## Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues para bugs ou sugestões, e enviar Pull Requests com melhorias ou novas funcionalidades.

## Licença

Este projeto está licenciado sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

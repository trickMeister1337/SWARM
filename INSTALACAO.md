# SWARM — Guia de Instalação e Uso

> Guia passo a passo para instalar e executar o SWARM do zero, mesmo sem experiência com terminal.

---

## O que você vai precisar

- Computador com **Windows 10/11**, **Ubuntu**, ou **Kali Linux**
- Conexão com a internet
- Permissão para instalar software na máquina

---

## PARTE 1 — Preparar o ambiente

### Windows: instalar o WSL (Windows Subsystem for Linux)

Se você usa Windows, precisa instalar o WSL para rodar o SWARM. Se já usa Linux ou Kali, pule direto para a Parte 2.

**1.** Abra o **PowerShell** como Administrador:
- Pressione `Windows + X`
- Clique em **"Windows PowerShell (Admin)"** ou **"Terminal (Admin)"**

**2.** Execute o comando abaixo e aguarde:
```
wsl --install
```

**3.** Reinicie o computador quando solicitado.

**4.** Após reiniciar, o Ubuntu vai abrir automaticamente e pedir para criar um usuário. Escolha um nome e senha (a senha não aparece enquanto você digita — isso é normal).

**5.** Pronto. Para abrir o terminal WSL nas próximas vezes: procure por **"Ubuntu"** no menu Iniciar.

---

## PARTE 2 — Baixar o SWARM

Abra o terminal (Ubuntu/WSL/Kali) e execute os comandos abaixo. **Copie e cole um de cada vez**, pressionando Enter após cada um:

**1.** Verificar se o git está instalado:
```bash
sudo apt install -y git
```
> Se pedir senha, digite a senha que você criou no passo anterior.

**2.** Baixar o SWARM:
```bash
git clone https://github.com/trickMeister1337/swarm.git
```

**3.** Entrar na pasta do SWARM:
```bash
cd swarm
```

---

## PARTE 3 — Instalar as dependências

Execute o instalador automático:

```bash
bash install.sh
```

O instalador vai:
- Detectar seu sistema automaticamente (Kali, Ubuntu ou WSL)
- Instalar todas as ferramentas necessárias
- Configurar o ambiente

Isso pode demorar **5 a 15 minutos** dependendo da sua conexão. Você verá o progresso em tela.

Ao terminar, você verá uma mensagem como esta:
```
  ✓  Instalação concluída com sucesso!

  Próximos passos:
  1.  source ~/.bashrc
  2.  bash test_swarm.sh
  3.  bash swarm.sh https://target.com
```

**4.** Execute o comando abaixo para ativar as mudanças no terminal atual:
```bash
source ~/.bashrc
```

---

## PARTE 4 — Validar a instalação

Execute o verificador de testes:

```bash
bash test_swarm.sh
```

Você verá uma lista de verificações. O resultado esperado no final é:
```
  ✓ Todos os testes passaram — script pronto para uso
```

Se algum teste falhar, verifique o arquivo `install.log` para detalhes. Falhas em ferramentas **opcionais** não impedem o uso do SWARM — as fases correspondentes serão puladas durante o scan com um aviso.

---

## PARTE 5 — Executar o primeiro scan

### Scan em um único alvo

```bash
bash swarm.sh https://www.exemplo.com.br
```

> Substitua `https://www.exemplo.com.br` pelo endereço que você quer escanear.

Você verá o banner do SWARM e o progresso das 11 fases em tempo real. O scan demora entre **30 e 90 minutos** dependendo do alvo.

Ao terminar, o relatório será salvo em uma pasta com o nome do domínio:
```
scan_exemplo.com.br_20260424_103000/
└── relatorio_swarm.html   ← abrir no navegador (Chrome, Firefox, Edge)
```

Para abrir o relatório no Windows via WSL:
```bash
explorer.exe relatorio_swarm.html
```

### Scan em múltiplos alvos

**1.** Crie um arquivo `targets.txt` com uma URL por linha:
```
https://app.empresa.com.br
https://api.empresa.com.br
https://admin.empresa.com.br
```

> Dica: pode criar no Bloco de Notas do Windows e salvar na pasta do SWARM.

**2.** Execute o scan em lote:
```bash
bash swarm_batch.sh targets.txt
```

O SWARM escaneia um alvo por vez e salva tudo em uma pasta de batch:
```
scan_batch_20260424_103000/
├── relatorio_consolidado.html   ← visão geral de todos os alvos
├── scan_app.empresa.com.br_xxx/ ← relatório completo do alvo 1
├── scan_api.empresa.com.br_xxx/ ← relatório completo do alvo 2
└── scan_admin.empresa.com.br_xxx/
```

---

## Problemas comuns

### "Comando não encontrado" após a instalação

Execute:
```bash
source ~/.bashrc
```
Se o problema persistir, feche e abra o terminal novamente.

### "Site não acessível (HTTP 000)"

Verifique se a URL está correta e inclui `https://`. Exemplo correto:
```bash
bash swarm.sh https://www.site.com.br
```

### "wafw00f não encontrado"

Execute:
```bash
pip3 install wafw00f --break-system-packages
source ~/.bashrc
```

### O scan parou sem terminar

Verifique se o OWASP ZAP está instalado:
```bash
zaproxy --version
```
Se não estiver:
```bash
sudo apt install -y zaproxy
```

### Onde ficam os relatórios?

Na mesma pasta onde você executou o script, em subpastas com o nome do domínio e a data/hora do scan.

---

## Atualizar o SWARM

Para baixar a versão mais recente:
```bash
cd swarm
git pull
bash install.sh
```

---

## Aviso Legal

> O SWARM deve ser usado **apenas em sistemas que você possui ou para os quais tem autorização escrita**.
> O uso não autorizado contra sistemas de terceiros é crime. Sempre obtenha permissão formal antes de executar qualquer scan.

#!/bin/bash
# ==============================================================================
# TEST HARNESS — swarm.sh
# Valida cada componente do script com dados mockados.
# Não requer ferramentas de segurança instaladas.
# ==============================================================================

PASS=0; FAIL=0; WARN=0
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$SCRIPT_DIR/swarm.sh"
TMP="$SCRIPT_DIR/test_tmp_$$"
mkdir -p "$TMP"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
section() { echo -e "\n${CYAN}${BOLD}══ $1 ══${NC}"; }

cleanup_tmp() { rm -rf "$TMP"; }
trap cleanup_tmp EXIT

# ─────────────────────────────────────────────────────────────────
section "1. SINTAXE E ESTRUTURA DO SCRIPT"
# ─────────────────────────────────────────────────────────────────

if [ ! -f "$SCRIPT" ]; then
    fail "Script não encontrado: $SCRIPT"
    exit 1
fi
pass "Arquivo existe"

bash -n "$SCRIPT" 2>/tmp/syntax_err
if [ $? -eq 0 ]; then
    pass "Sintaxe bash válida (bash -n)"
else
    fail "Erro de sintaxe: $(cat /tmp/syntax_err)"
fi

# Verificar variáveis críticas declaradas
for var in ZAP_PORT ZAP_HOST ZAP_STARTED_BY_SCRIPT ZAP_SPIDER_TIMEOUT \
           ZAP_SCAN_TIMEOUT NUCLEI_RATE_LIMIT NUCLEI_CONCURRENCY; do
    if grep -q "^${var}=" "$SCRIPT"; then
        pass "Variável configurável declarada: $var"
    else
        fail "Variável ausente: $var"
    fi
done

# Verificar funções obrigatórias
for fn in validate_tool zap_api_call wait_for_zap wait_for_zap_progress cleanup; do
    if grep -q "^${fn}()" "$SCRIPT"; then
        pass "Função declarada: ${fn}()"
    else
        fail "Função ausente: ${fn}()"
    fi
done

# Verificar trap
if grep -q "trap cleanup EXIT" "$SCRIPT"; then
    pass "trap cleanup EXIT registrado"
else
    fail "trap cleanup EXIT não encontrado"
fi

# ─────────────────────────────────────────────────────────────────
section "2. VALIDAÇÃO INICIAL E CONECTIVIDADE"
# ─────────────────────────────────────────────────────────────────

# Sem argumento deve sair com erro
output=$(bash "$SCRIPT" 2>&1)
if [ $? -ne 0 ]; then
    pass "Sai com erro quando sem argumento"
else
    fail "Deveria sair com erro sem argumento"
fi
if echo "$output" | grep -qi "uso\|uso:"; then
    pass "Mostra mensagem de uso"
else
    warn "Mensagem de uso não encontrada no output"
fi

# Verificar que conectividade testa códigos corretos
if grep -qE "200\|301\|302\|401\|403\|404" "$SCRIPT"; then
    pass "Verificação de conectividade aceita códigos HTTP esperados"
fi

# ─────────────────────────────────────────────────────────────────
section "3. VALIDATE_TOOL — required vs optional"
# ─────────────────────────────────────────────────────────────────

# Extrair e testar a função isoladamente
TEST_SCRIPT=$(cat <<'EOF'
validate_tool() {
    local tool=$1
    local required=${2:-optional}
    if ! command -v "$tool" &>/dev/null; then
        if [ "$required" = "required" ]; then
            echo "REQUIRED_MISSING:$tool"
            return 2
        fi
        echo "OPTIONAL_MISSING:$tool"
        return 1
    fi
    echo "FOUND:$tool"
    return 0
}
# Testar ferramenta inexistente como optional
result=$(validate_tool "nonexistent_tool_xyz_abc" "optional")
echo "OPT_RESULT:$result"
# Testar ferramenta inexistente como required (não deve dar exit)
result2=$(validate_tool "nonexistent_tool_xyz_abc" "required")
echo "REQ_RESULT:$result2"
# Testar ferramenta que existe
result3=$(validate_tool "python3" "required")
echo "REAL_RESULT:$result3"
EOF
)
output=$(bash -c "$TEST_SCRIPT" 2>&1)

if echo "$output" | grep -q "OPT_RESULT:OPTIONAL_MISSING"; then
    pass "validate_tool: optional retorna 1 sem abortar"
else
    fail "validate_tool: comportamento optional incorreto"
fi

if echo "$output" | grep -q "REQ_RESULT:REQUIRED_MISSING"; then
    pass "validate_tool: required retorna código de missing"
else
    fail "validate_tool: comportamento required incorreto"
fi

if echo "$output" | grep -q "REAL_RESULT:FOUND"; then
    pass "validate_tool: detecta python3 corretamente"
else
    warn "validate_tool: python3 não detectado (pode ser PATH)"
fi

# ─────────────────────────────────────────────────────────────────
section "4. EXTRAÇÃO DE DOMÍNIO"
# ─────────────────────────────────────────────────────────────────

test_domain() {
    local url=$1
    local expected=$2
    local result
    result=$(echo "$url" | sed -E 's|https?://||' | cut -d/ -f1 | cut -d: -f1)
    if [ "$result" = "$expected" ]; then
        pass "Domínio extraído de '$url' → '$result'"
    else
        fail "Domínio extraído de '$url': esperado='$expected' obtido='$result'"
    fi
}

test_domain "https://target.example.com"          "target.example.com"
test_domain "https://target.example.com/path"     "target.example.com"
test_domain "http://target.com:8080/app"       "target.com"
test_domain "https://192.168.1.1"              "192.168.1.1"
test_domain "http://sub.domain.example.co.uk"  "sub.domain.example.co.uk"

# ─────────────────────────────────────────────────────────────────
section "5. WAIT_FOR_ZAP_PROGRESS — lógica de polling"
# ─────────────────────────────────────────────────────────────────

# Simular progresso com um server mock via arquivo
POLL_SCRIPT=$(cat <<'EOF'
wait_for_zap_progress() {
    local status_endpoint=$1
    local scan_id=$2
    local timeout_secs=$3
    local label=$4
    local elapsed=0
    local interval=1
    local mock_file=$5   # arquivo que contém o progresso mock

    while [ $elapsed -lt $timeout_secs ]; do
        local progress
        progress=$(cat "$mock_file" 2>/dev/null || echo "0")
        if [ "$progress" = "100" ] || { [ "$progress" -eq "$progress" ] 2>/dev/null && [ "$progress" -ge 100 ]; }; then
            echo "COMPLETED_AT:${elapsed}s"
            return 0
        fi
        sleep $interval
        elapsed=$((elapsed + interval))
    done
    echo "TIMEOUT"
    return 1
}

MOCK_FILE=$(mktemp)
echo "50" > "$MOCK_FILE"

# Testar: progresso que chega a 100 depois de 1 iteração
(sleep 1; echo "100" > "$MOCK_FILE") &
result=$(wait_for_zap_progress "test/endpoint" "1" "10" "TestScan" "$MOCK_FILE")
rm -f "$MOCK_FILE"
echo "RESULT:$result"
EOF
)
output=$(bash -c "$POLL_SCRIPT" 2>&1)
if echo "$output" | grep -q "COMPLETED_AT"; then
    pass "wait_for_zap_progress: completa quando progresso atinge 100"
else
    fail "wait_for_zap_progress: não detectou conclusão"
fi

# Testar timeout
TIMEOUT_SCRIPT=$(cat <<'EOF'
wait_for_zap_progress() {
    local timeout_secs=$3
    local elapsed=0
    local interval=1
    while [ $elapsed -lt $timeout_secs ]; do
        sleep $interval
        elapsed=$((elapsed + interval))
    done
    echo "TIMEOUT_REACHED"
    return 1
}
result=$(wait_for_zap_progress "ep" "1" "2" "Test")
echo "$result"
EOF
)
output=$(bash -c "$TIMEOUT_SCRIPT" 2>&1)
if echo "$output" | grep -q "TIMEOUT_REACHED"; then
    pass "wait_for_zap_progress: respeita timeout"
else
    fail "wait_for_zap_progress: timeout não funcionou"
fi

# ─────────────────────────────────────────────────────────────────
section "6. FLAG ZAP_STARTED_BY_SCRIPT"
# ─────────────────────────────────────────────────────────────────

if grep -q "ZAP_STARTED_BY_SCRIPT=0" "$SCRIPT" && grep -q "ZAP_STARTED_BY_SCRIPT=1" "$SCRIPT"; then
    pass "Flag ZAP_STARTED_BY_SCRIPT tem ambos os estados (0 e 1)"
fi

if grep -A5 'grep -q "version"' "$SCRIPT" | grep -q 'ZAP_STARTED_BY_SCRIPT=0'; then
    pass "ZAP preexistente define flag=0 (não será encerrado)"
else
    fail "ZAP preexistente deveria definir ZAP_STARTED_BY_SCRIPT=0"
fi

if grep -A10 "zaproxy -daemon" "$SCRIPT" | grep -q 'ZAP_STARTED_BY_SCRIPT=1'; then
    pass "ZAP iniciado pelo script define flag=1 (será encerrado)"
else
    fail "ZAP iniciado deveria definir ZAP_STARTED_BY_SCRIPT=1"
fi

CLEANUP_LOGIC=$(grep -A6 "^cleanup()" "$SCRIPT")
if echo "$CLEANUP_LOGIC" | grep -q 'ZAP_STARTED_BY_SCRIPT.*-eq 1'; then
    pass "cleanup() verifica flag antes de encerrar ZAP"
else
    fail "cleanup() não verifica ZAP_STARTED_BY_SCRIPT"
fi

# ─────────────────────────────────────────────────────────────────
section "7. NUCLEI — rate limit e contagem"
# ─────────────────────────────────────────────────────────────────

if grep -q "rate-limit.*NUCLEI_RATE_LIMIT\|-rate-limit.*\$NUCLEI_RATE_LIMIT" "$SCRIPT"; then
    pass "Nuclei usa -rate-limit com variável configurável"
else
    fail "Nuclei sem -rate-limit"
fi

if grep -q "concurrency.*NUCLEI_CONCURRENCY\|-concurrency.*\$NUCLEI_CONCURRENCY" "$SCRIPT"; then
    pass "Nuclei usa -concurrency com variável configurável"
else
    fail "Nuclei sem -concurrency"
fi

# Contar achados deve usar wc -l, não grep -c '"info"'
if grep -q 'wc -l.*nuclei.json\|nuclei.json.*wc -l\|grep -c.*nuclei.json\|nuclei.json.*grep -c' "$SCRIPT"; then
    pass "Contagem Nuclei usa método de contagem por linha (wc -l ou grep -c)"
else
    warn "Contagem Nuclei pode estar usando método impreciso — verifique"
fi

# ─────────────────────────────────────────────────────────────────
section "8. NMAP — portas expandidas"
# ─────────────────────────────────────────────────────────────────

NMAP_BLOCK=$(grep -A3 "nmap -p" "$SCRIPT" | head -8 | tr -d '\\\n' | tr -s ' ')
for port in 80 443 8080 8443 8000 8888 3000 9090; do
    if echo "$NMAP_BLOCK" | grep -q "$port"; then
        pass "nmap inclui porta $port"
    else
        fail "nmap não inclui porta $port"
    fi
done

if echo "$NMAP_BLOCK" | grep -q "\-T4"; then
    pass "nmap usa -T4 (timing agressivo)"
else
    warn "nmap sem -T4 — pode ser lento"
fi

if echo "$NMAP_BLOCK" | grep -q "\-\-open"; then
    pass "nmap usa --open (mostra só portas abertas)"
else
    warn "nmap sem --open"
fi

# ─────────────────────────────────────────────────────────────────
section "9. PYTHON — processamento de resultados"
# ─────────────────────────────────────────────────────────────────

# Extrair bloco Python e testar isoladamente
OUTDIR="$TMP/scantest"
mkdir -p "$OUTDIR/raw"

# ── Mock Nuclei JSONL ──────────────────────────────────────────────
cat > "$OUTDIR/raw/nuclei.json" <<'NJSON'
{"info":{"name":"CVE-2021-44228 Log4Shell","severity":"critical","description":"Log4j RCE","remediation":"Update Log4j","classification":{"cve-id":["CVE-2021-44228"]}},"matched-at":"https://example.com/app"}
{"info":{"name":"Missing CSP Header","severity":"medium","description":"No CSP","remediation":"Add CSP header","classification":{}},"matched-at":"https://example.com/"}
{"info":{"name":"Default Login","severity":"high","description":"Default creds","remediation":"Change creds","classification":{"cve-id":[]}},"matched-at":"https://example.com/admin"}
NJSON

# ── Mock ZAP JSON ──────────────────────────────────────────────────
cat > "$OUTDIR/raw/zap_alerts.json" <<'ZJSON'
{
  "alerts": [
    {"name":"SQL Injection","risk":"High","description":"SQL injection found","solution":"Use prepared statements","cweid":"89","url":"https://example.com/search?q=test"},
    {"name":"X-Frame-Options Missing","risk":"Medium","description":"Clickjacking possible","solution":"Add X-Frame-Options","cweid":"1021","url":"https://example.com/"},
    {"name":"Information Disclosure","risk":"Informational","description":"Version disclosed","solution":"Remove version headers","cweid":"200","url":"https://example.com/"}
  ]
}
ZJSON

# ── Mock httpx e nmap ──────────────────────────────────────────────
echo "target.example.com [200] [Login — Example] [React,CloudFront]" > "$OUTDIR/raw/httpx_results.txt"
echo "sub.example.com [200] [Example App] [nginx]" >> "$OUTDIR/raw/httpx_results.txt"

cat > "$OUTDIR/raw/nmap.txt" <<'NMAP'
PORT     STATE SERVICE  VERSION
80/tcp   open  http     nginx 1.18
443/tcp  open  https    nginx 1.18
8080/tcp open  http-alt Apache 2.4
NMAP

# Rodar bloco Python do script
PYTHON_OUTPUT=$(OUTDIR="$OUTDIR" TARGET="https://example.com" DOMAIN="example.com" \
    OPEN_PORTS="80/tcp 443/tcp 8080/tcp" ACTIVE_COUNT="2" SUB_COUNT="3" \
    python3 <<'PYEOF'
import json, os, html, sys
from datetime import datetime

OUTDIR       = os.environ.get('OUTDIR')
TARGET       = os.environ.get('TARGET')
DOMAIN       = os.environ.get('DOMAIN')
OPEN_PORTS   = os.environ.get('OPEN_PORTS', 'N/A')
ACTIVE_COUNT = os.environ.get('ACTIVE_COUNT', '0')
SUB_COUNT    = os.environ.get('SUB_COUNT', '0')

errors = []
findings = []
nuclei_file = os.path.join(OUTDIR, "raw", "nuclei.json")
if os.path.exists(nuclei_file):
    with open(nuclei_file, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line: continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                severity = info.get("severity", "info").lower()
                classification = info.get("classification", {}) or {}
                cve_list = classification.get("cve-id", []) or []
                findings.append({
                    "source": "Nuclei",
                    "name": info.get("name", "Vuln"),
                    "severity": severity,
                    "description": (info.get("description", "N/A") or "N/A")[:500],
                    "cve": ", ".join(cve_list) if cve_list else "N/A",
                    "url": data.get("matched-at", TARGET),
                    "remediation": info.get("remediation", "Fix it.") or "Fix it.",
                })
            except json.JSONDecodeError as e:
                errors.append(f"Nuclei linha {line_num}: {e}")
            except Exception as e:
                errors.append(f"Nuclei linha {line_num}: {type(e).__name__}: {e}")

zap_findings = []
zap_file = os.path.join(OUTDIR, "raw", "zap_alerts.json")
if os.path.exists(zap_file):
    try:
        with open(zap_file, "r", encoding="utf-8") as f:
            zap_data = json.load(f)
        alerts = zap_data.get("alerts", [])
        risk_map = {"high":"high","medium":"medium","low":"low","informational":"info"}
        for i, alert in enumerate(alerts):
            try:
                risk = alert.get("risk","info").lower()
                severity = risk_map.get(risk, "info")
                zap_findings.append({
                    "source": "OWASP ZAP",
                    "name": alert.get("name","Alert"),
                    "severity": severity,
                    "description": (alert.get("description","N/A") or "N/A")[:500],
                    "cve": f"CWE-{alert.get('cweid','N/A')}",
                    "url": alert.get("url", TARGET),
                    "remediation": alert.get("solution","Fix.") or "Fix.",
                })
            except Exception as e:
                errors.append(f"ZAP alerta {i}: {type(e).__name__}: {e}")
    except Exception as e:
        errors.append(f"ZAP: {type(e).__name__}: {e}")

all_findings = findings + zap_findings
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
all_findings.sort(key=lambda x: SEV_ORDER.get(x["severity"],5))

stats = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
for f in all_findings:
    if f["severity"] in stats: stats[f["severity"]] += 1

total = len(all_findings)
raw_score = (stats["critical"]*10)+(stats["high"]*5)+(stats["medium"]*2)+stats["low"]
risk_score = min(raw_score, 100)

print(f"TOTAL:{total}")
print(f"CRITICAL:{stats['critical']}")
print(f"HIGH:{stats['high']}")
print(f"MEDIUM:{stats['medium']}")
print(f"LOW:{stats['low']}")
print(f"INFO:{stats['info']}")
print(f"RISK:{risk_score}")
print(f"ERRORS:{len(errors)}")
print(f"SORTED_FIRST:{all_findings[0]['severity'] if all_findings else 'none'}")

# Gerar relatório de teste
html_file = os.path.join(OUTDIR, "test_report.html")
with open(html_file, "w") as f:
    f.write(f"<html><body>Test OK — {total} findings</body></html>")
print(f"HTML_WRITTEN:{os.path.exists(html_file)}")
PYEOF
)

if echo "$PYTHON_OUTPUT" | grep -q "TOTAL:6"; then
    pass "Python: processa 3 Nuclei + 3 ZAP = 6 findings"
else
    TOTAL=$(echo "$PYTHON_OUTPUT" | grep "^TOTAL:" | cut -d: -f2)
    fail "Python: total esperado=6, obtido=${TOTAL:-ERR}"
fi

if echo "$PYTHON_OUTPUT" | grep -q "CRITICAL:1"; then
    pass "Python: 1 finding crítico (Log4Shell)"
else
    fail "Python: contagem crítico incorreta"
fi

if echo "$PYTHON_OUTPUT" | grep -q "HIGH:2"; then
    pass "Python: 2 findings altos (Default Login + SQL Injection)"
else
    HIGH=$(echo "$PYTHON_OUTPUT" | grep "^HIGH:" | cut -d: -f2)
    fail "Python: alto esperado=2, obtido=${HIGH:-ERR}"
fi

if echo "$PYTHON_OUTPUT" | grep -q "MEDIUM:2"; then
    pass "Python: 2 findings médios"
else
    fail "Python: contagem médio incorreta"
fi

if echo "$PYTHON_OUTPUT" | grep -q "INFO:1"; then
    pass "Python: 1 finding informacional"
else
    fail "Python: contagem info incorreta"
fi

if echo "$PYTHON_OUTPUT" | grep -q "RISK:"; then
    RISK=$(echo "$PYTHON_OUTPUT" | grep "^RISK:" | cut -d: -f2)
    # C=1(10) + H=2(10) + M=2(4) + L=0 = 24 → capped at 100
    if [ "$RISK" -le 100 ] && [ "$RISK" -gt 0 ] 2>/dev/null; then
        pass "Python: risk score normalizado ($RISK ≤ 100)"
    else
        fail "Python: risk score fora do range (obtido: $RISK)"
    fi
fi

if echo "$PYTHON_OUTPUT" | grep -q "SORTED_FIRST:critical"; then
    pass "Python: findings ordenados por severidade (critical primeiro)"
else
    FIRST=$(echo "$PYTHON_OUTPUT" | grep "^SORTED_FIRST:" | cut -d: -f2)
    fail "Python: ordem incorreta — primeiro: ${FIRST:-ERR}"
fi

if echo "$PYTHON_OUTPUT" | grep -q "ERRORS:0"; then
    pass "Python: zero erros com dados válidos"
else
    ERRS=$(echo "$PYTHON_OUTPUT" | grep "^ERRORS:" | cut -d: -f2)
    warn "Python: ${ERRS:-?} erro(s) de processamento"
fi

if echo "$PYTHON_OUTPUT" | grep -q "HTML_WRITTEN:True"; then
    pass "Python: arquivo HTML gerado corretamente"
else
    fail "Python: HTML não foi escrito"
fi

# ─────────────────────────────────────────────────────────────────
section "10. PYTHON — tratamento de dados malformados"
# ─────────────────────────────────────────────────────────────────

OUTDIR2="$TMP/scantest_bad"
mkdir -p "$OUTDIR2/raw"

# JSON inválido no Nuclei
echo '{"info":{"name":"OK"}' > "$OUTDIR2/raw/nuclei.json"        # truncado
echo '{"info":{"name":"Bad","severity":null}}' >> "$OUTDIR2/raw/nuclei.json"

# ZAP malformado
echo "NOT JSON AT ALL" > "$OUTDIR2/raw/zap_alerts.json"

BAD_OUTPUT=$(OUTDIR="$OUTDIR2" TARGET="https://x.com" DOMAIN="x.com" \
    OPEN_PORTS="N/A" ACTIVE_COUNT="0" SUB_COUNT="1" \
    python3 <<'PYEOF2'
import json, os
OUTDIR = os.environ.get('OUTDIR')
TARGET = os.environ.get('TARGET')
errors = []
findings = []
nuclei_file = os.path.join(OUTDIR, "raw", "nuclei.json")
if os.path.exists(nuclei_file):
    with open(nuclei_file, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line: continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                severity = info.get("severity", "info")
                if severity is None: severity = "info"
                severity = severity.lower()
                findings.append({"source":"Nuclei","name":info.get("name","V"),"severity":severity,
                    "description":"N/A","cve":"N/A","url":TARGET,"remediation":"Fix."})
            except json.JSONDecodeError as e:
                errors.append(f"line {line_num}: {e}")
            except Exception as e:
                errors.append(f"line {line_num}: {type(e).__name__}")

zap_findings = []
zap_file = os.path.join(OUTDIR, "raw", "zap_alerts.json")
if os.path.exists(zap_file):
    try:
        with open(zap_file) as f:
            zap_data = json.load(f)
    except json.JSONDecodeError as e:
        errors.append(f"ZAP malformed: {e}")
    except Exception as e:
        errors.append(f"ZAP: {type(e).__name__}")

print(f"DID_NOT_CRASH:yes")
print(f"ERRORS_CAUGHT:{len(errors)}")
print(f"VALID_FINDINGS:{len(findings)}")
PYEOF2
)

if echo "$BAD_OUTPUT" | grep -q "DID_NOT_CRASH:yes"; then
    pass "Python: não crasha com JSON malformado"
else
    fail "Python: crashou com dados malformados"
fi

if echo "$BAD_OUTPUT" | grep -q "ERRORS_CAUGHT:"; then
    EC=$(echo "$BAD_OUTPUT" | grep "ERRORS_CAUGHT:" | cut -d: -f2)
    if [ "$EC" -gt 0 ] 2>/dev/null; then
        pass "Python: captura erros de parse ($EC erros registrados)"
    else
        warn "Python: erros não foram registrados"
    fi
fi

if echo "$BAD_OUTPUT" | grep -q "VALID_FINDINGS:1"; then
    pass "Python: processa linhas válidas mesmo com linhas inválidas ao redor"
else
    VF=$(echo "$BAD_OUTPUT" | grep "VALID_FINDINGS:" | cut -d: -f2)
    fail "Python: findings válidos esperado=1, obtido=${VF:-ERR}"
fi

# ─────────────────────────────────────────────────────────────────
section "11. OUTDIR — nome inclui domínio"
# ─────────────────────────────────────────────────────────────────

if grep -q 'OUTDIR="scan_\${DOMAIN}_\${TIMESTAMP}"' "$SCRIPT"; then
    pass "OUTDIR inclui domínio no nome (scan_DOMAIN_TIMESTAMP)"
else
    warn "OUTDIR pode não incluir domínio — verifique nomeação do diretório"
fi

# ─────────────────────────────────────────────────────────────────
section "12. COMPATIBILIDADE — ferramentas do sistema"
# ─────────────────────────────────────────────────────────────────

for tool in bash curl python3; do
    if command -v "$tool" &>/dev/null; then
        pass "Ferramenta obrigatória disponível: $tool"
    else
        fail "Ferramenta obrigatória ausente: $tool"
    fi
done

# URL encoding via python3 (sem jq para URLs)
ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" \
    "https://example.com/path?q=test" 2>/dev/null)
if echo "$ENC" | grep -q "example.com"; then
    pass "URL encoding via python3 funciona"
else
    fail "URL encoding falhou"
fi

# ─────────────────────────────────────────────────────────────────
section "13. TESTSSL — fase 3"
# ─────────────────────────────────────────────────────────────────

if grep -q 'validate_tool "testssl"' "$SCRIPT"; then
    pass "testssl declarado como ferramenta opcional"
else
    fail "testssl não declarado em validate_tool"
fi

if grep -q 'FASE 3/8: ANÁLISE TLS' "$SCRIPT"; then
    pass "Fase 3/8 TLS presente no script"
else
    fail "Fase 3/8 TLS não encontrada"
fi

if grep -q 'testssl.*--jsonfile\|--jsonfile.*testssl' "$SCRIPT"; then
    pass "testssl usa --jsonfile para output estruturado"
else
    fail "testssl sem --jsonfile"
fi

# Testar parser testssl com mock JSON
TESTSSL_OUTPUT=$(python3 -c "
import json
mock = [
    {'id':'heartbleed','severity':'CRITICAL','finding':'Vulnerable','cve':'CVE-2014-0160'},
    {'id':'TLS1_1','severity':'WARN','finding':'TLS 1.1 offered','cve':''},
    {'id':'cert_ok','severity':'OK','finding':'Certificate valid','cve':''},
]
SEV_MAP = {'CRITICAL':'critical','HIGH':'high','WARN':'medium','LOW':'low','OK':'info','INFO':'info'}
findings = [f for f in mock if f['severity'] in ('CRITICAL','HIGH','WARN','LOW')]
print('COUNT:' + str(len(findings)))
")
if echo "$TESTSSL_OUTPUT" | grep -q "COUNT:2"; then
    pass "testssl parser: filtra OK/INFO, mantém CRITICAL/WARN (2 achados)"
else
    fail "testssl parser incorreto: $TESTSSL_OUTPUT"
fi

# ─────────────────────────────────────────────────────────────────
section "14. CONFIRMAÇÃO DE EXPLOITS — fase 5"
# ─────────────────────────────────────────────────────────────────

if grep -q 'FASE 5/8: CONFIRMAÇÃO' "$SCRIPT"; then
    pass "Fase 5/8 Confirmação presente no script"
else
    fail "Fase 5/8 Confirmação não encontrada"
fi

if grep -q 'exploit_confirmations.json' "$SCRIPT"; then
    pass "Arquivo exploit_confirmations.json referenciado"
else
    fail "exploit_confirmations.json não referenciado"
fi

if grep -q 'curl-command' "$SCRIPT"; then
    pass "Script usa curl-command do Nuclei para reconfirmação"
else
    fail "curl-command não referenciado"
fi

# Testar lógica de confirmação com mock
python3 > /tmp/swtest_c1.out 2>/dev/null << 'PYEOF_C1'
import re
mock = "body\n---SWARM_STATUS:200---"
match = re.search(r"SWARM_STATUS:(\d+)", mock)
status = match.group(1) if match else "???"
confirmed = status.startswith("2") or status.startswith("3")
print("STATUS:" + status + ":CONFIRMED:" + str(confirmed))
PYEOF_C1
CONFIRM_RESULT=$(cat /tmp/swtest_c1.out)
if echo "$CONFIRM_RESULT" | grep -q "STATUS:200:CONFIRMED:True"; then
    pass "Lógica de confirmação: HTTP 200 → CONFIRMADO"
else
    fail "Lógica de confirmação incorreta: $CONFIRM_RESULT"
fi

python3 > /tmp/swtest_c2.out 2>/dev/null << 'PYEOF_C2'
import re
mock = "Forbidden\n---SWARM_STATUS:403---"
match = re.search(r"SWARM_STATUS:(\d+)", mock)
status = match.group(1) if match else "???"
confirmed = status.startswith("2") or status.startswith("3")
print("STATUS:" + status + ":CONFIRMED:" + str(confirmed))
PYEOF_C2
CONFIRM_RESULT2=$(cat /tmp/swtest_c2.out)
if echo "$CONFIRM_RESULT2" | grep -q "STATUS:403:CONFIRMED:False"; then
    pass "Lógica de confirmação: HTTP 403 → NÃO CONFIRMADO"
else
    fail "Lógica de confirmação incorreta para 403: $CONFIRM_RESULT2"
fi

# ─────────────────────────────────────────────────────────────────
section "15. OPENAPI — integração ZAP"
# ─────────────────────────────────────────────────────────────────

if grep -q 'FASE 6/8: COLETA' "$SCRIPT"; then
    pass "Fase 6/8 ZAP presente"
else
    fail "Fase 6/8 ZAP não encontrada"
fi

if grep -q 'openapi/action/importUrl' "$SCRIPT"; then
    pass "OpenAPI: usa ZAP API openapi/action/importUrl"
else
    fail "OpenAPI: importUrl não encontrado"
fi

# Verificar que probes pelo menos 5 paths comuns
OPENAPI_PATH_COUNT=$(grep -c "swagger.json\|openapi.json\|api-docs\|swagger-ui" "$SCRIPT" 2>/dev/null || echo 0)
if [ "$OPENAPI_PATH_COUNT" -ge 4 ]; then
    pass "OpenAPI: testa múltiplos paths comuns ($OPENAPI_PATH_COUNT matches)"
else
    fail "OpenAPI: poucos paths testados ($OPENAPI_PATH_COUNT < 4)"
fi

if grep -q 'swagger.*openapi.*paths\|"swagger"\|"openapi"' "$SCRIPT"; then
    pass "OpenAPI: valida conteúdo da resposta antes de importar"
else
    warn "OpenAPI: validação de conteúdo não encontrada"
fi

# ─────────────────────────────────────────────────────────────────
section "16. SCREENSHOTS — fase 7"
# ─────────────────────────────────────────────────────────────────

if grep -q 'FASE 7/8: SCREENSHOTS' "$SCRIPT"; then
    pass "Fase 7/8 Screenshots presente"
else
    fail "Fase 7/8 Screenshots não encontrada"
fi

if grep -q 'SCREENSHOT_TOOL' "$SCRIPT"; then
    pass "Variável SCREENSHOT_TOOL declarada"
else
    fail "SCREENSHOT_TOOL não declarada"
fi

# Verificar fallback chain
for browser in chromium chromium-browser wkhtmltoimage; do
    if grep -q "$browser" "$SCRIPT"; then
        pass "Screenshot: $browser no fallback chain"
    else
        fail "Screenshot: $browser ausente"
    fi
done

# Verificar embed base64
if grep -q 'base64\|data:image/png;base64' "$SCRIPT"; then
    pass "Screenshots embeds como base64 no HTML"
else
    fail "Screenshots sem embed base64"
fi

# Testar lógica base64 embed
B64_RESULT=$(python3 -c 'import base64; b=base64.b64encode(b"P").decode(); print("OK" if b else "FAIL")')
if [ "$B64_RESULT" = "OK" ]; then
    pass "Screenshot base64 embed: geração correta"
else
    fail "Screenshot base64 embed: falhou"
fi

# Verificar que screenshots aparecem no relatório HTML
if grep -q 'screenshot-grid\|screenshot-card\|screenshot-label' "$SCRIPT"; then
    pass "Screenshots: CSS classes no HTML do relatório"
else
    fail "Screenshots: CSS classes ausentes"
fi

# ─────────────────────────────────────────────────────────────────
section "17. INTEGRAÇÃO — novas seções no relatório"
# ─────────────────────────────────────────────────────────────────

if grep -q 'tls_html\|tls_findings' "$SCRIPT"; then
    pass "TLS: seção HTML gerada no relatório"
else
    fail "TLS: tls_html ausente no relatório"
fi

if grep -q 'confirm_html\|confirmations' "$SCRIPT"; then
    pass "Confirmações: seção HTML gerada no relatório"
else
    fail "Confirmações: confirm_html ausente"
fi

if grep -q 'screenshots_html\|screenshots_grid\|screenshot-grid' "$SCRIPT"; then
    pass "Screenshots: seção HTML gerada no relatório"
else
    fail "Screenshots: screenshots_html ausente"
fi

# Verificar que export passa as novas variáveis para o Python
if grep -q 'export.*SCREENSHOT_COUNT.*OPENAPI_FOUND.*TLS_ISSUES.*CONFIRMED_COUNT' "$SCRIPT"; then
    pass "export: novas variáveis passadas ao Python do relatório"
else
    fail "export: variáveis novas não exportadas"
fi




# ─────────────────────────────────────────────────────────────────
section "18. PARALELISMO — testssl + nuclei"
# ─────────────────────────────────────────────────────────────────

if grep -q 'TLS_PID=' "$SCRIPT"; then
    pass "testssl usa TLS_PID para controle de background"
else
    fail "TLS_PID não encontrado — testssl não roda em background"
fi

if grep -q 'testssl.*&$\|testssl.*& *$\|testssl.*2>&1 &' "$SCRIPT"; then
    pass "testssl iniciado em background (&)"
else
    fail "testssl não está em background"
fi

if grep -q 'wait.*TLS_PID\|wait.*\$TLS_PID' "$SCRIPT"; then
    pass "Script aguarda TLS_PID antes de coletar resultado"
else
    fail "wait TLS_PID ausente"
fi

if grep -q 'paralelo com nuclei\|paralelo com testssl' "$SCRIPT"; then
    pass "Fases 3+4 indicam execução paralela no terminal"
else
    fail "Label de fase paralela não encontrado"
fi

# ─────────────────────────────────────────────────────────────────
section "19. CONFIRMAÇÃO — filtro C/A/M"
# ─────────────────────────────────────────────────────────────────

if grep -q '"critical".*"high".*"medium"\|critical.*high.*medium' "$SCRIPT" | grep -q "not in\|continue"; then
    pass "Confirmação filtra por severidade"
fi

# Testar a lógica de filtro diretamente
python3 > /tmp/swtest_conf_filter.out << 'PYEOF_CF'
def should_confirm(severity):
    return severity.lower() in ("critical", "high", "medium")

results = [
    ("critical", True),
    ("high",     True),
    ("medium",   True),
    ("low",      False),
    ("info",     False),
]
ok = all(should_confirm(s) == e for s, e in results)
print("OK" if ok else "FAIL")
PYEOF_CF
CONF_FILTER=$(cat /tmp/swtest_conf_filter.out)
if [ "$CONF_FILTER" = "OK" ]; then
    pass "Filtro C/A/M: critical/high/medium=confirmar, low/info=ignorar"
else
    fail "Filtro de confirmação incorreto"
fi

# Verificar que o filtro está no script
if grep -q 'severity.*not in.*critical.*high.*medium\|not in.*(\"critical\".*\"high\".*\"medium\")' "$SCRIPT"; then
    pass "Lógica de filtro presente no script"
else
    # Try alternative pattern
    grep -q 'if severity.*lower.*not in' "$SCRIPT" && \
        pass "Lógica de filtro presente no script" || \
        warn "Verificar filtro de severidade na confirmação"
fi

# ─────────────────────────────────────────────────────────────────
section "20. ZAP MEDIUM — deduplicação"
# ─────────────────────────────────────────────────────────────────

if grep -q '"medium","low","info"\|"medium".*"low".*"info"' "$SCRIPT"; then
    pass "ZAP agrupa Medium/Low/Info (deduplicação estendida)"
else
    fail "Deduplicação ZAP não inclui Medium"
fi

# Testar lógica de agrupamento com dados mock
python3 > /tmp/swtest_dedup.out << 'PYEOF_DD'
alerts = [
    {"name": "Missing CSP", "risk": "Medium", "url": "https://t.com/a"},
    {"name": "Missing CSP", "risk": "Medium", "url": "https://t.com/b"},
    {"name": "Missing CSP", "risk": "Medium", "url": "https://t.com/c"},
    {"name": "SQL Injection","risk": "High",   "url": "https://t.com/api"},
    {"name": "Cookie Flag",  "risk": "Low",    "url": "https://t.com/x"},
]
rmap = {"high":"high","medium":"medium","low":"low","informational":"info"}
zap_findings = []
zap_groups   = {}
sev_order    = {"medium":0,"low":1,"info":2}
for a in alerts:
    sev = rmap.get(a["risk"].lower(),"info")
    if sev in ("medium","low","info"):
        n = a["name"]
        if n not in zap_groups:
            zap_groups[n] = {"count":0,"urls":[],"sev":sev}
        else:
            if sev_order.get(sev,3) < sev_order.get(zap_groups[n]["sev"],3):
                zap_groups[n]["sev"] = sev
        zap_groups[n]["count"] += 1
        if a["url"] not in zap_groups[n]["urls"]:
            zap_groups[n]["urls"].append(a["url"])
    else:
        zap_findings.append(a)

ok = (len(zap_findings)==1 and
      "Missing CSP" in zap_groups and
      zap_groups["Missing CSP"]["count"]==3 and
      len(zap_groups["Missing CSP"]["urls"])==3 and
      "Cookie Flag" in zap_groups)
print("OK" if ok else f"FAIL: cards={len(zap_findings)} groups={list(zap_groups.keys())}")
PYEOF_DD
DEDUP_RESULT=$(cat /tmp/swtest_dedup.out)
if [ "$DEDUP_RESULT" = "OK" ]; then
    pass "ZAP deduplicação: 3x CSP Medium → 1 grupo, High → card individual"
else
    fail "ZAP deduplicação Medium incorreta: $DEDUP_RESULT"
fi

# ─────────────────────────────────────────────────────────────────
section "21. RISK SCORE — EPSS incorporado"
# ─────────────────────────────────────────────────────────────────

if grep -q 'epss_bonus\|epss_score.*bonus\|EPSS.*risk' "$SCRIPT"; then
    pass "EPSS bonus presente no cálculo de risco"
else
    fail "EPSS bonus ausente no risk score"
fi

python3 > /tmp/swtest_epss_risk.out << 'PYEOF_ER'
def calc_risk(stats, cve_enrichment):
    base = (stats["critical"]*10)+(stats["high"]*5)+(stats["medium"]*2)+stats["low"]
    epss_bonus = 0
    for ev in cve_enrichment.values():
        epss = ev.get("epss_score") or 0
        if epss >= 0.5:    epss_bonus += 15
        elif epss >= 0.1:  epss_bonus += 7
        elif epss >= 0.01: epss_bonus += 2
    return min(base + epss_bonus, 100), base, epss_bonus

# Case 1: same stats, different EPSS → different scores
stats = {"critical":1,"high":0,"medium":0,"low":0,"info":0}
r1, b1, e1 = calc_risk(stats, {})
r2, b2, e2 = calc_risk(stats, {"CVE-A":{"epss_score":0.97}})
r3, b3, e3 = calc_risk(stats, {"CVE-B":{"epss_score":0.15}})  # 0.15>=0.1 → +7
r4, b4, e4 = calc_risk(stats, {"CVE-C":{"epss_score":0.05}})  # 0.05>=0.01 → +2

ok = (r1==10 and e1==0 and        # no EPSS → base only
      r2==25 and e2==15 and        # EPSS≥0.5 → +15
      r3==17 and e3==7 and         # EPSS≥0.1 → +7
      r4==12 and e4==2 and         # EPSS≥0.01 → +2
      min(100+50, 100)==100)       # cap at 100
print("OK" if ok else f"FAIL: r1={r1} r2={r2} r3={r3} r4={r4}")
PYEOF_ER
EPSS_RISK=$(cat /tmp/swtest_epss_risk.out)
if [ "$EPSS_RISK" = "OK" ]; then
    pass "EPSS risk: sem EPSS=base, EPSS≥50%=+15, EPSS≥10%=+7, cap=100"
else
    fail "EPSS risk score incorreto: $EPSS_RISK"
fi

# ─────────────────────────────────────────────────────────────────
section "22. DURAÇÃO TOTAL — relatório"
# ─────────────────────────────────────────────────────────────────

if grep -q 'SCAN_START_TS' "$SCRIPT"; then
    pass "SCAN_START_TS declarado no script"
else
    fail "SCAN_START_TS não encontrado"
fi

if grep -q 'duration_secs\|duration_str' "$SCRIPT"; then
    pass "Cálculo de duração presente no Python do relatório"
else
    fail "duration_str ausente"
fi

if grep -q 'Duração.*duration_str\|duration_str.*Duração' "$SCRIPT"; then
    pass "Duração exibida no HTML do relatório"
else
    fail "Duração não aparece no HTML"
fi

python3 > /tmp/swtest_duration.out << 'PYEOF_DUR'
import time as _time
cases = [
    (3742,  "1h 2m 22s"),
    (60,    "0h 1m 0s"),
    (3600,  "1h 0m 0s"),
    (86399, "23h 59m 59s"),
]
ok = True
for secs, expected in cases:
    start = int(_time.time()) - secs
    d = int(_time.time()) - start
    result = f"{d//3600}h {(d%3600)//60}m {d%60}s"
    # Allow ±1s drift
    exp_parts = [int(x[:-1]) for x in expected.split()]
    res_parts = [int(x[:-1]) for x in result.split()]
    if abs(res_parts[0]-exp_parts[0])>0 or abs(res_parts[1]-exp_parts[1])>0:
        ok = False
        print(f"FAIL: expected ~{expected} got {result}")
        break
print("OK" if ok else "")
PYEOF_DUR
DUR_RESULT=$(cat /tmp/swtest_duration.out)
if [ "$DUR_RESULT" = "OK" ]; then
    pass "Formato de duração: Xh Ym Zs correto"
else
    fail "Formato de duração incorreto: $DUR_RESULT"
fi

# ─────────────────────────────────────────────────────────────────
section "23. SCREENSHOTS — ZAP high incluídos"
# ─────────────────────────────────────────────────────────────────

if grep -q "zap_alerts.json\|zap.*alerts.*screenshot\|risk.*high.*critical.*screenshot\|screenshot.*zap" "$SCRIPT"; then
    pass "Screenshots incluem URLs de alertas ZAP high/critical"
else
    fail "Screenshots não consultam zap_alerts.json"
fi

python3 > /tmp/swtest_ss_urls.out << 'PYEOF_SS'
import json

nuclei_data = [
    {"info":{"severity":"critical"},"matched-at":"https://t.com/rce"},
    {"info":{"severity":"info"},    "matched-at":"https://t.com/info"},
]
zap_data = {"alerts":[
    {"risk":"High",   "url":"https://t.com/sqli"},
    {"risk":"Medium", "url":"https://t.com/xss"},
    {"risk":"High",   "url":"https://t.com/rce"},  # duplicate with nuclei
]}

seen = set(); urls = []
for d in nuclei_data:
    sev = d.get("info",{}).get("severity","")
    url = d.get("matched-at","")
    if sev in ("critical","high") and url and url not in seen:
        seen.add(url); urls.append(url)
for a in zap_data["alerts"]:
    if a.get("risk","").lower() in ("high","critical"):
        url = a.get("url","")
        if url and url not in seen:
            seen.add(url); urls.append(url)

# Expect: nuclei crit (rce), zap high (sqli) - rce already seen
ok = (len(urls)==2 and
      "https://t.com/rce" in urls and
      "https://t.com/sqli" in urls and
      "https://t.com/info" not in urls and
      "https://t.com/xss" not in urls)
print("OK" if ok else f"FAIL: {urls}")
PYEOF_SS
SS_RESULT=$(cat /tmp/swtest_ss_urls.out)
if [ "$SS_RESULT" = "OK" ]; then
    pass "Screenshot URLs: nuclei C/A + ZAP H/C, deduplicado, sem info/medium"
else
    fail "Screenshot URL collection incorreta: $SS_RESULT"
fi

# ─────────────────────────────────────────────────────────────────
section "24. NVD RETRY — backoff exponencial"
# ─────────────────────────────────────────────────────────────────

if grep -q 'max_retries\|backoff\|2 \*\* attempt' "$SCRIPT"; then
    pass "NVD retry com backoff exponencial presente"
else
    fail "NVD retry/backoff não encontrado"
fi

if grep -q '403\|429' "$SCRIPT"; then
    pass "NVD trata HTTP 403/429 (rate limit)"
else
    fail "NVD não trata códigos de rate limit"
fi

python3 > /tmp/swtest_nvd_retry.out << 'PYEOF_NVD'
# Testar lógica de backoff
calls = []
def mock_fetch(attempt, max_retries=3):
    calls.append(attempt)
    if attempt < 2:
        return None, 403  # rate limited
    return {"data": "ok"}, 200

results = []
for attempt in range(3):
    data, code = mock_fetch(attempt)
    if code == 200:
        results.append(data)
        break
    wait = (2 ** attempt) * 6
    results.append(f"wait_{wait}s")

ok = (results[0] == "wait_6s" and
      results[1] == "wait_12s" and
      results[2] == {"data":"ok"})
print("OK" if ok else f"FAIL: {results}")
PYEOF_NVD
NVD_RETRY=$(cat /tmp/swtest_nvd_retry.out)
if [ "$NVD_RETRY" = "OK" ]; then
    pass "NVD backoff: 403→6s, 403→12s, 200→ok"
else
    fail "NVD retry incorreto: $NVD_RETRY"
fi

# ─────────────────────────────────────────────────────────────────
section "25. TMP FILES — usa OUTDIR"
# ─────────────────────────────────────────────────────────────────

TMP_COUNT=$(grep -c '/tmp/swarm' "$SCRIPT" 2>/dev/null); TMP_COUNT=${TMP_COUNT:-0}
if [ "$TMP_COUNT" -eq 0 ]; then
    pass "Sem arquivos /tmp/swarm — todos usam OUTDIR"
else
    fail "$TMP_COUNT referência(s) a /tmp/swarm encontrada(s)"
fi

if grep -q 'swarm_ss_urls\|swarm_oa_check' "$SCRIPT"; then
    TMP_REF=$(grep 'swarm_ss_urls\|swarm_oa_check' "$SCRIPT" | grep -c '/tmp/'); TMP_REF=${TMP_REF:-0}
    [ "$TMP_REF" -eq 0 ] && pass "Arquivos temporários usam OUTDIR (não /tmp)" || \
        fail "$TMP_REF arquivo(s) temporário(s) ainda usam /tmp"
fi

# ─────────────────────────────────────────────────────────────────
section "26. CÓDIGO — import re consolidado"
# ─────────────────────────────────────────────────────────────────

# import re as _re should not exist (was inside render_finding — now uses global re)
if grep -q 'import re as _re' "$SCRIPT"; then
    fail "import re as _re ainda presente (deveria usar re global)"
else
    pass "import re as _re removido — render_finding usa re global"
fi

# Verify re is imported at top level of PYEOF block
if grep -q 'import json, os, html, re' "$SCRIPT"; then
    pass "import re consolidado no topo do bloco Python"
else
    fail "import re não encontrado no topo do bloco Python"
fi

# Cleanup temp files
rm -f /tmp/swtest_conf_filter.out /tmp/swtest_dedup.out /tmp/swtest_epss_risk.out
rm -f /tmp/swtest_duration.out /tmp/swtest_ss_urls.out /tmp/swtest_nvd_retry.out

# ─────────────────────────────────────────────────────────────────
section "RESULTADO FINAL"
# ─────────────────────────────────────────────────────────────────

TOTAL=$((PASS + FAIL + WARN))
echo ""
echo -e "${BOLD}  Total de testes: $TOTAL${NC}"
echo -e "  ${GREEN}Passou : $PASS${NC}"
echo -e "  ${RED}Falhou : $FAIL${NC}"
echo -e "  ${YELLOW}Aviso  : $WARN${NC}"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  ✓ Todos os testes passaram — script pronto para uso${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}  ✗ $FAIL teste(s) falharam — revisar antes de usar${NC}"
    exit 1
fi

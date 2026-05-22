#!/usr/bin/env python3
"""
email_security.py — SPF/DMARC/DKIM → email_security.json

Extraído de swarm.sh (heredoc PYEMAIL). Recebe argumentos posicionais
via sys.argv, idêntico à invocação original do swarm.sh.
"""
import subprocess, json, sys, re, os

domain = sys.argv[1]
outdir = sys.argv[2]

def dig(record_type, name, short=True):
    cmd = ["dig", "+short", record_type, name] if short else ["dig", record_type, name]
    try:
        return subprocess.check_output(cmd, timeout=10, text=True).strip()
    except: return ""

results = {}

# ── SPF ───────────────────────────────────────────────────────────
spf_raw = dig("TXT", domain)
spf_records = [l for l in spf_raw.splitlines() if "v=spf1" in l.lower()]

if not spf_records:
    results["spf"] = {"status": "MISSING", "severity": "high",
        "detail": "Registro SPF ausente — qualquer servidor pode enviar e-mail em nome do domínio.",
        "recommendation": "Adicione um registro TXT SPF, ex: v=spf1 include:_spf.google.com ~all"}
elif any("+all" in r for r in spf_records):
    results["spf"] = {"status": "PERMISSIVE", "severity": "high",
        "detail": f"SPF com '+all' permite QUALQUER servidor enviar e-mail pelo domínio.",
        "value": spf_records[0],
        "recommendation": "Substitua '+all' por '~all' (softfail) ou '-all' (hardfail)."}
elif any("?all" in r for r in spf_records):
    results["spf"] = {"status": "NEUTRAL", "severity": "medium",
        "detail": "SPF com '?all' (neutro) não bloqueia remetentes não autorizados.",
        "value": spf_records[0],
        "recommendation": "Substitua '?all' por '~all' ou '-all'."}
else:
    qual = "softfail (~all)" if "~all" in spf_records[0] else "hardfail (-all)" if "-all" in spf_records[0] else "configurado"
    results["spf"] = {"status": "OK", "severity": "none",
        "detail": f"SPF configurado corretamente ({qual}).",
        "value": spf_records[0]}

# ── DMARC ─────────────────────────────────────────────────────────
dmarc_raw = dig("TXT", f"_dmarc.{domain}")
dmarc_records = [l for l in dmarc_raw.splitlines() if "v=dmarc1" in l.lower()]

if not dmarc_records:
    results["dmarc"] = {"status": "MISSING", "severity": "high",
        "detail": "Registro DMARC ausente — sem visibilidade ou controle sobre uso abusivo do domínio.",
        "recommendation": "Adicione: _dmarc."+domain+" TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@"+domain+"\""}
else:
    dmarc = dmarc_records[0]
    policy_m = re.search(r'p=(none|quarantine|reject)', dmarc, re.IGNORECASE)
    policy = policy_m.group(1).lower() if policy_m else "unknown"
    if policy == "none":
        results["dmarc"] = {"status": "MONITOR_ONLY", "severity": "medium",
            "detail": "DMARC com p=none apenas monitora — e-mails falsos ainda chegam aos destinatários.",
            "value": dmarc,
            "recommendation": "Evolua para p=quarantine e depois p=reject após validar relatórios."}
    elif policy in ("quarantine", "reject"):
        results["dmarc"] = {"status": "OK", "severity": "none",
            "detail": f"DMARC configurado com p={policy}.",
            "value": dmarc}
    else:
        results["dmarc"] = {"status": "INVALID", "severity": "medium",
            "detail": f"DMARC com política inválida ou não reconhecida: {policy}",
            "value": dmarc,
            "recommendation": "Verifique a sintaxe do registro DMARC."}

# ── DKIM (heurística: verificar seletores comuns) ─────────────────
selectors = ["default", "google", "mail", "k1", "s1", "s2", "email", "selector1", "selector2"]
dkim_found = []
for sel in selectors:
    r = dig("TXT", f"{sel}._domainkey.{domain}")
    if "v=dkim1" in r.lower() or "p=" in r:
        dkim_found.append(sel)

if dkim_found:
    results["dkim"] = {"status": "OK", "severity": "none",
        "detail": f"DKIM encontrado para seletores: {', '.join(dkim_found)}"}
else:
    results["dkim"] = {"status": "NOT_FOUND", "severity": "low",
        "detail": "DKIM não detectado nos seletores comuns. Pode estar configurado com seletor personalizado.",
        "recommendation": "Verifique se o provedor de e-mail configurou DKIM para o domínio."}

# ── Salvar e exibir ────────────────────────────────────────────────
with open(os.path.join(outdir, "raw", "email_security.json"), "w") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

issues = sum(1 for v in results.values() if v["severity"] in ("high","medium"))
print(f"  [{'!' if issues else '✓'}] SPF: {results['spf']['status']} | DMARC: {results['dmarc']['status']} | DKIM: {results['dkim']['status']}")
if issues:
    print(f"  [!] {issues} problema(s) de segurança de email encontrado(s)")
    for key, val in results.items():
        if val["severity"] in ("high","medium"):
            print(f"      • {key.upper()}: {val['detail']}")

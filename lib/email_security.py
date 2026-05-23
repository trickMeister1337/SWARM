#!/usr/bin/env python3
"""
email_security.py — SPF/DMARC/DKIM → email_security.json

Extraído de stiglitz.sh (heredoc PYEMAIL). Recebe argumentos posicionais
via sys.argv, idêntico à invocação original do stiglitz.sh.
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
        "detail": "SPF record missing — any server can send email on behalf of the domain.",
        "recommendation": "Add a TXT SPF record, e.g. v=spf1 include:_spf.google.com ~all"}
elif any("+all" in r for r in spf_records):
    results["spf"] = {"status": "PERMISSIVE", "severity": "high",
        "detail": f"SPF with '+all' allows ANY server to send email for the domain.",
        "value": spf_records[0],
        "recommendation": "Replace '+all' with '~all' (softfail) or '-all' (hardfail)."}
elif any("?all" in r for r in spf_records):
    results["spf"] = {"status": "NEUTRAL", "severity": "medium",
        "detail": "SPF with '?all' (neutral) does not block unauthorized senders.",
        "value": spf_records[0],
        "recommendation": "Replace '?all' with '~all' or '-all'."}
else:
    qual = "softfail (~all)" if "~all" in spf_records[0] else "hardfail (-all)" if "-all" in spf_records[0] else "configured"
    results["spf"] = {"status": "OK", "severity": "none",
        "detail": f"SPF configured correctly ({qual}).",
        "value": spf_records[0]}

# ── DMARC ─────────────────────────────────────────────────────────
dmarc_raw = dig("TXT", f"_dmarc.{domain}")
dmarc_records = [l for l in dmarc_raw.splitlines() if "v=dmarc1" in l.lower()]

if not dmarc_records:
    results["dmarc"] = {"status": "MISSING", "severity": "high",
        "detail": "DMARC record missing — no visibility or control over domain abuse.",
        "recommendation": "Adicione: _dmarc."+domain+" TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@"+domain+"\""}
else:
    dmarc = dmarc_records[0]
    policy_m = re.search(r'p=(none|quarantine|reject)', dmarc, re.IGNORECASE)
    policy = policy_m.group(1).lower() if policy_m else "unknown"
    if policy == "none":
        results["dmarc"] = {"status": "MONITOR_ONLY", "severity": "medium",
            "detail": "DMARC with p=none only monitors — spoofed emails still reach recipients.",
            "value": dmarc,
            "recommendation": "Move to p=quarantine and then p=reject after validating reports."}
    elif policy in ("quarantine", "reject"):
        results["dmarc"] = {"status": "OK", "severity": "none",
            "detail": f"DMARC configured with p={policy}.",
            "value": dmarc}
    else:
        results["dmarc"] = {"status": "INVALID", "severity": "medium",
            "detail": f"DMARC with invalid or unrecognized policy: {policy}",
            "value": dmarc,
            "recommendation": "Check the DMARC record syntax."}

# ── DKIM (heurística: verificar seletores comuns) ─────────────────
selectors = ["default", "google", "mail", "k1", "s1", "s2", "email", "selector1", "selector2"]
dkim_found = []
for sel in selectors:
    r = dig("TXT", f"{sel}._domainkey.{domain}")
    if "v=dkim1" in r.lower() or "p=" in r:
        dkim_found.append(sel)

if dkim_found:
    results["dkim"] = {"status": "OK", "severity": "none",
        "detail": f"DKIM found for selectors: {', '.join(dkim_found)}"}
else:
    results["dkim"] = {"status": "NOT_FOUND", "severity": "low",
        "detail": "DKIM not detected on common selectors. It may be configured with a custom selector.",
        "recommendation": "Verify whether the email provider configured DKIM for the domain."}

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

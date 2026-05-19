#!/usr/bin/env python3
"""
batch_report.py — Consolidador de relatórios SWARM

Uso:
  python3 lib/batch_report.py -d scan_batch_*/          # batch dir
  python3 lib/batch_report.py scan_*/findings.json      # arquivos diretos
  python3 lib/batch_report.py --min-severity high ...   # filtro de severidade
  python3 lib/batch_report.py --out relatorio.html ...  # saída customizada

Severidades: critical > high > medium > low > info
"""

import argparse
import glob
import json
import os
import sys
from datetime import datetime
from collections import defaultdict

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ─── knowledge base de remediações ───────────────────────────────────────────
# Usado quando o campo remediation está ausente ou é genérico ("Revisar.").
REMEDIATION_KB: dict[str, str] = {
    "Node-Red - Default Login": """\
RISCO: Acesso administrativo completo com credenciais padrão → RCE imediato.

AÇÃO IMEDIATA:
  1. Troque as credenciais padrão AGORA — acesse o painel e altere a senha antes de qualquer outra coisa.
  2. Habilite autenticação em settings.js (Node-RED ≥ 1.x):

     module.exports = {
         adminAuth: {
             type: "credentials",
             users: [{
                 username: "admin",
                 password: "$2b$08$<bcrypt-hash>",  // gere com: node -e "console.log(require('bcryptjs').hashSync('SuaSenhaForte',8))"
                 permissions: "*"
             }]
         }
     }

  3. Restrinja o endpoint /red/ e /admin por IP no reverse proxy (Nginx/Caddy):

     location /red/ {
         allow 10.0.0.0/8;    # apenas rede interna
         deny all;
         proxy_pass http://localhost:1880/;
     }

  4. Desabilite o editor em produção se não for necessário (settings.js):
       editorTheme: { header: { title: "Production" } },
       // ou: httpAdminRoot: false  (desabilita UI completamente)

  5. Habilite auditoria de fluxos e revise flows.json em busca de credenciais expostas.
  6. Atualize Node-RED para a versão mais recente (npm install -g node-red@latest).

VALIDAÇÃO: curl -u admin:password http://<host>:1880/red/ deve retornar 401 após a correção.\
""",

    "Weak Cipher Suites Detection": """\
Desabilite cipher suites fracas (DES, RC4, 3DES, EXPORT, NULL) e force TLS 1.2+.

Nginx (em /etc/nginx/nginx.conf ou no vhost):
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
  ssl_prefer_server_ciphers on;
  ssl_session_cache shared:SSL:10m;

Apache (/etc/apache2/mods-enabled/ssl.conf):
  SSLProtocol -all +TLSv1.2 +TLSv1.3
  SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:!aNULL:!eNULL:!EXPORT:!RC4:!DES:!3DES
  SSLHonorCipherOrder on

Referência: https://ssl-config.mozilla.org/ (perfil "Intermediate" para compatibilidade)
Validação: testssl.sh --cipher <host> ou SSL Labs (ssllabs.com/ssltest/)\
""",

    "TLS Version - Detect": """\
TLS 1.0 e TLS 1.1 são considerados inseguros (RFC 8996) e devem ser desabilitados.

Nginx:
  ssl_protocols TLSv1.2 TLSv1.3;

Apache:
  SSLProtocol -all +TLSv1.2 +TLSv1.3

AWS ALB/CloudFront: Configure a Security Policy para ELBSecurityPolicy-TLS13-1-2-2021-06 ou superior.
Validação: testssl.sh --protocols <host>\
""",

    "HTTP Missing Security Headers": """\
Adicione os seguintes cabeçalhos de segurança HTTP à resposta do servidor:

Nginx (no bloco server {} ou location {}):
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-Frame-Options "SAMEORIGIN" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
  add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'" always;

Apache (no .htaccess ou VirtualHost):
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"

Validação: securityheaders.com ou curl -I https://<host>\
""",

    "WAF Detection": """\
Finding informativo — presença de WAF detectada. Nenhuma ação de remediação necessária.
Recomendação: Mantenha as regras do WAF atualizadas e revise periodicamente os logs de bloqueio.\
""",

    "Wappalyzer Technology Detection": """\
Finding informativo — tecnologias identificadas via Wappalyzer. Nenhuma ação imediata necessária.
Recomendação: Remova ou ofusque cabeçalhos que revelem versões específicas (X-Powered-By, Server)
para reduzir a superfície de reconhecimento passivo.\
""",

    "Nginx version detect": """\
Remova a divulgação de versão do Nginx para dificultar a identificação de vulnerabilidades conhecidas.

Em /etc/nginx/nginx.conf (bloco http {}):
  server_tokens off;

Para remover também do cabeçalho Server:
  # Requer módulo ngx_headers_more (OpenResty ou compilação customizada):
  more_clear_headers Server;

Validação: curl -I https://<host> — o cabeçalho Server não deve exibir a versão.\
""",

    "Absence of Anti-CSRF Tokens": """\
Implemente tokens CSRF em todos os formulários HTML e requisições de estado mutável (POST/PUT/DELETE/PATCH).

1. Framework-level (preferido):
   - Django: {{ csrf_token }} no template + @csrf_protect no view
   - Spring Security: <csrf /> em SecurityConfig (habilitado por padrão no Spring Security 4+)
   - Laravel: @csrf na blade template
   - Express (Node.js): use o pacote csurf ou csrf-csrf

2. Implementação manual (se sem framework):
   a. Gere um token aleatório criptograficamente seguro na sessão:
      token = secrets.token_hex(32)  # Python
      session['csrf_token'] = token
   b. Inclua-o em cada formulário como campo hidden:
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
   c. Valide no servidor em cada requisição de escrita:
      if request.form['csrf_token'] != session['csrf_token']: abort(403)

3. Para APIs com SPA (Single Page Application):
   - Use o padrão Double Submit Cookie ou SameSite=Strict nos cookies de sessão
   - Adicione o header personalizado X-Requested-With: XMLHttpRequest

4. SameSite Cookie (defesa em camadas):
   Set-Cookie: session=<valor>; SameSite=Strict; Secure; HttpOnly

Validação: Tente submeter um formulário de outro domínio sem o token — deve retornar 403.\
""",
}

_GENERIC_REMEDIATIONS = {"revisar.", "revisar", "review.", "review", "n/a", ""}


def enrich_remediation(name: str, remediation: str) -> str:
    """Retorna remediação do KB se a original for genérica ou ausente."""
    if (remediation or "").strip().lower() in _GENERIC_REMEDIATIONS:
        return REMEDIATION_KB.get(name, remediation)
    return remediation
SEV_COLOR = {
    "critical": "#c0392b",
    "high":     "#e55a00",
    "medium":   "#d4a500",
    "low":      "#27ae60",
    "info":     "#2980b9",
}
SEV_LABEL = {
    "critical": "CRÍTICO",
    "high":     "ALTO",
    "medium":   "MÉDIO",
    "low":      "BAIXO",
    "info":     "INFO",
}

# ─── coleta de dados ──────────────────────────────────────────────────────────

def load_findings(path: str) -> dict | None:
    try:
        with open(path) as f:
            data = json.load(f)
        if "findings" not in data or "scan" not in data:
            return None
        return data
    except Exception as e:
        print(f"[!] Ignorando {path}: {e}", file=sys.stderr)
        return None


def resolve_paths(args_paths: list[str], batch_dir: str | None) -> list[str]:
    paths = []
    if batch_dir:
        for d in glob.glob(os.path.join(batch_dir, "**/findings.json"), recursive=True):
            paths.append(d)
        if not paths:
            for d in glob.glob(os.path.join(batch_dir, "*/findings.json")):
                paths.append(d)
    for p in args_paths:
        if os.path.isdir(p):
            cand = os.path.join(p, "findings.json")
            if os.path.exists(cand):
                paths.append(cand)
        elif os.path.isfile(p):
            paths.append(p)
        else:
            for m in glob.glob(p):
                paths.append(m)
    return sorted(set(paths))


def collect(paths: list[str], min_sev: str) -> tuple[list[dict], list[dict]]:
    """Retorna (targets_meta, all_findings) filtrados por severidade mínima."""
    min_order = SEV_ORDER.get(min_sev, 1)
    targets = []
    findings_all = []

    for path in paths:
        data = load_findings(path)
        if not data:
            continue
        scan = data["scan"]
        summary = data.get("summary", {})
        findings = data.get("findings", [])

        filtered = [
            f for f in findings
            if SEV_ORDER.get(f.get("severity", "info"), 99) <= min_order
        ]

        targets.append({
            "domain":    scan.get("domain", "?"),
            "target":    scan.get("target", "?"),
            "timestamp": scan.get("timestamp", ""),
            "risk_score": scan.get("risk_score", 0),
            "risk_level": scan.get("risk_level", ""),
            "waf":       scan.get("waf_detected", False),
            "waf_name":  scan.get("waf_name", ""),
            "summary":   summary,
            "findings":  filtered,
            "path":      path,
        })

        for f in filtered:
            findings_all.append({**f, "_domain": scan.get("domain", "?")})

    targets.sort(key=lambda t: (
        -(t["summary"].get("critical", 0) * 1000 +
          t["summary"].get("high", 0) * 100 +
          t["summary"].get("medium", 0))
    ))
    findings_all.sort(key=lambda f: SEV_ORDER.get(f.get("severity", "info"), 99))
    return targets, findings_all

# ─── geração HTML ─────────────────────────────────────────────────────────────

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f2f5;color:#222;font-size:14px}
.wrap{max-width:1300px;margin:0 auto;padding:24px}
h1,h2,h3{line-height:1.3}
a{color:#2980b9;text-decoration:none}
a:hover{text-decoration:underline}

/* header */
.header{background:linear-gradient(135deg,#1a3a4f,#0f2a3d);color:#fff;
        padding:40px 36px;border-radius:12px 12px 0 0;text-align:center}
.header h1{font-size:2rem;letter-spacing:1px}
.header .sub{opacity:.75;margin-top:6px;font-size:.95rem}
.card{background:#fff;border-radius:10px;box-shadow:0 2px 12px rgba(0,0,0,.09);
      margin-bottom:24px;overflow:hidden}
.card-header{background:#1a3a4f;color:#fff;padding:14px 20px;font-size:1rem;font-weight:600}
.card-body{padding:20px}

/* stat tiles */
.stats{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}
.stat{flex:1;min-width:140px;background:#fff;border-radius:10px;padding:18px 20px;
      box-shadow:0 2px 8px rgba(0,0,0,.08);text-align:center}
.stat .num{font-size:2rem;font-weight:700}
.stat .lbl{font-size:.8rem;color:#777;margin-top:4px;text-transform:uppercase;letter-spacing:.5px}
.stat.critical{border-top:4px solid #c0392b;background:#fff5f5}
.stat.critical .num{color:#c0392b}
.stat.high    {border-top:4px solid #e55a00;background:#fff7f2}
.stat.high     .num{color:#e55a00}
.stat.medium  {border-top:4px solid #d4a500;background:#fffde8}
.stat.medium   .num{color:#c09000}
.stat.low      .num{color:#27ae60}
.stat.info     .num{color:#2980b9}
.stat.targets  .num{color:#1a3a4f}

/* badges */
.badge{display:inline-block;padding:3px 10px;border-radius:12px;
       font-size:.75rem;font-weight:600;color:#fff;white-space:nowrap}
.badge.critical{background:#c0392b}
.badge.high    {background:#e55a00}
.badge.medium  {background:#d4a500}
.badge.low     {background:#27ae60}
.badge.info    {background:#2980b9}

/* tables */
table{width:100%;border-collapse:collapse}
th{background:#f4f6f8;padding:10px 12px;text-align:left;
   font-size:.8rem;text-transform:uppercase;letter-spacing:.5px;
   border-bottom:2px solid #dde1e7;position:sticky;top:0}
td{padding:10px 12px;border-bottom:1px solid #eef0f3;vertical-align:top}
tr:hover td{background:#f9fbfd}
.tbl-wrap{overflow-x:auto;border-radius:8px;border:1px solid #dde1e7}

/* findings detail */
.finding-block{border:1px solid #dde1e7;border-radius:8px;margin-bottom:12px;overflow:hidden}
.finding-head{display:flex;align-items:center;gap:12px;padding:12px 16px;
              background:#f8f9fb;cursor:pointer;user-select:none}
.finding-head:hover{background:#eef2f7}
.finding-body{padding:16px;border-top:1px solid #eef0f3;display:none}
.finding-body.open{display:block}
.finding-body pre{background:#f4f6f8;border-radius:6px;padding:12px;
                  font-size:.82rem;white-space:pre-wrap;word-break:break-word}
.finding-body .section{margin-bottom:12px}
.finding-body .section h4{font-size:.82rem;text-transform:uppercase;
                           letter-spacing:.5px;color:#555;margin-bottom:4px}

/* target overview table */
.risk-bar{height:8px;border-radius:4px;background:#eee;overflow:hidden;min-width:80px}
.risk-fill{height:100%;border-radius:4px;background:#e67e22}

/* executive summary */
.exec-box{background:#1a3a4f;color:#fff;border-radius:10px;padding:28px 32px;
          margin-bottom:24px;line-height:1.8}
.exec-box h2{margin-bottom:12px;font-size:1.3rem}
.exec-box ul{padding-left:20px}
.exec-box li{margin-bottom:6px;font-size:.95rem}
.exec-box .highlight{color:#f39c12;font-weight:600}

/* responsive */
@media(max-width:700px){.stats{flex-direction:column}}
"""

JS = """
document.querySelectorAll('.finding-head').forEach(h=>{
  h.addEventListener('click',()=>{
    h.nextElementSibling.classList.toggle('open');
  });
});
function filterSev(val){
  document.querySelectorAll('.finding-block').forEach(b=>{
    const sev=b.dataset.sev;
    b.style.display=(val==='all'||sev===val)?'':'none';
  });
  document.querySelectorAll('.sev-btn').forEach(btn=>{
    btn.classList.toggle('active', btn.dataset.sev===val);
  });
}
"""


def sev_badge(sev: str) -> str:
    label = SEV_LABEL.get(sev, sev.upper())
    return f'<span class="badge {sev}">{label}</span>'


def esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_html(targets: list[dict], findings_all: list[dict],
                min_sev: str, generated_at: str) -> str:

    total_targets = len(targets)
    total_c = sum(t["summary"].get("critical", 0) for t in targets)
    total_a = sum(t["summary"].get("high", 0) for t in targets)
    total_m = sum(t["summary"].get("medium", 0) for t in targets)
    total_b = sum(t["summary"].get("low", 0) for t in targets)
    total_i = sum(t["summary"].get("info", 0) for t in targets)
    total_findings = sum(t["summary"].get("total", 0) for t in targets)

    shown_c = sum(1 for f in findings_all if f.get("severity") == "critical")
    shown_a = sum(1 for f in findings_all if f.get("severity") == "high")

    # ── executive summary ────────────────────────────────────────────────────
    top_targets = [t for t in targets if
                   t["summary"].get("critical", 0) + t["summary"].get("high", 0) > 0][:5]

    exec_items = []
    if shown_c:
        exec_items.append(
            f'<li><span class="highlight">{shown_c} finding(s) CRÍTICO(s)</span> '
            f'requerem remediação imediata.</li>')
    if shown_a:
        exec_items.append(
            f'<li><span class="highlight">{shown_a} finding(s) ALTO(s)</span> '
            f'devem ser corrigidos com prioridade.</li>')
    if top_targets:
        domains = ", ".join(f"<code>{esc(t['domain'])}</code>" for t in top_targets)
        exec_items.append(f"<li>Alvos com maior exposição: {domains}.</li>")
    if not exec_items:
        exec_items.append(
            "<li>Nenhum finding crítico ou alto identificado nos alvos analisados.</li>")

    exec_html = f"""
<div class="exec-box">
  <h2>Sumário Executivo</h2>
  <ul>
    {''.join(exec_items)}
    <li>{total_targets} alvo(s) analisado(s) — {total_findings} finding(s) totais.</li>
    <li>Relatório gerado em: {generated_at}</li>
  </ul>
</div>"""

    # ── stat tiles ───────────────────────────────────────────────────────────
    stats_html = f"""
<div class="stats">
  <div class="stat targets"><div class="num">{total_targets}</div><div class="lbl">Alvos</div></div>
  <div class="stat critical"><div class="num">{total_c}</div><div class="lbl">Críticos</div></div>
  <div class="stat high"><div class="num">{total_a}</div><div class="lbl">Altos</div></div>
  <div class="stat medium"><div class="num">{total_m}</div><div class="lbl">Médios</div></div>
  <div class="stat low"><div class="num">{total_b}</div><div class="lbl">Baixos</div></div>
  <div class="stat info"><div class="num">{total_i}</div><div class="lbl">Info</div></div>
</div>"""

    # ── targets overview table ───────────────────────────────────────────────
    rows = []
    for t in targets:
        s = t["summary"]
        c = s.get("critical", 0)
        a = s.get("high", 0)
        m = s.get("medium", 0)
        risk = t.get("risk_score", 0)
        fill = min(risk, 100)
        waf = "✓" if t.get("waf") else "✗"
        rows.append(f"""
<tr>
  <td><strong>{esc(t['domain'])}</strong></td>
  <td>{sev_badge('critical') if c else ''} {c if c else '-'}</td>
  <td>{sev_badge('high') if a else ''} {a if a else '-'}</td>
  <td>{m if m else '-'}</td>
  <td>
    <div class="risk-bar"><div class="risk-fill" style="width:{fill}%"></div></div>
    <small>{risk}</small>
  </td>
  <td>{waf}</td>
  <td><small>{esc(t['timestamp'][:10]) if t['timestamp'] else '-'}</small></td>
</tr>""")

    targets_table = f"""
<div class="card">
  <div class="card-header">Visão Geral por Alvo</div>
  <div class="card-body">
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>Domínio</th><th>Crítico</th><th>Alto</th>
            <th>Médio</th><th>Risk Score</th><th>WAF</th><th>Data</th>
          </tr>
        </thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </div>
  </div>
</div>"""

    # ── findings filtrados C/A ───────────────────────────────────────────────
    sev_filter_label = SEV_LABEL.get(min_sev, min_sev.upper())

    filter_btns = """
<div style="margin-bottom:16px;display:flex;gap:8px;flex-wrap:wrap">
  <button class="sev-btn active" data-sev="all"
    onclick="filterSev('all')"
    style="padding:6px 14px;border-radius:20px;border:1px solid #ccc;
           cursor:pointer;font-size:.82rem;background:#1a3a4f;color:#fff">
    Todos
  </button>"""
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = sum(1 for f in findings_all if f.get("severity") == sev)
        if count:
            filter_btns += f"""
  <button class="sev-btn" data-sev="{sev}"
    onclick="filterSev('{sev}')"
    style="padding:6px 14px;border-radius:20px;border:1px solid {SEV_COLOR[sev]};
           cursor:pointer;font-size:.82rem;color:{SEV_COLOR[sev]}">
    {SEV_LABEL[sev]} ({count})
  </button>"""
    filter_btns += "</div>"

    finding_blocks = []
    for f in findings_all:
        sev = f.get("severity", "info")
        name = esc(f.get("name", "?"))
        domain = esc(f.get("_domain", ""))
        url = esc(f.get("url", ""))
        source = esc(f.get("source", ""))
        desc = esc(f.get("description", ""))
        remediation = esc(enrich_remediation(f.get("name", ""), f.get("remediation", "")))
        cves = f.get("cve_ids", [])
        cvss = f.get("cvss")
        epss = f.get("epss")
        in_kev = f.get("in_kev", False)

        meta_parts = [f"<strong>Fonte:</strong> {source}", f"<strong>URL:</strong> {url}"]
        if cves:
            meta_parts.append("<strong>CVEs:</strong> " + ", ".join(cves))
        if cvss:
            meta_parts.append(f"<strong>CVSS:</strong> {cvss:.1f}")
        if epss:
            meta_parts.append(f"<strong>EPSS:</strong> {epss:.3f}")
        if in_kev:
            meta_parts.append('<span style="color:#c0392b;font-weight:700">⚠ KEV</span>')

        finding_blocks.append(f"""
<div class="finding-block" data-sev="{sev}">
  <div class="finding-head">
    {sev_badge(sev)}
    <span style="font-weight:600;flex:1">{name}</span>
    <span style="color:#888;font-size:.82rem">{domain}</span>
    <span style="color:#aaa;margin-left:8px">▼</span>
  </div>
  <div class="finding-body">
    <div class="section">
      <h4>Metadados</h4>
      <p>{'  |  '.join(meta_parts)}</p>
    </div>
    {'<div class="section"><h4>Descrição</h4><pre>' + desc + '</pre></div>' if desc else ''}
    {'<div class="section"><h4>Remediação</h4><pre>' + remediation + '</pre></div>' if remediation else ''}
  </div>
</div>""")

    findings_card = f"""
<div class="card">
  <div class="card-header">
    Findings — {sev_filter_label}+ ({len(findings_all)} exibidos)
  </div>
  <div class="card-body">
    {filter_btns}
    {''.join(finding_blocks) if finding_blocks else '<p style="color:#888">Nenhum finding nesta severidade.</p>'}
  </div>
</div>"""

    # ── montagem final ───────────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SWARM — Relatório Consolidado</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="header">
      <h1>SWARM — Relatório Consolidado</h1>
      <div class="sub">
        Severidade mínima exibida: <strong>{sev_filter_label}</strong>
        &nbsp;·&nbsp; Gerado em: {generated_at}
      </div>
    </div>
  </div>
  {exec_html}
  {stats_html}
  {targets_table}
  {findings_card}
</div>
<script>{JS}</script>
</body>
</html>"""


def render_executive_txt(targets: list[dict], findings_all: list[dict],
                         generated_at: str) -> str:
    total_c = sum(t["summary"].get("critical", 0) for t in targets)
    total_a = sum(t["summary"].get("high", 0) for t in targets)
    total_m = sum(t["summary"].get("medium", 0) for t in targets)

    lines = [
        "=" * 64,
        "  SWARM — SUMÁRIO EXECUTIVO",
        f"  Gerado: {generated_at}",
        "=" * 64,
        f"  Alvos analisados : {len(targets)}",
        f"  Críticos         : {total_c}",
        f"  Altos            : {total_a}",
        f"  Médios           : {total_m}",
        "",
        "  ALVOS COM MAIOR EXPOSIÇÃO:",
    ]
    for t in targets:
        s = t["summary"]
        c, a, m = s.get("critical", 0), s.get("high", 0), s.get("medium", 0)
        if c + a == 0:
            continue
        lines.append(f"    {t['domain']:<45} C={c} A={a} M={m}")

    lines += ["", "  FINDINGS CRÍTICOS E ALTOS:", ""]
    for f in findings_all:
        if f.get("severity") not in ("critical", "high"):
            continue
        lines.append(f"  [{SEV_LABEL[f['severity']]}] {f.get('name','?')}")
        lines.append(f"    Alvo : {f.get('_domain','')}")
        lines.append(f"    URL  : {f.get('url','')}")
        lines.append(f"    Fonte: {f.get('source','')}")
        lines.append("")

    lines += ["=" * 64]
    return "\n".join(lines)

# ─── main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Consolida relatórios SWARM em um único HTML filtrado por severidade."
    )
    parser.add_argument("paths", nargs="*",
                        help="Caminhos para findings.json ou diretórios de scan")
    parser.add_argument("-d", "--batch-dir",
                        help="Diretório de batch (scan_batch_*/)")
    parser.add_argument("--min-severity", default="high",
                        choices=["critical", "high", "medium", "low", "info"],
                        help="Severidade mínima para exibir (default: high)")
    parser.add_argument("--out", default="relatorio_consolidado_ch.html",
                        help="Arquivo HTML de saída")
    parser.add_argument("--exec-out", default="sumario_executivo_ch.txt",
                        help="Arquivo de sumário executivo de saída")
    args = parser.parse_args()

    paths = resolve_paths(args.paths, args.batch_dir)
    if not paths:
        print("[!] Nenhum findings.json encontrado.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] {len(paths)} arquivo(s) encontrado(s)", file=sys.stderr)
    targets, findings_all = collect(paths, args.min_severity)
    print(f"[*] {len(targets)} alvo(s) carregado(s) | "
          f"{len(findings_all)} finding(s) filtrados (>= {args.min_severity})", file=sys.stderr)

    generated_at = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    html = render_html(targets, findings_all, args.min_severity, generated_at)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[✓] Relatório HTML : {args.out}", file=sys.stderr)

    txt = render_executive_txt(targets, findings_all, generated_at)
    with open(args.exec_out, "w", encoding="utf-8") as f:
        f.write(txt)
    print(f"[✓] Sumário exec   : {args.exec_out}", file=sys.stderr)

    # imprime sumário no stdout
    print(txt)


if __name__ == "__main__":
    main()

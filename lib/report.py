#!/usr/bin/env python3
"""
Stiglitz RED — Gerador de relatório HTML.
Consolida outputs de todas as fases em um relatório acionável.

Uso: python3 report.py <outdir> <target> <profile> <duration_sec>
"""
import csv
import html
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

esc = html.escape


def _read_csv(path):
    try:
        with open(path, newline="") as f:
            return list(csv.DictReader(f))
    except Exception:
        return []


def _read_text(path):
    try:
        return Path(path).read_text().strip()
    except Exception:
        return ""


def _read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return None


def _badge(label, color):
    return f'<span class="badge" style="background:{color}">{esc(label)}</span>'


def _severity_color(sev):
    return {
        "CRITICAL": "#c0392b", "HIGH": "#e67e22",
        "MEDIUM":   "#f1c40f", "LOW":  "#27ae60",
        "INFO":     "#7f8c8d",
    }.get(sev.upper(), "#7f8c8d")


# ── Seções do relatório ───────────────────────────────────────────────────────

def _section_sqli(outdir):
    rows = _read_csv(os.path.join(outdir, "sqli_results.csv"))
    if not rows:
        return "<p>Nenhum resultado SQLi.</p>"

    vulns = [r for r in rows if r.get("status") == "VULNERABLE"]
    total = len(rows)

    html_rows = ""
    for r in rows:
        is_vuln = r.get("status") == "VULNERABLE"
        badge = _badge("VULNERÁVEL", "#c0392b") if is_vuln else _badge("LIMPO", "#27ae60")
        html_rows += f"""
        <tr>
            <td>{badge}</td>
            <td style="word-break:break-all">{esc(r.get('url',''))}</td>
            <td>{esc(r.get('dbms',''))}</td>
            <td>{esc(r.get('injection_type',''))}</td>
            <td><code>{esc(r.get('log_file',''))}</code></td>
        </tr>"""

    return f"""
    <p><strong>{len(vulns)}</strong> vulnerável(is) de <strong>{total}</strong> testada(s)</p>
    <table>
        <tr><th>Status</th><th>URL</th><th>DBMS</th><th>Tipo</th><th>Log</th></tr>
        {html_rows}
    </table>"""


def _section_brute(outdir):
    rows = _read_csv(os.path.join(outdir, "brute_results.csv"))
    if not rows:
        return "<p>Nenhum resultado de brute force.</p>"

    found = [r for r in rows if r.get("status") == "FOUND"]

    if not found:
        return f"<p>Testado(s) {len(rows)} serviço(s) — nenhuma credencial encontrada.</p>"

    html_rows = ""
    for r in found:
        html_rows += f"""
        <tr>
            <td>{_badge('CREDENCIAL', '#c0392b')}</td>
            <td>{esc(r.get('host',''))}:{esc(r.get('port',''))}</td>
            <td>{esc(r.get('service',''))}</td>
            <td><code>{esc(r.get('username',''))}</code></td>
            <td><code>{esc(r.get('password',''))}</code></td>
        </tr>"""

    return f"""
    <p>{_badge(f'{len(found)} credencial(is) encontrada(s)', '#c0392b')}</p>
    <table>
        <tr><th>Status</th><th>Host:Porta</th><th>Serviço</th><th>Usuário</th><th>Senha</th></tr>
        {html_rows}
    </table>"""


def _section_msf(outdir):
    msf_dir = os.path.join(outdir, "msf")
    vulns = _read_csv(os.path.join(msf_dir, "vulns.csv"))
    creds = _read_csv(os.path.join(msf_dir, "creds.csv"))

    if not vulns and not creds:
        return "<p>Nenhum resultado Metasploit ou fase não executada.</p>"

    parts = []
    if creds:
        html_rows = "".join(
            f"<tr><td>{esc(c.get('host',''))}</td>"
            f"<td>{esc(c.get('service_name',''))}</td>"
            f"<td><code>{esc(c.get('public',''))}</code></td>"
            f"<td><code>{esc(c.get('private',''))}</code></td></tr>"
            for c in creds
        )
        parts.append(f"""
        <h4>Credenciais ({len(creds)})</h4>
        <table>
            <tr><th>Host</th><th>Serviço</th><th>Usuário</th><th>Segredo</th></tr>
            {html_rows}
        </table>""")

    if vulns:
        html_rows = "".join(
            f"<tr><td>{esc(v.get('host',''))}</td>"
            f"<td>{esc(v.get('name',''))}</td>"
            f"<td>{esc(v.get('refs',''))}</td></tr>"
            for v in vulns
        )
        parts.append(f"""
        <h4>Vulnerabilidades confirmadas ({len(vulns)})</h4>
        <table>
            <tr><th>Host</th><th>Módulo</th><th>Referências</th></tr>
            {html_rows}
        </table>""")

    return "\n".join(parts)


def _section_web(outdir):
    filtered = _read_text(os.path.join(outdir, "web", "nikto_filtered.txt"))
    if not filtered:
        return "<p>Nenhum finding Nikto acima do limiar de severidade ou fase não executada.</p>"

    lines = [l for l in filtered.splitlines() if l.strip()]
    items = "".join(f"<li>{esc(l)}</li>" for l in lines)
    return f"<p>{len(lines)} finding(s):</p><ul>{items}</ul>"


def _section_cves(outdir):
    cves_file = os.path.join(outdir, "cves_found.txt")
    cves = [l.strip() for l in _read_text(cves_file).splitlines() if l.strip()]
    if not cves:
        return "<p>Nenhum CVE identificado.</p>"

    items = "".join(
        f'<li><a href="https://nvd.nist.gov/vuln/detail/{esc(c)}" target="_blank">{esc(c)}</a></li>'
        for c in cves
    )
    return f"<p>{len(cves)} CVE(s) encontrado(s) pelo Stiglitz:</p><ul>{items}</ul>"


# ── HTML template ─────────────────────────────────────────────────────────────

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', Arial, sans-serif; padding: 2rem; }
h1 { color: #58a6ff; margin-bottom: .5rem; }
h2 { color: #79c0ff; margin: 2rem 0 .75rem; border-bottom: 1px solid #30363d; padding-bottom: .4rem; }
h3 { color: #d2a8ff; margin: 1.5rem 0 .5rem; }
h4 { color: #e3b341; margin: 1rem 0 .4rem; }
.meta { color: #8b949e; font-size: .9rem; margin-bottom: 2rem; }
table { width: 100%; border-collapse: collapse; margin: .5rem 0 1rem; font-size: .875rem; }
th { background: #161b22; color: #79c0ff; padding: .5rem .75rem; text-align: left; border: 1px solid #30363d; }
td { padding: .4rem .75rem; border: 1px solid #21262d; vertical-align: top; }
tr:hover td { background: #161b22; }
code { background: #161b22; padding: .1rem .3rem; border-radius: 3px; font-size: .85rem; color: #e3b341; }
ul { padding-left: 1.5rem; margin: .5rem 0; }
li { margin: .3rem 0; line-height: 1.4; }
.badge { display: inline-block; padding: .2rem .55rem; border-radius: 4px; font-size: .75rem;
         font-weight: bold; color: #fff; white-space: nowrap; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 1rem; margin: 1rem 0 2rem; }
.stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; text-align: center; }
.stat-card .number { font-size: 2rem; font-weight: bold; color: #58a6ff; }
.stat-card .label { font-size: .8rem; color: #8b949e; margin-top: .3rem; }
a { color: #58a6ff; }
"""


def generate_report(outdir, target, profile, duration_sec):
    now = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S UTC")
    duration = f"{int(duration_sec) // 60}m {int(duration_sec) % 60}s"

    summary = _read_json(os.path.join(outdir, "ingest_summary.json")) or {}
    sqli_rows = _read_csv(os.path.join(outdir, "sqli_results.csv"))
    sqli_vuln = sum(1 for r in sqli_rows if r.get("status") == "VULNERABLE")
    brute_rows = _read_csv(os.path.join(outdir, "brute_results.csv"))
    brute_found = sum(1 for r in brute_rows if r.get("status") == "FOUND")
    cves = [l for l in _read_text(os.path.join(outdir, "cves_found.txt")).splitlines() if l.strip()]

    stats = f"""
    <div class="summary-grid">
        <div class="stat-card"><div class="number">{summary.get('sqli_urls', 0)}</div><div class="label">URLs testadas (SQLi)</div></div>
        <div class="stat-card"><div class="number" style="color:#c0392b">{sqli_vuln}</div><div class="label">SQLi confirmados</div></div>
        <div class="stat-card"><div class="number" style="color:#c0392b">{brute_found}</div><div class="label">Credenciais encontradas</div></div>
        <div class="stat-card"><div class="number">{len(cves)}</div><div class="label">CVEs identificados</div></div>
        <div class="stat-card"><div class="number">{summary.get('services', 0)}</div><div class="label">Serviços mapeados</div></div>
    </div>"""

    body = f"""
    <h1>Stiglitz RED — Relatório de Exploração</h1>
    <p class="meta">
        Alvo: <strong>{esc(target)}</strong> &nbsp;|&nbsp;
        Perfil: <strong>{esc(profile)}</strong> &nbsp;|&nbsp;
        Gerado: {now} &nbsp;|&nbsp;
        Duração: {duration}
    </p>

    <h2>Resumo Executivo</h2>
    {stats}

    <h2>Fase 2 — SQL Injection</h2>
    {_section_sqli(outdir)}

    <h2>Fase 3 — Metasploit</h2>
    {_section_msf(outdir)}

    <h2>Fase 4 — Brute Force</h2>
    {_section_brute(outdir)}

    <h2>Fase 5 — Web Scanner (Nikto)</h2>
    {_section_web(outdir)}

    <h2>CVEs Identificados pelo Stiglitz</h2>
    {_section_cves(outdir)}
    """

    report_html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Stiglitz RED — {esc(target)}</title>
    <style>{CSS}</style>
</head>
<body>{body}</body>
</html>"""

    out_path = os.path.join(outdir, "stiglitz_red_report.html")
    Path(out_path).write_text(report_html)
    return out_path


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print(f"Uso: {sys.argv[0]} <outdir> <target> <profile> <duration_sec>")
        sys.exit(1)
    path = generate_report(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    print(f"[report] Relatório gerado: {path}")

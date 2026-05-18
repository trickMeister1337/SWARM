#!/usr/bin/env python3
"""
SWARM RED v7.0 — Gerador de Relatório Red Team (Big4 Style).

Uso: python3 report_generator.py <outdir> <target> <profile> <total> <success> <failed> <version>

Lê dados consolidados de evidence.py e gera relatorio_swarm_red.html.
"""
import sys
import os
import html as H
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evidence import collect_and_consolidate
from poc_generator import collect_pocs, generate_verify_script

esc = lambda s: H.escape(str(s)) if s else ""


def generate_report(
    outdir: str, target: str, profile: str,
    total: int, success: int, failed: int, version: str
) -> str:
    now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    data = collect_and_consolidate(outdir)

    pocs = collect_pocs(outdir)
    if pocs:
        generate_verify_script(outdir, pocs, target)

    findings      = data["findings"]
    sqli_results  = data["sqli_results"]
    xss_results   = data["xss_results"]
    msf_log       = data["msf_log"]
    hydra_results = data["hydra_results"]
    nikto_findings= data["nikto_findings"]
    cves          = data["cves"]
    services      = data["services"]
    log_content   = data["log_content"]
    zap_hc        = data["zap_hc"]
    ssd           = data["searchsploit"]
    subdomains    = data["subdomains"]

    st = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        if f["sev"] in st: st[f["sev"]] += 1
    tf = sum(st.values())
    rs = min(100, st["Critical"] * 30 + st["High"] * 15 + st["Medium"] * 5 + st["Low"])

    if rs >= 70:   rl_, rc_ = "CRÍTICO", "#7a2e2e"
    elif rs >= 40: rl_, rc_ = "ALTO",    "#b34e4e"
    elif rs >= 15: rl_, rc_ = "MÉDIO",   "#d4833a"
    else:          rl_, rc_ = "BAIXO",   "#4a7c8c"

    pl = {"staging": "Staging/Homolog", "lab": "Laboratório", "production": "Produção"}
    sqli_vc       = len([r for r in sqli_results if r["vulnerable"]])
    xss_vc        = len([f for f in findings if f.get("type") == "xss"])
    msf_sess      = msf_log.lower().count("session") if msf_log else 0
    total_endpoints = sum(f.get("count", 1) for f in findings)

    # Detect mode from existence of recon dir
    mode = "BLACKBOX" if os.path.isdir(f"{outdir}/recon") and subdomains else "SWARM"

    html = _build_html(
        target=target, profile=profile, version=version, now=now, mode=mode,
        total=total, success=success, st=st, tf=tf, rs=rs, rl_=rl_, rc_=rc_,
        pl=pl, sqli_vc=sqli_vc, xss_vc=xss_vc, msf_sess=msf_sess,
        total_endpoints=total_endpoints,
        findings=findings, sqli_results=sqli_results, xss_results=xss_results,
        msf_log=msf_log, hydra_results=hydra_results, nikto_findings=nikto_findings,
        cves=cves, services=services, log_content=log_content,
        zap_hc=zap_hc, ssd=ssd, outdir=outdir, pocs=pocs, subdomains=subdomains,
    )

    report_path = f"{outdir}/relatorio_swarm_red.html"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    return report_path


def _build_html(**k) -> str:
    CSS = """
body{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:20px;background:#f0f2f5}
.ctn{max-width:1200px;margin:0 auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,.1)}
.hdr{background:#1a3a4f;color:#fff;padding:40px 30px;text-align:center}
.hdr h1{margin:0 0 5px;font-size:1.6em;letter-spacing:2px;text-transform:uppercase}
.hdr .sub{font-size:1.1em;opacity:.9;margin:5px 0}.hdr .meta{font-size:.85em;opacity:.7}
.hdr .cls{display:inline-block;border:2px solid #e74c3c;color:#e74c3c;padding:4px 16px;border-radius:4px;font-weight:700;font-size:.8em;margin-top:12px;letter-spacing:1px}
.cnt{padding:30px}
h2{color:#1a3a4f;border-bottom:2px solid #e0e0e0;padding-bottom:8px;margin-top:30px}
h3{color:#2c3e50;margin-top:20px}
.sts{display:flex;gap:12px;margin:20px 0;flex-wrap:wrap}
.sc{flex:1;padding:18px;text-align:center;color:#fff;border-radius:8px;min-width:85px}
.sc .n{font-size:32px;font-weight:bold}.sc .l{font-size:.75em;text-transform:uppercase;letter-spacing:.5px;opacity:.9}
.s-cr{background:#7a2e2e}.s-hi{background:#b34e4e}.s-me{background:#d4833a}.s-lo{background:#4a7c8c}.s-in{background:#6e8f72}.s-te{background:#2c3e50}
.ib{background:#e8f4f8;padding:15px 20px;border-radius:8px;margin:15px 0;border-left:4px solid #1a3a4f}
.ib.n{border-left-color:#2c3e50;background:#f9f9f9}.ib.g{border-left-color:#27ae60;background:#f0faf4}
table{width:100%;border-collapse:collapse;margin:10px 0}
th,td{border:1px solid #ddd;padding:10px;text-align:left;vertical-align:top}
th{background:#f5f5f5;font-weight:600;font-size:.85em}
.fd{border:1px solid #ddd;margin:18px 0;padding:20px;border-radius:8px;background:#fafafa}
.fd.Critical{border-left:10px solid #7a2e2e}.fd.High{border-left:10px solid #b34e4e}
.fd.Medium{border-left:10px solid #d4833a}.fd.Low{border-left:10px solid #4a7c8c}
.fd h3{margin-top:0}
.sb{display:inline-block;padding:3px 10px;border-radius:4px;font-size:.75em;font-weight:700;color:#fff}
.sb-cr{background:#7a2e2e}.sb-hi{background:#b34e4e}.sb-me{background:#d4833a}.sb-lo{background:#4a7c8c}.sb-in{background:#6e8f72}
.tb{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.7em;font-weight:700;margin-left:6px;color:#fff}
.t-sq{background:#e67e22}.t-ms{background:#2980b9}.t-hy{background:#8e44ad}.t-nk{background:#27ae60}.t-df{background:#c0392b}
.ev{background:#2d3436;color:#dfe6e9;padding:14px;border-radius:6px;font-family:'Cascadia Code',monospace;font-size:.82em;overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:400px;margin:8px 0;line-height:1.5}
.rb{background:#e0e0e0;border-radius:4px;height:14px;margin:8px 0}.ri{height:14px;border-radius:4px}
code{background:#f4f4f4;padding:1px 4px;border-radius:3px;font-size:.85em}
.ft{background:#f5f5f5;padding:20px;text-align:center;font-size:.8em;color:#666}
.toc{background:#f8f9fa;padding:15px 20px;border-radius:8px;margin:15px 0}.toc a{color:#1a3a4f;text-decoration:none}.toc a:hover{text-decoration:underline}.toc li{margin:4px 0}
.pt{display:inline-block;background:#1a3a4f;color:#fff;padding:2px 8px;border-radius:3px;font-size:.7em;margin-right:6px}
.tl{border-left:3px solid #1a3a4f;margin:15px 0;padding:0}
.ti{padding:10px 20px;position:relative;margin-left:15px}
.ti::before{content:'';position:absolute;left:-24px;top:15px;width:12px;height:12px;border-radius:50%;background:#1a3a4f}
.ti.ok::before{background:#27ae60}.ti.no::before{background:#95a5a6}
.cnt-badge{background:#555;color:#fff;padding:2px 10px;border-radius:10px;font-size:.7em;font-weight:700}
.ep-list{background:#f8f9fa;border:1px solid #e0e0e0;border-radius:6px;padding:10px 14px;margin:8px 0;font-size:.85em;max-height:200px;overflow-y:auto}
.ep-list li{margin:2px 0;font-family:monospace;font-size:.9em}
.mode-badge{display:inline-block;background:#27ae60;color:#fff;padding:3px 12px;border-radius:4px;font-size:.75em;font-weight:700;margin-left:10px}
"""
    h = f"""<!DOCTYPE html><html lang="pt-br"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SWARM RED — {esc(k['target'])}</title><style>{CSS}</style></head>
<body><div class="ctn">
<div class="hdr">
<h1>SWARM RED — Red Team Engagement Report
<span class="mode-badge">{k['mode']}</span></h1>
<div class="sub">{esc(k['target'])}</div>
<div class="meta">Data: {k['now']} | Perfil: {k['profile'].upper()} ({k['pl'].get(k['profile'],k['profile'])}) | v{k['version']}</div>
<div class="cls">CONFIDENCIAL — RED TEAM — DISTRIBUIÇÃO RESTRITA</div></div>
<div class="cnt">
<div class="toc"><strong>Índice</strong><ol>
<li><a href="#s1">Sumário Executivo</a></li><li><a href="#s2">Escopo e Metodologia</a></li>
<li><a href="#s3">Superfície de Ataque</a></li><li><a href="#s4">Narrativa de Ataque</a></li>
<li><a href="#s5">Achados e Vulnerabilidades</a></li><li><a href="#s6">Recomendações</a></li>
<li><a href="#s7">Conclusão</a></li><li><a href="#s8">Provas de Conceito (PoC)</a></li>
<li><a href="#s9">Apêndices</a></li></ol></div>"""

    h += _section_exec_summary(**k)
    h += _section_scope(**k)
    h += _section_surface(**k)
    h += _section_narrative(**k)
    h += _section_findings(**k)
    h += _section_recommendations(**k)
    h += _section_conclusion(**k)
    h += _section_poc(**k)
    h += _section_appendix(**k)

    h += f'</div><div class="ft">SWARM RED v{k["version"]} — Red Team Report | {k["now"]} | <strong>CONFIDENCIAL</strong></div></div></body></html>'
    return h


def _section_exec_summary(**k) -> str:
    h = f"""<h2 id="s1">1. Sumário Executivo</h2>
<div class="sts">
<div class="sc s-te"><div class="n">{k['total']}</div><div class="l">Testes</div></div>
<div class="sc s-cr"><div class="n">{k['st']['Critical']}</div><div class="l">Crítico</div></div>
<div class="sc s-hi"><div class="n">{k['st']['High']}</div><div class="l">Alto</div></div>
<div class="sc s-me"><div class="n">{k['st']['Medium']}</div><div class="l">Médio</div></div>
<div class="sc s-lo"><div class="n">{k['st']['Low']}</div><div class="l">Baixo</div></div>
<div class="sc s-in"><div class="n">{k['st']['Info']}</div><div class="l">Info</div></div></div>
<div class="ib"><p><strong>Risco:</strong> {k['rs']}/100 — <span style="color:{k['rc_']};font-weight:bold">{k['rl_']}</span></p>
<div class="rb"><div class="ri" style="background:{k['rc_']};width:{k['rs']}%"></div></div></div>
<div class="ib n">
<p>O SWARM RED executou um engagement de Red Team contra <strong>{esc(k['target'])}</strong>
(modo: {k['mode']}, perfil: {k['pl'].get(k['profile'], k['profile'])}), realizando {k['total']} teste(s).</p>"""
    if k['success'] > 0:
        h += f'\n<p><strong style="color:#7a2e2e">Confirmados {k["success"]} exploit(s)</strong> afetando {k["total_endpoints"]} endpoint(s).</p>'
    else:
        h += '\n<p>Nenhum exploit confirmado. Os controles resistiram às técnicas aplicadas.</p>'
    if k['findings']:
        parts = []
        if k['st']['Critical']: parts.append(f'{k["st"]["Critical"]} crítico(s)')
        if k['st']['High']:     parts.append(f'{k["st"]["High"]} alto(s)')
        if k['st']['Medium']:   parts.append(f'{k["st"]["Medium"]} médio(s)')
        h += f'\n<p><strong>{k["tf"]} achado(s):</strong> {", ".join(parts) or "nenhum"}.</p>'
    h += '\n<p>Recomendações na seção 6.</p></div>\n'
    return h


def _section_scope(**k) -> str:
    mode = k.get("mode", "SWARM")
    approach = "Black-box — sem conhecimento prévio do alvo" if mode == "BLACKBOX" else "Grey-box — dados do SWARM scan"
    h = f'''<h2 id="s2">2. Escopo e Metodologia</h2>
<div class="ib"><p><strong>Alvo:</strong> <code>{esc(k['target'])}</code> | <strong>Abordagem:</strong> {approach} | <strong>Metodologia:</strong> PTES + OWASP Testing Guide + MITRE ATT&CK</p></div>
<table><tr><th>Ferramenta</th><th>Tática MITRE</th><th>Propósito</th></tr>
<tr><td><strong>subfinder + httpx</strong></td><td><span class="pt">T1590</span></td><td>Reconhecimento — descoberta de subdomínios e superfície</td></tr>
<tr><td><strong>nmap</strong></td><td><span class="pt">T1046</span></td><td>Mapeamento de rede e serviços</td></tr>
<tr><td><strong>katana + ffuf</strong></td><td><span class="pt">T1083</span></td><td>Crawling e fuzzing de endpoints</td></tr>
<tr><td><strong>sqlmap</strong></td><td><span class="pt">T1190</span></td><td>SQL Injection — crawl, forms, parâmetros</td></tr>
<tr><td><strong>dalfox</strong></td><td><span class="pt">T1059.007</span></td><td>Cross-Site Scripting (XSS) — reflected, stored, DOM</td></tr>
<tr><td><strong>Hydra</strong></td><td><span class="pt">T1110</span></td><td>Brute force — SSH, FTP, MySQL, PostgreSQL, HTTP</td></tr>
<tr><td><strong>Metasploit</strong></td><td><span class="pt">T1210</span></td><td>Exploração de CVEs confirmados</td></tr>
<tr><td><strong>Nikto</strong></td><td><span class="pt">T1046</span></td><td>Misconfigurations web e arquivos padrão</td></tr>
<tr><td><strong>SearchSploit</strong></td><td><span class="pt">T1588.005</span></td><td>Exploits públicos para CVEs</td></tr></table>'''
    return h


def _section_surface(**k) -> str:
    h = '<h2 id="s3">3. Superfície de Ataque</h2>\n'

    # Subdomains (blackbox recon)
    if k.get("subdomains"):
        h += f'<h3>Subdomínios Descobertos ({len(k["subdomains"])})</h3>\n'
        h += '<div class="ep-list"><ul>\n'
        for s in k["subdomains"][:50]:
            h += f'<li>{esc(s)}</li>\n'
        if len(k["subdomains"]) > 50:
            h += f'<li><em>... e mais {len(k["subdomains"]) - 50}</em></li>\n'
        h += '</ul></div>\n'

    # Services
    if k["services"]:
        h += '<h3>Serviços Abertos</h3>\n'
        h += '<table><tr><th>Porta</th><th>Serviço</th><th>Versão</th></tr>\n'
        for s in k["services"]:
            p = s.split()
            h += f'<tr><td><code>{esc(p[0] if p else "?")}</code></td><td>{esc(p[1] if len(p)>1 else "?")}</td><td>{esc(" ".join(p[2:]) if len(p)>2 else "")}</td></tr>\n'
        h += '</table>\n'

    # CVEs
    if k["cves"]:
        h += f'<h3>CVEs Identificados ({len(k["cves"])})</h3>\n'
        h += '<table><tr><th>CVE</th><th>Exploits Públicos</th></tr>\n'
        for cv in k["cves"]:
            ex = k["ssd"].get(cv, [])
            if ex:
                h += f'<tr><td><strong style="color:#7a2e2e">{esc(cv)}</strong></td><td>{", ".join(esc(e.get("Title","")[:50]) for e in ex[:3])}</td></tr>\n'
            else:
                h += f'<tr><td><code>{esc(cv)}</code></td><td style="color:#999">—</td></tr>\n'
        h += '</table>\n'

    if not k["services"] and not k["cves"] and not k.get("subdomains"):
        h += '<div class="ib n"><p>Nenhum dado de superfície coletado.</p></div>\n'

    return h


def _section_narrative(**k) -> str:
    mode = k.get("mode", "SWARM")
    h = '<h2 id="s4">4. Narrativa de Ataque</h2><div class="tl">\n'

    if mode == "BLACKBOX":
        n_subs = len(k.get("subdomains", []))
        h += f'<div class="ti {"ok" if n_subs>1 else "no"}"><strong>Fase 1 — Reconhecimento</strong><br>'
        h += f'{n_subs} subdomínio(s) descoberto(s).</div>\n'
    else:
        h += f'<div class="ti ok"><strong>Fase 1 — Ingestão SWARM</strong><br>{len(k["services"])} serviço(s), {len(k["cves"])} CVE(s).</div>\n'

    h += f'<div class="ti {"ok" if k["sqli_vc"]>0 else "no"}"><strong>Fase SQLi (sqlmap)</strong><br>'
    if k["sqli_vc"] > 0: h += f'{k["sqli_vc"]} endpoint(s) vulnerável(is).'
    elif k["sqli_results"]: h += f'{len(k["sqli_results"])} testado(s) — nenhum vulnerável.'
    else: h += 'Modo discovery.'
    h += '</div>\n'

    h += f'<div class="ti {"ok" if k["xss_vc"]>0 else "no"}"><strong>Fase XSS (dalfox)</strong><br>'
    if k["xss_vc"] > 0: h += f'{k["xss_vc"]} XSS confirmado(s).'
    elif k.get("xss_results"): h += f'{len(k["xss_results"])} testado(s) — nenhum vulnerável.'
    else: h += 'Não executada ou sem resultados.'
    h += '</div>\n'

    h += f'<div class="ti {"ok" if k["msf_sess"]>0 else "no"}"><strong>Fase Metasploit</strong><br>'
    if k["msf_sess"] > 0: h += f'{k["msf_sess"]} sessão(ões) abertas.'
    elif k["msf_log"]: h += 'Módulos executados.'
    else: h += 'Não executada.'
    h += '</div>\n'

    h += f'<div class="ti {"ok" if k["hydra_results"] else "no"}"><strong>Fase Brute Force (Hydra)</strong><br>'
    if k["hydra_results"]: h += f'Credenciais em {len(k["hydra_results"])} serviço(s).'
    else: h += 'Sem credenciais fracas identificadas.'
    h += '</div>\n'

    h += f'<div class="ti {"ok" if k["nikto_findings"] else "no"}"><strong>Fase Web (Nikto)</strong><br>'
    if k["nikto_findings"]: h += f'{len(k["nikto_findings"])} achado(s) de misconfiguration.'
    else: h += 'Sem achados de misconfiguration.'
    h += '</div>\n'

    h += f'<div class="ti ok"><strong>Consolidação</strong><br>{len(k["cves"])} CVE(s), {len(k["ssd"])} com exploit(s) público(s).</div>\n</div>\n'
    return h


def _section_findings(**k) -> str:
    findings = k["findings"]
    h = '<h2 id="s5">5. Achados e Vulnerabilidades</h2>\n'
    if not findings:
        return h + '<div class="ib g"><p><strong>Nenhum exploit confirmado.</strong></p></div>\n'

    total_ep = sum(f.get("count", 1) for f in findings)
    h += f'<div class="ib"><p><strong>{len(findings)} achado(s)</strong> representando {total_ep} endpoint(s).</p></div>\n'

    mitre = {
        "sqli":        "T1190 — Exploit Public-Facing Application",
        "xss":         "T1059.007 — JavaScript Execution",
        "bruteforce":  "T1110 — Brute Force",
        "exploit":     "T1210 — Exploitation of Remote Services",
    }
    impact = {
        "sqli":       "Leitura, modificação ou exclusão de dados. Possível escalação para RCE.",
        "xss":        "Roubo de sessão, defacement, phishing, exfiltração de dados via JS.",
        "bruteforce": "Acesso não autorizado. Possível movimentação lateral.",
        "exploit":    "Execução remota de código ou acesso privilegiado.",
    }

    for i, f in enumerate(findings, 1):
        sv, tl = f["sev"], f["tool"]
        tc = {"sqlmap": "t-sq", "metasploit": "t-ms", "hydra": "t-hy",
              "nikto": "t-nk", "dalfox": "t-df"}.get(tl, "t-sq")
        sc = {"Critical": "sb-cr", "High": "sb-hi", "Medium": "sb-me", "Low": "sb-lo"}.get(sv, "sb-in")
        cnt = f.get("count", 1)
        cnt_html = f' <span class="cnt-badge">{cnt} endpoint{"s" if cnt>1 else ""}</span>' if cnt > 1 else ""

        h += f'<div class="fd {sv}"><h3>RED-{i:03d}: {esc(f["title"])}{cnt_html} <span class="sb {sc}">{sv.upper()}</span> <span class="tb {tc}">{esc(tl)}</span></h3>\n'
        h += f'<table><tr><th style="width:130px">Alvo</th><td><code>{esc(f["target"][:200])}</code></td></tr>\n'
        h += f'<tr><th>MITRE ATT&CK</th><td>{mitre.get(f.get("type",""), "T1210")}</td></tr>\n'
        h += f'<tr><th>Impacto</th><td>{impact.get(f.get("type",""), "Comprometimento do sistema")}</td></tr></table>\n'

        eps = f.get("endpoints", [])
        if eps and len(eps) > 1:
            h += f'<p><strong>Endpoints afetados ({len(eps)}):</strong></p>\n<div class="ep-list"><ol>\n'
            for ep in eps[:30]: h += f'<li>{esc(ep)}</li>\n'
            if len(eps) > 30: h += f'<li><em>... e mais {len(eps)-30}</em></li>\n'
            h += '</ol></div>\n'

        det = f.get("detail", "")
        if det and det.strip():
            h += f'<p><strong>Evidência técnica:</strong></p>\n<div class="ev">{esc(det)}</div>\n'
        h += '</div>\n'

    # Nikto
    if k["nikto_findings"]:
        h += '<h3>Nikto — Misconfigurations</h3><table><tr><th>Severidade</th><th>Achado</th><th>URL</th></tr>\n'
        for nf in k["nikto_findings"][:30]:
            if isinstance(nf, dict):
                sev_c = {"HIGH": "#7a2e2e", "MEDIUM": "#d4833a", "INFO": "#6e8f72"}.get(
                    nf.get("sev", "INFO"), "#6e8f72")
                h += f'<tr><td><strong style="color:{sev_c}">{esc(nf.get("sev","INFO"))}</strong></td>'
                h += f'<td>{esc(nf.get("msg",""))}</td><td><code>{esc(nf.get("url",""))}</code></td></tr>\n'
        h += '</table>\n'

    # MSF log
    if k["msf_log"]:
        h += '<h3>Log Metasploit</h3>\n<div class="ev">' + esc(k["msf_log"][-2000:]) + '</div>\n'

    # ZAP
    zap_hi = [z for z in k["zap_hc"] if z.get("risk") in ("Critical","High")]
    zap_show = zap_hi or [z for z in k["zap_hc"] if z.get("risk") == "Medium"]
    if zap_show:
        title = "OWASP ZAP — High/Critical" if zap_hi else "OWASP ZAP — Medium"
        h += f'<h3>{title}</h3><table><tr><th>Risco</th><th>Alerta</th><th>URL</th></tr>\n'
        for z in zap_show:
            c = {"Critical": "#7a2e2e", "High": "#b34e4e", "Medium": "#d4833a"}.get(z.get("risk",""), "#555")
            h += f'<tr><td><strong style="color:{c}">{esc(z["risk"])}</strong></td><td>{esc(z["alert"])}</td><td><code>{esc(z["url"][:80])}</code></td></tr>\n'
        h += '</table>\n'

    return h


def _section_recommendations(**k) -> str:
    h = '<h2 id="s6">6. Recomendações</h2>\n'
    obs = []

    if k["sqli_vc"] > 0:
        obs.append(("SQL Injection", "Endpoints aceitam input não sanitizado.",
            "1. Prepared statements em TODAS as queries\n2. WAF com regras SQLi\n3. Input validation (whitelist)\n4. Menor privilégio no banco\n5. Code review urgente", "Imediata (0-7 dias)"))

    if k["xss_vc"] > 0:
        obs.append(("Cross-Site Scripting (XSS)", "Parâmetros refletem input sem sanitização.",
            "1. Encoding de output em TODOS os contextos (HTML, JS, URL, CSS)\n2. Content Security Policy (CSP) restritiva\n3. HttpOnly + Secure nos cookies de sessão\n4. X-XSS-Protection: 1; mode=block\n5. DOMPurify para sanitização client-side", "Imediata (0-7 dias)"))

    if k["hydra_results"]:
        obs.append(("Credenciais Fracas", "Senhas padrão ou fracas aceitas.",
            "1. Trocar TODAS as senhas default imediatamente\n2. Min 14 chars, complexidade, rotação 90d\n3. MFA em TODOS os serviços expostos\n4. Account lockout (5 tentativas)\n5. Monitoramento SIEM para brute force", "Imediata (0-7 dias)"))

    if k["msf_sess"] > 0:
        obs.append(("Exploração Remota Confirmada", "Exploits conhecidos funcionaram.",
            "1. Patch management de emergência\n2. Segmentação de rede (micro-segmentação)\n3. EDR/XDR em todos os endpoints\n4. Hardening de serviços expostos\n5. Incident response imediato", "Imediata (0-3 dias)"))

    if k["cves"]:
        obs.append(("CVEs com Exploits Públicos", f"{len(k['cves'])} CVE(s), {len(k['ssd'])} com exploits.",
            "1. Patching prioritário (CISA KEV first)\n2. Vulnerability management contínuo\n3. Compensating controls enquanto patch não é aplicado\n4. Virtual patching via WAF", "Curto prazo (0-30 dias)"))

    if not obs:
        obs.append(("Manutenção de Postura", "Controles atuais resistiram.",
            "1. Patching contínuo\n2. Red team trimestral\n3. Expandir escopo de testes\n4. Bug bounty program", "Contínuo"))

    for title, detail, rec, prazo in obs:
        h += f'<div class="fd Medium"><h3>{esc(title)}</h3><table>\n'
        h += f'<tr><th style="width:130px">Observação</th><td>{esc(detail)}</td></tr>\n'
        h += f'<tr><th>Ações</th><td><pre style="margin:0;background:transparent;border:none;font-size:.9em">{esc(rec)}</pre></td></tr>\n'
        h += f'<tr><th>Prazo</th><td><strong>{esc(prazo)}</strong></td></tr></table></div>\n'
    return h


def _section_conclusion(**k) -> str:
    h = '<h2 id="s7">7. Conclusão</h2><div class="ib n">\n'
    if k["success"] > 0:
        h += f'<p><strong style="color:#7a2e2e">Confirmados {k["success"]} exploit(s)</strong> contra {esc(k["target"])}, afetando {k["total_endpoints"]} endpoint(s). Remediação imediata recomendada.</p>'
    else:
        h += f'<p>Os controles de {esc(k["target"])} resistiram a {k["total"]} teste(s) em modo {k["mode"]}. Expandir escopo em futuros engagements.</p>'
    return h + '</div>\n'


def _section_poc(**k) -> str:
    pocs = k.get("pocs", [])
    h = '<h2 id="s8">8. Provas de Conceito (PoC)</h2>\n'

    has_verify = os.path.exists(f"{k['outdir']}/poc/verify.sh")
    if has_verify:
        h += ('<div class="ib g"><p><strong>Script de verificação:</strong> '
              '<code>poc/verify.sh</code> — execute antes e após remediação.</p>'
              '<pre style="background:#1e1e1e;color:#d4d4d4;padding:10px;border-radius:6px;'
              'font-size:.85em;margin:8px 0">bash poc/verify.sh</pre></div>\n')

    if not pocs:
        h += '<div class="ib n"><p>Nenhuma vulnerabilidade confirmada via PoC.</p></div>\n'
        return h

    h += f'<div class="ib"><p>{len(pocs)} prova(s) de conceito gerada(s).</p></div>\n'

    for poc in pocs:
        color_map = {"sqli_time": "#7a2e2e", "sqli_bool": "#7a2e2e", "cors": "#b34e4e", "header_missing": "#4a7c8c"}
        border = color_map.get(poc["type"], "#d4833a")
        h += (f'<div class="fd" style="border-left:8px solid {border};margin:18px 0;padding:20px;border-radius:8px;background:#fafafa">\n'
              f'<h3 style="margin-top:0">{esc(poc["id"])}: {esc(poc["title"])}</h3>\n')
        if poc.get("sqlmap_title"):
            h += f'<p><strong>Técnica:</strong> <code>{esc(poc["sqlmap_title"])}</code></p>\n'
        h += f'<p><strong>Alvo:</strong> <code>{esc(poc["url"])}</code></p>\n'
        h += '<p><strong>Como reproduzir:</strong></p>\n'
        h += f'<div class="ev">{esc(poc["curl"])}</div>\n'
        if poc.get("remediation"):
            h += (f'<details style="margin-top:12px"><summary style="cursor:pointer;font-weight:600">Remediação</summary>'
                  f'<pre style="background:#f4f4f4;padding:10px;border-radius:4px;font-size:.85em">{esc(poc["remediation"])}</pre></details>\n')
        h += '</div>\n'

    return h


def _section_appendix(**k) -> str:
    h = '<h2 id="s9">9. Apêndices</h2>\n<h3>A. Activity Log</h3>\n'
    h += '<div class="ev">' + esc(k["log_content"]) + '</div>\n'
    h += '<h3>B. Artefatos</h3><table><tr><th>Arquivo</th><th>Descrição</th></tr>\n'
    artifacts = [
        ("exploits_confirmed.csv", "Exploits confirmados"),
        ("data/cves_found.txt", "CVEs identificados"),
        ("data/open_services.txt", "Serviços abertos"),
        ("recon/subdomains.txt", "Subdomínios (recon)"),
        ("crawl/katana_urls.txt", "URLs (katana)"),
        ("swarm_red.log", "Log de atividades"),
        ("sqlmap/", "Resultados sqlmap"),
        ("xss/xss_confirmed.txt", "XSS confirmados"),
        ("poc/verify.sh", "Script de verificação PoC"),
        ("metasploit/swarm_red.rc", "RC Metasploit"),
        ("hydra/", "Brute force"),
        ("nikto/nikto_report.json", "Nikto"),
        ("searchsploit/", "SearchSploit"),
    ]
    for fn, ds in artifacts:
        ex = "✓" if os.path.exists(f"{k['outdir']}/{fn}") else "—"
        h += f'<tr><td><code>{ex} {esc(fn)}</code></td><td>{esc(ds)}</td></tr>\n'
    h += '</table>\n'
    return h


if __name__ == "__main__":
    if len(sys.argv) < 8:
        print(__doc__)
        sys.exit(1)
    path = generate_report(
        outdir=sys.argv[1], target=sys.argv[2], profile=sys.argv[3],
        total=int(sys.argv[4]), success=int(sys.argv[5]),
        failed=int(sys.argv[6]), version=sys.argv[7]
    )
    print(f"REPORT_OK:{path}")

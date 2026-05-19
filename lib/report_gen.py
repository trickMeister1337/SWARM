import json
import os
import sys
from datetime import datetime

def generate_report(outdir):
    nuclei_file = os.path.join(outdir, "raw", "nuclei.json")
    enrich_file = os.path.join(outdir, "raw", "cve_enrichment.json")
    confirm_file = os.path.join(outdir, "raw", "exploit_confirmations.json")
    report_file = os.path.join(outdir, "report.html")

    findings = []
    if os.path.exists(nuclei_file):
        with open(nuclei_file, "r") as f:
            for line in f:
                try: findings.append(json.loads(line))
                except: pass

    enrichment = {}
    if os.path.exists(enrich_file):
        with open(enrich_file, "r") as f:
            enrichment = json.load(f)

    confirmations = {}
    if os.path.exists(confirm_file):
        with open(confirm_file, "r") as f:
            conf_data = json.load(f)
            for c in conf_data:
                confirmations[c.get("template", "")] = c.get("confidence", "low")

    html = f"""
    <html>
    <head>
        <title>SWARM Report - {outdir}</title>
        <style>
            body {{ font-family: sans-serif; background: #f4f4f9; padding: 20px; }}
            .card {{ background: white; padding: 15px; margin-bottom: 10px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .critical {{ border-left: 10px solid #7a2e2e; }}
            .high {{ border-left: 10px solid #b34e4e; }}
            .medium {{ border-left: 10px solid #d4833a; }}
            .low {{ border-left: 10px solid #4a7c8c; }}
            .badge {{ padding: 2px 8px; border-radius: 4px; color: white; font-size: 12px; font-weight: bold; }}
            .confirmed {{ background: #27ae60; }}
        </style>
    </head>
    <body>
        <h1>SWARM Security Assessment</h1>
        <p>Gerado em: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <hr>
        <h2>Achados ({len(findings)})</h2>
    """

    for f in findings:
        info = f.get("info", {})
        sev = info.get("severity", "info").lower()
        tpl_id = f.get("template-id", "")
        conf = confirmations.get(tpl_id, "low-confidence")
        
        html += f"""
        <div class="card {sev}">
            <h3>{info.get("name", "Vulnerabilidade")} <span class="badge" style="background: #333">{sev.upper()}</span></h3>
            <p><b>URL:</b> {f.get("matched-at", "")}</p>
            <p><b>Confiança:</b> {conf}</p>
            <p>{info.get("description", "")}</p>
        </div>
        """

    html += "</body></html>"
    with open(report_file, "w") as f:
        f.write(html)

if __name__ == "__main__":
    if len(sys.argv) > 1: generate_report(sys.argv[1])

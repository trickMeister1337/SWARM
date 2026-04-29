#!/usr/bin/env python3
"""
SWARM RED — Extração de evidências e consolidação de findings.

Uso: python3 evidence.py <outdir>
  Lê resultados do sqlmap/hydra/metasploit, extrai evidências
  profissionais e consolida findings para o relatório.
  Output: JSON em stdout com findings consolidados.
"""
import sys
import os
import json
import re
import glob
import csv
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse


def extract_sqlmap_evidence(log_content: str, log_dir: str) -> Dict[str, Any]:
    """Extrai evidência estruturada de um log do sqlmap."""
    info: Dict[str, Any] = {
        "target_url": "",
        "parameter": "",
        "place": "",
        "techniques": [],
        "dbms": "",
        "current_user": "",
        "current_db": "",
        "banner": "",
        "tables": [],
        "csv_data": [],
        "injectable": False,
    }

    for line in log_content.split("\n"):
        l = line.strip()
        ll = l.lower()
        clean = re.sub(r"\[\d{2}:\d{2}:\d{2}\]\s*\[\w+\]\s*", "", l)

        if "parameter '" in ll and ("is vulnerable" in ll or "injectable" in ll):
            info["injectable"] = True
            m = re.search(r"parameter '([^']+)'", l)
            if m:
                info["parameter"] = m.group(1)

        if "place:" in ll and not info["place"]:
            m = re.search(r"Place:\s*(\w+)", l, re.I)
            if m:
                info["place"] = m.group(1)

        if "type:" in ll and any(
            t in ll for t in ["boolean", "time", "union", "error", "stacked", "inline"]
        ):
            tech = re.sub(r"^.*Type:\s*", "", clean, flags=re.I).strip()
            if tech and tech not in info["techniques"] and "testing" not in ll:
                info["techniques"].append(tech)

        if "back-end dbms:" in ll:
            info["dbms"] = clean.split(":", 1)[-1].strip()
        if "current user:" in ll and ":" in l:
            info["current_user"] = clean.split(":", 1)[-1].strip().strip("'\"")
        if "current database:" in ll and ":" in l:
            info["current_db"] = clean.split(":", 1)[-1].strip().strip("'\"")
        if "banner:" in ll:
            info["banner"] = clean.split(":", 1)[-1].strip().strip("'\"")

        if re.match(r"^\[\*\]\s+\w", l) and "starting" not in ll and "shutting" not in ll:
            val = l.lstrip("[*] ").strip()
            if val and len(val) < 60 and val not in info["tables"]:
                info["tables"].append(val)

        m = re.search(r"testing URL '([^']+)'", l)
        if m:
            info["target_url"] = m.group(1)
        m = re.search(r"target URL:\s*(\S+)", l, re.I)
        if m:
            info["target_url"] = m.group(1)

    # Read CSV results
    csv_paths: List[str] = []
    for pattern in [f"{log_dir}/results-*.csv", f"{log_dir}/*/results-*.csv"]:
        csv_paths.extend(glob.glob(pattern))
    for d in glob.glob(f"{log_dir}/*/"):
        csv_paths.extend(glob.glob(f"{d}results-*.csv"))
    csv_paths = list(set(csv_paths))

    for cp in csv_paths[:3]:
        try:
            with open(cp) as f:
                reader = csv.reader(f)
                rows = list(reader)
                if len(rows) > 1:
                    info["csv_data"].append(
                        {"file": os.path.basename(cp), "header": rows[0], "rows": rows[1:10]}
                    )
        except Exception:
            pass

    # Read dump CSVs
    for dp in glob.glob(f"{log_dir}/dump/**/*.csv", recursive=True)[:3]:
        try:
            with open(dp) as f:
                reader = csv.reader(f)
                rows = list(reader)
                if rows:
                    tname = os.path.basename(dp).replace(".csv", "")
                    info["csv_data"].append(
                        {"file": f"dump/{tname}", "header": rows[0] if rows else [], "rows": rows[1:10]}
                    )
        except Exception:
            pass

    return info


def format_evidence(info: Dict[str, Any]) -> Optional[str]:
    """Formata evidência como texto profissional para relatório Red Team."""
    parts: List[str] = []

    if info["parameter"]:
        line = f"Parâmetro vulnerável: {info['parameter']}"
        if info["place"]:
            line += f" ({info['place']})"
        parts.append(line)

    if info["techniques"]:
        parts.append("Técnica(s) de injeção:")
        for t in info["techniques"][:5]:
            parts.append(f"  • {t}")

    if info["dbms"]:
        parts.append(f"DBMS identificado: {info['dbms']}")
    if info["banner"]:
        parts.append(f"Banner: {info['banner']}")
    if info["current_user"]:
        parts.append(f"Usuário atual: {info['current_user']}")
    if info["current_db"]:
        parts.append(f"Base de dados atual: {info['current_db']}")

    if info["tables"]:
        parts.append("Bases/Tabelas encontradas:")
        for t in info["tables"][:10]:
            parts.append(f"  • {t}")

    if info["csv_data"]:
        for csv_info in info["csv_data"][:2]:
            parts.append(f"\nDados extraídos ({csv_info['file']}):")
            if csv_info["header"]:
                parts.append("  " + " | ".join(str(h) for h in csv_info["header"]))
                parts.append("  " + "-" * min(70, len(" | ".join(str(h) for h in csv_info["header"]))))
            for row in csv_info["rows"][:5]:
                parts.append("  " + " | ".join(str(c) for c in row))
            if len(csv_info["rows"]) > 5:
                parts.append(f"  ... ({len(csv_info['rows'])} registros total)")

    return "\n".join(parts[:25]) if parts else None


def collect_and_consolidate(outdir: str) -> Dict[str, Any]:
    """Coleta dados de todas as fontes e consolida findings deduplicados."""

    def _rf(p: str, lim: Optional[int] = None) -> str:
        try:
            with open(p) as f:
                c = f.read()
                return c[-lim:] if lim else c
        except:
            return ""

    def _rl(p: str) -> List[str]:
        try:
            with open(p) as f:
                return [l.strip() for l in f if l.strip()]
        except:
            return []

    def _rj(p: str):
        try:
            with open(p) as f:
                return json.load(f)
        except:
            return []

    # ── SQLi results ──
    sqli_results = []
    for f in sorted(glob.glob(f"{outdir}/sqlmap/*_output.log")):
        with open(f) as fh:
            c = fh.read()
        vuln = any(w in c.lower() for w in ["is vulnerable", "injectable", "payload", "fetched"])
        info = extract_sqlmap_evidence(c, os.path.dirname(f))
        info["injectable"] = info["injectable"] or vuln
        evidence = format_evidence(info)
        target_url = info["target_url"]
        if not target_url:
            m = re.search(r"testing URL '([^']+)'", c) or re.search(r"-u ['\"]?([^\s'\"]+)", c)
            target_url = m.group(1) if m else os.path.basename(f)
        sqli_results.append({
            "file": os.path.basename(f), "vulnerable": info["injectable"],
            "evidence": evidence, "target_url": target_url, "info": info
        })

    # ── Other sources ──
    msf_log = _rf(f"{outdir}/metasploit/msf_output.log", 4000)

    hydra_results = []
    for f in glob.glob(f"{outdir}/hydra/*_results.txt"):
        c = _rf(f).strip()
        if c:
            hydra_results.append({"service": os.path.basename(f).replace("_results.txt", ""), "content": c})

    nikto_findings = []
    nd = _rj(f"{outdir}/nikto/nikto_report.json")
    if isinstance(nd, dict):
        nikto_findings = nd.get("vulnerabilities", [])
    elif isinstance(nd, list):
        nikto_findings = [x for x in nd if isinstance(x, dict)]

    confirmed = []
    for line in _rl(f"{outdir}/exploits_confirmed.csv"):
        p = line.split("|")
        if len(p) >= 3 and p[0] != "status":
            confirmed.append({"status": p[0], "target": p[1], "tool": p[2], "detail": p[3] if len(p) > 3 else ""})

    cves = _rl(f"{outdir}/cves_found.txt")
    services = _rl(f"{outdir}/open_services.txt")
    log_content = _rf(f"{outdir}/swarm_red.log", 3000)

    zap_hc = []
    for line in _rl(f"{outdir}/zap_high_crit.txt"):
        p = line.split("|")
        if len(p) >= 3:
            zap_hc.append({"risk": p[0], "alert": p[1], "url": p[2]})

    ssd = {}
    for f in glob.glob(f"{outdir}/searchsploit/CVE-*.json"):
        cv = os.path.basename(f).replace(".json", "")
        d = _rj(f)
        if isinstance(d, dict):
            ex = d.get("RESULTS_EXPLOIT", [])
            if ex:
                ssd[cv] = ex

    # ── Consolidate findings ──
    findings: List[Dict] = []
    vc = [c for c in confirmed if c["status"] == "VULNERABLE"]

    # Group confirmed by URL base path
    confirmed_groups: Dict = {}
    for c in vc:
        base = re.sub(r"\?.*$", "", c["target"]).rstrip("/")
        path = re.sub(r"https?://[^/]+", "", base)
        key = (c["tool"], path)
        if key not in confirmed_groups:
            confirmed_groups[key] = {"urls": [], "tool": c["tool"], "detail": c.get("detail", "")}
        confirmed_groups[key]["urls"].append(c["target"])

    for key, grp in confirmed_groups.items():
        urls = grp["urls"]
        tool = grp["tool"]
        n = len(urls)

        best_ev = None
        for sr in sqli_results:
            if sr["vulnerable"] and sr["evidence"]:
                sr_base = re.sub(r"\?.*$", "", sr["target_url"]).rstrip("/")
                for u in urls:
                    u_base = re.sub(r"\?.*$", "", u).rstrip("/")
                    if sr_base == u_base:
                        best_ev = sr["evidence"]
                        break
                if best_ev:
                    break
        if not best_ev:
            for sr in sqli_results:
                if sr["vulnerable"] and sr["evidence"]:
                    best_ev = sr["evidence"]
                    break

        ev_parts = []
        if best_ev:
            ev_parts.append(best_ev)
        ev_parts.append(f"\nEndpoints afetados ({n}):")
        for u in urls[:20]:
            ev_parts.append(f"  • {u}")
        if n > 20:
            ev_parts.append(f"  ... e mais {n - 20} endpoint(s)")

        findings.append({
            "sev": "High",
            "title": f"SQL Injection — {tool} ({n} endpoints)" if n > 1 else f"SQL Injection — {tool}",
            "target": urls[0] if n == 1 else f"{n} endpoints em {urlparse(urls[0]).netloc}",
            "tool": tool, "detail": "\n".join(ev_parts), "type": "sqli",
            "count": n, "endpoints": urls
        })

    # Unmatched SQLi from logs
    confirmed_urls = set(u for grp in confirmed_groups.values() for u in grp["urls"])
    unmatched = [r for r in sqli_results if r["vulnerable"] and r["target_url"] not in confirmed_urls]
    if unmatched:
        groups: Dict = {}
        for r in unmatched:
            ev_key = (r["info"]["parameter"], r["info"]["dbms"])
            if ev_key not in groups:
                groups[ev_key] = {"items": [], "evidence": r["evidence"]}
            groups[ev_key]["items"].append(r)

        for ev_key, grp in groups.items():
            items = grp["items"]
            n = len(items)
            urls = [r["target_url"] for r in items]
            ev_parts = []
            if grp["evidence"]:
                ev_parts.append(grp["evidence"])
            if n > 1:
                ev_parts.append(f"\nEndpoints ({n}):")
                for u in urls[:15]:
                    ev_parts.append(f"  • {u}")
                if n > 15:
                    ev_parts.append(f"  ... e mais {n - 15}")
            findings.append({
                "sev": "High",
                "title": f"SQL Injection Confirmada ({n} endpoints)" if n > 1 else "SQL Injection Confirmada",
                "target": urls[0] if n == 1 else f"{n} endpoints",
                "tool": "sqlmap", "detail": "\n".join(ev_parts) or "Injeção SQL confirmada via sqlmap",
                "type": "sqli", "count": n, "endpoints": urls
            })

    # Hydra
    for r in hydra_results:
        findings.append({
            "sev": "High", "title": f"Credenciais Fracas — {r['service'].upper()}",
            "target": r["service"], "tool": "hydra", "detail": r["content"][:400],
            "type": "bruteforce", "count": 1, "endpoints": []
        })

    # Final dedup
    seen: set = set()
    deduped = []
    for f in findings:
        key = (f["tool"], f["type"], f.get("count", 0))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return {
        "findings": deduped,
        "sqli_results": sqli_results,
        "msf_log": msf_log,
        "hydra_results": hydra_results,
        "nikto_findings": nikto_findings,
        "confirmed": confirmed,
        "cves": cves,
        "services": services,
        "log_content": log_content,
        "zap_hc": zap_hc,
        "searchsploit": ssd,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    result = collect_and_consolidate(sys.argv[1])
    print(json.dumps({
        "findings_count": len(result["findings"]),
        "sqli_vulnerable": len([r for r in result["sqli_results"] if r["vulnerable"]]),
        "cves": len(result["cves"]),
        "services": len(result["services"]),
    }, indent=2))

#!/usr/bin/env python3
"""
secscan.py — security.txt (RFC-9116) + exposição de IPs internos → secscan_findings.json

Extraído de swarm.sh (heredoc PYSECSCAN). Recebe argumentos posicionais
via sys.argv, idêntico à invocação original do swarm.sh.
"""
import sys, re, json, ssl, urllib.request, urllib.error

outdir, target, domain = sys.argv[1], sys.argv[2].rstrip('/'), sys.argv[3]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
findings = []

def fetch(url, timeout=10):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SWARM-Scanner/2.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(65536).decode("utf-8", errors="replace"), dict(r.headers)
    except Exception:
        return None, None, {}

# ── RFC-9116: security.txt ────────────────────────────────────────
sec_paths = ["/.well-known/security.txt", "/security.txt"]
sec_found = False
for path in sec_paths:
    status, body, _ = fetch(f"{target}{path}")
    if status == 200 and body and ("Contact:" in body or "contact:" in body):
        sec_found = True
        print(f"  [✓] security.txt encontrado em {path}")
        with open(f"{outdir}/raw/security_txt.txt", "w") as f:
            f.write(body)
        break

if not sec_found:
    print("  [!] security.txt ausente (RFC-9116 não implementado)")
    findings.append({
        "id": "SECSCAN-001", "tool": "pysecscan", "type": "secscan",
        "title": "security.txt ausente (RFC-9116)",
        "url": f"{target}/.well-known/security.txt",
        "severity": "info",
        "detail": "O alvo não publica security.txt — dificulta divulgação responsável de vulnerabilidades.",
    })

# ── Internal IP exposure in HTTP responses ────────────────────────
RFC1918 = re.compile(
    r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3})\b'
)
probe_paths = ["/", "/health", "/metrics", "/-/metrics", "/actuator/health",
               "/api/v1", "/api", "/status", "/ping"]
ip_hits = {}
for path in probe_paths:
    status, body, hdrs = fetch(f"{target}{path}")
    if body:
        matches = RFC1918.findall(body)
        for hk, hv in hdrs.items():
            matches += RFC1918.findall(hv)
        if matches:
            unique = list(dict.fromkeys(matches))
            ip_hits[path] = unique
            print(f"  [⚠] IPs internos em {path}: {', '.join(unique[:5])}")

if ip_hits:
    findings.append({
        "id": "SECSCAN-002", "tool": "pysecscan", "type": "secscan",
        "title": "Exposição de endereços IP internos (RFC-1918)",
        "url": target,
        "severity": "medium",
        "detail": f"Respostas HTTP expõem IPs da rede interna: {ip_hits}. "
                  "Facilita reconhecimento de topologia interna e ataques SSRF.",
    })
else:
    print("  [✓] Nenhum IP interno exposto nas respostas HTTP")

out_file = f"{outdir}/raw/secscan_findings.json"
with open(out_file, "w") as f:
    json.dump(findings, f, indent=2, ensure_ascii=False)

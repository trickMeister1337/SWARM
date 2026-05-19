import requests
import json
import sys
import os

SECURITY_HEADERS = {
    "Content-Security-Policy": "XSS Mitigation",
    "X-Content-Type-Options": "MIME Sniffing",
    "X-Frame-Options": "Clickjacking",
    "Strict-Transport-Security": "HSTS",
    "Referrer-Policy": "Privacy",
}

def check_headers(url):
    try:
        r = requests.head(url, timeout=10, verify=False, allow_redirects=True)
        missing = [h for h in SECURITY_HEADERS if h.lower() not in [k.lower() for k in r.headers]]
        return {"url": url, "missing": missing}
    except:
        return None

def main(outdir):
    httpx_file = os.path.join(outdir, "raw", "httpx_results.txt")
    if not os.path.exists(httpx_file): return
    
    results = []
    with open(httpx_file, "r") as f:
        urls = [line.strip().split()[0] for line in f if line.strip().startswith("http")]
    
    for url in urls[:10]:
        res = check_headers(url)
        if res: results.append(res)
        
    with open(os.path.join(outdir, "raw", "security_headers.json"), "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    if len(sys.argv) > 1: main(sys.argv[1])

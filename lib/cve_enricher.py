import json
import sys
import os
import urllib.request
import urllib.parse
import time
import csv
import io

def fetch_kev():
    kev_set = set()
    kev_meta = {}
    cache_dir = os.path.join(os.path.expanduser("~"), ".cache", "swarm")
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, "kev_cache.json")
    max_age = 86400

    if os.path.exists(cache_file) and (time.time() - os.path.getmtime(cache_file) < max_age):
        try:
            with open(cache_file, 'r') as f:
                cached = json.load(f)
                return set(cached.get("kev_set", [])), cached.get("kev_meta", {})
        except: pass

    try:
        url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
        req = urllib.request.Request(url, headers={"User-Agent": "SWARM/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode("utf-8")
        reader = csv.DictReader(io.StringIO(raw))
        for row in reader:
            cid = row.get("cveID","").strip().upper()
            if cid:
                kev_set.add(cid)
                kev_meta[cid] = {
                    "date_added": row.get("dateAdded",""),
                    "due_date": row.get("dueDate",""),
                    "vendor": row.get("vendorProject",""),
                    "product": row.get("product","")
                }
        with open(cache_file, 'w') as f:
            json.dump({"kev_set": list(kev_set), "kev_meta": kev_meta}, f)
    except Exception as e:
        print(f"  [!] Erro KEV: {e}")
    return kev_set, kev_meta

def nvd_fetch(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(cve_id)}"
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SWARM/1.0"})
            with urllib.request.urlopen(req, timeout=12) as r:
                if r.status == 200: return json.loads(r.read())
        except Exception:
            time.sleep(2 ** attempt)
    return None

def main(outdir):
    nuclei_file = os.path.join(outdir, "raw", "nuclei.json")
    cve_db_file = os.path.join(outdir, "raw", "cve_enrichment.json")
    if not os.path.exists(nuclei_file): return

    kev_set, kev_meta = fetch_kev()
    cves = set()
    with open(nuclei_file, "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                for cve in data.get("info", {}).get("classification", {}).get("cve-id", []) or []:
                    if cve.upper().startswith("CVE-"): cves.add(cve.upper())
            except: pass

    enriched = {}
    for cve_id in sorted(cves):
        entry = {"cve_id": cve_id, "cvss_v3": None, "in_kev": cve_id in kev_set}
        nvd = nvd_fetch(cve_id)
        if nvd and nvd.get("vulnerabilities"):
            cve_data = nvd["vulnerabilities"][0]["cve"]
            metrics = cve_data.get("metrics", {})
            cvss3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
            if cvss3: entry["cvss_v3"] = cvss3[0]["cvssData"]["baseScore"]
        enriched[cve_id] = entry
        time.sleep(0.6) # Rate limit

    with open(cve_db_file, "w") as f:
        json.dump(enriched, f, indent=2)

if __name__ == "__main__":
    if len(sys.argv) > 1: main(sys.argv[1])

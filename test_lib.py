#!/usr/bin/env python3
"""
SWARM RED — Testes unitários dos módulos Python.

Uso: python3 test_lib.py
"""
import sys
import os
import json
import tempfile
import shutil
import unittest

# Add lib/ to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

from parsers import parse_nuclei, parse_zap, extract_all_urls, _normalize_zap_alerts
from evidence import extract_sqlmap_evidence, format_evidence, collect_and_consolidate
from report_generator import generate_report


class TestParsers(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_parse_nuclei_extracts_cves(self):
        nuclei_file = os.path.join(self.tmpdir, "nuclei.json")
        with open(nuclei_file, "w") as f:
            f.write('{"info":{"classification":{"cve":["CVE-2021-44228"]}},"matched-at":"https://test.com/api?id=1"}\n')
            f.write('{"info":{"classification":{"cve":["CVE-2023-1234"]}},"matched-at":"https://test.com/search?q=x"}\n')
            f.write('{"info":{"classification":{}},"matched-at":"https://test.com"}\n')

        result = parse_nuclei(nuclei_file, self.tmpdir)
        self.assertEqual(result["cves"], 2)
        self.assertEqual(result["urls_params"], 2)
        self.assertEqual(result["urls_total"], 3)

        # Verify files
        with open(os.path.join(self.tmpdir, "cves_found.txt")) as f:
            cves = [l.strip() for l in f if l.strip()]
        self.assertIn("CVE-2021-44228", cves)
        self.assertIn("CVE-2023-1234", cves)

    def test_parse_nuclei_handles_string_cve(self):
        nuclei_file = os.path.join(self.tmpdir, "nuclei.json")
        with open(nuclei_file, "w") as f:
            f.write('{"info":{"classification":{"cve":"CVE-2024-9999"}},"matched-at":"https://t.com"}\n')
        result = parse_nuclei(nuclei_file, self.tmpdir)
        self.assertEqual(result["cves"], 1)

    def test_parse_zap_array_format(self):
        zap_file = os.path.join(self.tmpdir, "zap.json")
        with open(zap_file, "w") as f:
            json.dump([
                {"alert": "SQL Injection", "risk": "High", "url": "https://t.com/login?u=a"},
                {"alert": "XSS", "risk": "High", "url": "https://t.com/search"},
                {"alert": "Missing CSP", "risk": "Medium", "url": "https://t.com"},
            ], f)
        result = parse_zap(zap_file, self.tmpdir)
        self.assertEqual(result["sqli"], 1)
        self.assertEqual(result["high_crit"], 2)

    def test_parse_zap_nested_format(self):
        zap_file = os.path.join(self.tmpdir, "zap.json")
        with open(zap_file, "w") as f:
            json.dump({"site": [{"alerts": [
                {"alert": "SQL Injection", "risk": "Critical", "url": "https://t.com/api"}
            ]}]}, f)
        result = parse_zap(zap_file, self.tmpdir)
        self.assertEqual(result["sqli"], 1)
        self.assertEqual(result["high_crit"], 1)

    def test_parse_zap_handles_string_elements(self):
        zap_file = os.path.join(self.tmpdir, "zap.json")
        with open(zap_file, "w") as f:
            json.dump(["some string", {"alert": "Test", "risk": "Low", "url": "https://t.com"}], f)
        result = parse_zap(zap_file, self.tmpdir)
        self.assertEqual(result["high_crit"], 0)  # string element skipped

    def test_parse_zap_riskdesc_format(self):
        zap_file = os.path.join(self.tmpdir, "zap.json")
        with open(zap_file, "w") as f:
            json.dump([{"alert": "SQL Injection", "risk": "High (Medium)", "url": "https://t.com/x"}], f)
        result = parse_zap(zap_file, self.tmpdir)
        self.assertEqual(result["sqli"], 1)
        self.assertEqual(result["high_crit"], 1)

    def test_normalize_zap_alerts_dict_with_alerts_key(self):
        raw = {"alerts": [{"alert": "Test", "url": "https://t.com"}]}
        alerts = _normalize_zap_alerts(raw)
        self.assertEqual(len(alerts), 1)

    def test_extract_all_urls_consolidates_sources(self):
        # Create mock input files
        with open(os.path.join(self.tmpdir, "input_nuclei.jsonl"), "w") as f:
            f.write('{"matched-at":"https://t.com/api?id=1"}\n')
        with open(os.path.join(self.tmpdir, "input_zap.json"), "w") as f:
            json.dump([{"url": "https://t.com/login?user=a", "alert": "SQLi", "risk": "High"}], f)
        with open(os.path.join(self.tmpdir, "input_httpx.jsonl"), "w") as f:
            f.write('{"url":"https://t.com/admin"}\n')

        result = extract_all_urls(self.tmpdir, "t.com")
        self.assertGreater(result["params"], 0)
        self.assertGreater(result["total"], 0)

        with open(os.path.join(self.tmpdir, "urls_with_params.txt")) as f:
            urls = [l.strip() for l in f if l.strip()]
        self.assertTrue(any("id=1" in u for u in urls))

    def test_extract_urls_excludes_static_files(self):
        """robots.txt, .css, .js, images NÃO devem virar targets SQLi."""
        with open(os.path.join(self.tmpdir, "input_httpx.jsonl"), "w") as f:
            f.write('{"url":"https://t.com/robots.txt"}\n')
            f.write('{"url":"https://t.com/style.css"}\n')
            f.write('{"url":"https://t.com/app.js"}\n')
            f.write('{"url":"https://t.com/logo.png"}\n')
            f.write('{"url":"https://t.com/sitemap.xml"}\n')
            f.write('{"url":"https://t.com/api/users"}\n')  # Este SIM deve entrar

        result = extract_all_urls(self.tmpdir, "t.com")
        with open(os.path.join(self.tmpdir, "urls_with_params.txt")) as f:
            urls = [l.strip() for l in f if l.strip()]

        # Nenhuma URL estática deve ter virado target com parâmetro
        static_in_params = [u for u in urls if any(
            ext in u for ext in [".txt?", ".css?", ".js?", ".png?", ".xml?"]
        )]
        self.assertEqual(len(static_in_params), 0,
            f"URLs estáticas viraram targets SQLi: {static_in_params}")

        # Mas api/users deve ter gerado variantes
        api_urls = [u for u in urls if "/api/users" in u]
        self.assertGreater(len(api_urls), 0, "URL dinâmica /api/users deveria gerar variantes")

    def test_extract_urls_excludes_http_headers_as_params(self):
        """Headers HTTP reportados pelo ZAP como 'param' NÃO são query params."""
        with open(os.path.join(self.tmpdir, "input_zap.json"), "w") as f:
            json.dump([
                {"url": "https://t.com/", "alert": "Missing CSP", "risk": "Medium",
                 "param": "x-content-type-options"},
                {"url": "https://t.com/page", "alert": "Missing Header", "risk": "Low",
                 "param": "cache-control"},
                {"url": "https://t.com/api", "alert": "SQLi", "risk": "High",
                 "param": "user_id"},  # Este SIM é param real
            ], f)

        result = extract_all_urls(self.tmpdir, "t.com")
        with open(os.path.join(self.tmpdir, "urls_with_params.txt")) as f:
            urls = [l.strip() for l in f if l.strip()]

        # Headers NÃO devem virar params
        header_urls = [u for u in urls if "x-content-type" in u or "cache-control" in u]
        self.assertEqual(len(header_urls), 0,
            f"Headers HTTP viraram query params: {header_urls}")

        # Mas user_id SIM deve estar
        real_params = [u for u in urls if "user_id" in u]
        self.assertGreater(len(real_params), 0, "Param real user_id deveria estar")

    def test_extract_urls_excludes_external_domains(self):
        """URLs de domínios externos (caniuse.com, mozilla.org) NÃO devem ser testadas."""
        with open(os.path.join(self.tmpdir, "input_zap.json"), "w") as f:
            json.dump([
                {"url": "https://webapp.target.com/api", "alert": "Missing HSTS", "risk": "Medium",
                 "reference": "https://caniuse.com/stricttransportsecurity"},
                {"url": "https://webapp.target.com/login", "alert": "XSS", "risk": "High",
                 "other": "See https://developer.mozilla.org/en-US/docs/Web/HTTP",
                 "evidence": "https://owasp.org/www-community/attacks/xss/"},
                {"url": "https://webapp.target.com/search?q=test", "alert": "SQLi", "risk": "High"},
            ], f)

        result = extract_all_urls(self.tmpdir, "webapp.target.com")
        with open(os.path.join(self.tmpdir, "urls_with_params.txt")) as f:
            urls = [l.strip() for l in f if l.strip()]
        with open(os.path.join(self.tmpdir, "all_target_urls.txt")) as f:
            all_urls = [l.strip() for l in f if l.strip()]

        # NENHUMA URL externa deve estar presente
        external = [u for u in all_urls if "caniuse.com" in u or "mozilla.org" in u or "owasp.org" in u]
        self.assertEqual(len(external), 0,
            f"URLs externas encontradas: {external}")

        # URL do alvo deve estar
        target_urls = [u for u in all_urls if "webapp.target.com" in u]
        self.assertGreater(len(target_urls), 0, "URLs do alvo deveriam estar presentes")

    def test_extract_urls_excludes_external_domains(self):
        """URLs de domínios externos (caniuse.com, owasp.org) NÃO devem ser testadas."""
        with open(os.path.join(self.tmpdir, "input_zap.json"), "w") as f:
            json.dump([
                {"url": "https://target.com/page", "alert": "Missing HSTS", "risk": "Medium",
                 "reference": "https://caniuse.com/stricttransportsecurity https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"},
                {"url": "https://target.com/login", "alert": "CSP", "risk": "Medium",
                 "other": "See https://owasp.org/www-community/controls/Content_Security_Policy"},
                {"url": "https://target.com/api?id=1", "alert": "SQLi", "risk": "High"},
            ], f)

        result = extract_all_urls(self.tmpdir, "target.com")
        with open(os.path.join(self.tmpdir, "urls_with_params.txt")) as f:
            urls = [l.strip() for l in f if l.strip()]
        with open(os.path.join(self.tmpdir, "all_target_urls.txt")) as f:
            all_u = [l.strip() for l in f if l.strip()]

        # Nenhuma URL externa
        external = [u for u in all_u if "caniuse.com" in u or "mozilla.org" in u or "owasp.org" in u]
        self.assertEqual(len(external), 0,
            f"URLs externas vazaram: {external}")

        # URLs do target devem estar
        target_urls = [u for u in all_u if "target.com" in u]
        self.assertGreater(len(target_urls), 0, "URLs do target devem estar presentes")


class TestEvidence(unittest.TestCase):
    def test_extract_sqlmap_evidence_finds_parameter(self):
        log = """
[10:00:01] [INFO] testing URL 'https://target.com/search?q=test'
[10:00:05] [INFO] parameter 'q' is vulnerable
[10:00:05] [INFO] Place: GET
[10:00:06] [INFO] Type: boolean-based blind
[10:00:07] [INFO] back-end DBMS: MySQL >= 5.0
[10:00:08] [INFO] current user: 'app_user'
[10:00:09] [INFO] current database: 'production_db'
"""
        tmpdir = tempfile.mkdtemp()
        try:
            info = extract_sqlmap_evidence(log, tmpdir)
            self.assertTrue(info["injectable"])
            self.assertEqual(info["parameter"], "q")
            self.assertIn("boolean", info["techniques"][0].lower())
            self.assertIn("MySQL", info["dbms"])
            self.assertEqual(info["current_user"], "app_user")
            self.assertEqual(info["current_db"], "production_db")
        finally:
            shutil.rmtree(tmpdir)

    def test_extract_sqlmap_evidence_reads_csv(self):
        tmpdir = tempfile.mkdtemp()
        try:
            csv_path = os.path.join(tmpdir, "results-04282026.csv")
            with open(csv_path, "w") as f:
                f.write("Target URL,Place,Parameter,Technique(s),Note(s)\n")
                f.write("https://t.com/api,GET,id,boolean-based blind,\n")
                f.write("https://t.com/api,GET,name,time-based blind,\n")

            info = extract_sqlmap_evidence("", tmpdir)
            self.assertEqual(len(info["csv_data"]), 1)
            self.assertEqual(len(info["csv_data"][0]["rows"]), 2)
            self.assertIn("Target URL", info["csv_data"][0]["header"])
        finally:
            shutil.rmtree(tmpdir)

    def test_format_evidence_professional(self):
        info = {
            "parameter": "q", "place": "GET", "techniques": ["boolean-based blind"],
            "dbms": "MySQL >= 5.0", "current_user": "root", "current_db": "app",
            "banner": "5.7.38", "tables": ["users", "orders"], "csv_data": [],
            "target_url": "", "injectable": True
        }
        text = format_evidence(info)
        self.assertIsNotNone(text)
        self.assertIn("Parâmetro vulnerável: q (GET)", text)
        self.assertIn("boolean-based blind", text)
        self.assertIn("MySQL", text)
        self.assertIn("root", text)

    def test_format_evidence_returns_none_when_empty(self):
        info = {
            "parameter": "", "place": "", "techniques": [], "dbms": "",
            "current_user": "", "current_db": "", "banner": "",
            "tables": [], "csv_data": [], "target_url": "", "injectable": False
        }
        self.assertIsNone(format_evidence(info))

    def test_collect_and_consolidate_deduplicates(self):
        tmpdir = tempfile.mkdtemp()
        try:
            for d in ["sqlmap", "metasploit", "hydra", "nikto", "searchsploit"]:
                os.makedirs(os.path.join(tmpdir, d), exist_ok=True)

            # Create confirmed CSV with duplicates
            with open(os.path.join(tmpdir, "exploits_confirmed.csv"), "w") as f:
                f.write("status|target|tool|detail\n")
                f.write("VULNERABLE|https://t.com/api?id=1|sqlmap|level=3,risk=2\n")
                f.write("VULNERABLE|https://t.com/api?name=x|sqlmap|level=3,risk=2\n")
                f.write("VULNERABLE|https://t.com/api?q=y|sqlmap|level=3,risk=2\n")

            for path in ["cves_found.txt", "open_services.txt", "swarm_red.log",
                         "zap_high_crit.txt", "urls_with_params.txt"]:
                open(os.path.join(tmpdir, path), "w").close()

            result = collect_and_consolidate(tmpdir)
            findings = result["findings"]
            # Should be consolidated into 1 finding, not 3
            self.assertLessEqual(len(findings), 2)
            if findings:
                self.assertGreaterEqual(findings[0].get("count", 1), 3)
        finally:
            shutil.rmtree(tmpdir)


class TestReportGenerator(unittest.TestCase):
    def test_generate_report_creates_html(self):
        tmpdir = tempfile.mkdtemp()
        try:
            for d in ["sqlmap", "metasploit", "hydra", "nikto", "searchsploit"]:
                os.makedirs(os.path.join(tmpdir, d), exist_ok=True)
            for path in ["exploits_confirmed.csv", "cves_found.txt", "open_services.txt",
                         "swarm_red.log", "zap_high_crit.txt"]:
                with open(os.path.join(tmpdir, path), "w") as f:
                    if "csv" in path:
                        f.write("status|target|tool|detail\n")

            report_path = generate_report(tmpdir, "test.com", "staging", 5, 0, 0, "1.0.0")
            self.assertTrue(os.path.exists(report_path))

            with open(report_path) as f:
                html = f.read()
            self.assertIn("SWARM RED", html)
            self.assertIn("test.com", html)
            self.assertIn("CONFIDENCIAL", html)
            self.assertIn("<style>", html)
            self.assertGreater(len(html), 3000)
        finally:
            shutil.rmtree(tmpdir)

    def test_generate_report_with_findings(self):
        tmpdir = tempfile.mkdtemp()
        try:
            for d in ["sqlmap", "metasploit", "hydra", "nikto", "searchsploit"]:
                os.makedirs(os.path.join(tmpdir, d), exist_ok=True)

            with open(os.path.join(tmpdir, "exploits_confirmed.csv"), "w") as f:
                f.write("status|target|tool|detail\n")
                f.write("VULNERABLE|https://t.com/api?id=1|sqlmap|level=3,risk=2\n")

            # Create a sqlmap log
            with open(os.path.join(tmpdir, "sqlmap", "abc12345_output.log"), "w") as f:
                f.write("[10:00:01] [INFO] testing URL 'https://t.com/api?id=1'\n")
                f.write("[10:00:05] [INFO] parameter 'id' is vulnerable\n")
                f.write("[10:00:06] [INFO] Type: boolean-based blind\n")
                f.write("[10:00:07] [INFO] back-end DBMS: MySQL >= 5.0\n")

            for path in ["cves_found.txt", "open_services.txt", "swarm_red.log", "zap_high_crit.txt"]:
                open(os.path.join(tmpdir, path), "w").close()

            report_path = generate_report(tmpdir, "t.com", "staging", 1, 1, 0, "1.0.0")
            with open(report_path) as f:
                html = f.read()

            self.assertIn("RED-001", html)
            self.assertIn("boolean", html.lower())
            self.assertIn("MySQL", html)
        finally:
            shutil.rmtree(tmpdir)


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)

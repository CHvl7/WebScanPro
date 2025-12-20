import requests
import json
import argparse
from difflib import SequenceMatcher

VULNERABILITY_FINDINGS = []

XSS_PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert('XSS')>"]
WEAK_CREDENTIALS = [("admin", "admin"), ("user", "user"), ("admin", "password")]

ACCESS_ENDPOINTS = [
    {"path": "/rest/user/whoami", "type": "IDOR / Horizontal Escalation"},
    {"path": "/api/Users/1", "type": "IDOR / Data Exposure"},
    {"path": "/administration", "type": "Vertical Privilege Escalation"},
    {"path": "/ftp", "type": "Broken Access Control (Files)"}
]

def ml_similarity_analysis(url, path):
    try:
        baseline = requests.get(url + "/thispageexistsnever", timeout=3).text
        current = requests.get(url + path, timeout=3).text
        return SequenceMatcher(None, baseline, current).ratio()
    except:
        return 0.0

def check_access_control_week6(url):
    global VULNERABILITY_FINDINGS
    print("[*] Initializing Week 6: Access Control & IDOR Testing...")
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
    for entry in ACCESS_ENDPOINTS:
        try:
            target = url + entry["path"]
            res = requests.get(target, headers=headers, timeout=5)
            similarity = ml_similarity_analysis(url, entry["path"])
            if res.status_code == 200 and similarity < 0.7:
                mitigation = "Implement Role-Based Access Control (RBAC)."
                if "IDOR" in entry["type"]:
                    mitigation = "Use UUIDs/Indirect references instead of plain integers."
                VULNERABILITY_FINDINGS.append({
                    "type": entry["type"],
                    "status": "VULNERABLE",
                    "severity": "HIGH",
                    "details": f"Unauthorized access to {entry['path']}. AI Similarity score ({similarity:.2f}) indicates non-error content.",
                    "mitigation": mitigation
                })
            else:
                VULNERABILITY_FINDINGS.append({"type": entry["type"], "status": "PASSED", "severity": "LOW"})
        except:
            continue

def check_sql_injection(url):
    global VULNERABILITY_FINDINGS
    payload = "' OR 1=1 --"
    try:
        res = requests.get(f"{url}/rest/products/search?q={payload}", timeout=5)
        if res.status_code == 200:
            VULNERABILITY_FINDINGS.append({"type": "SQL Injection", "status": "VULNERABLE", "severity": "HIGH"})
        else:
            VULNERABILITY_FINDINGS.append({"type": "SQL Injection", "status": "PASSED", "severity": "LOW"})
    except: pass

def check_xss(url):
    global VULNERABILITY_FINDINGS
    try:
        res = requests.get(f"{url}/search?q={XSS_PAYLOADS[0]}", timeout=5)
        if XSS_PAYLOADS[0] in res.text:
            VULNERABILITY_FINDINGS.append({"type": "Reflected XSS", "status": "VULNERABLE", "severity": "MEDIUM"})
        else:
            VULNERABILITY_FINDINGS.append({"type": "Reflected XSS", "status": "PASSED", "severity": "LOW"})
    except: pass

def generate_report(url):
    print("\n" + "="*85)
    print(f"| WEB SCANNER FINAL REPORT | TARGET: {url} |")
    print("="*85)
    print(f"| {'VULNERABILITY TYPE':<35} | {'STATUS':<12} | {'SEVERITY':<10} |")
    print("-" * 85)
    total = 0
    for f in VULNERABILITY_FINDINGS:
        status = f.get("status", "N/A")
        print(f"| {f['type']:<35} | {status:<12} | {f['severity']:<10} |")
        if status == "VULNERABLE":
            total += 1
    print("="*85)
    print(f"| TOTAL VULNERABILITIES FOUND: {total:<52} |")
    print("="*85)
    with open("security_report.json", "w") as f:
        json.dump(VULNERABILITY_FINDINGS, f, indent=4)

def run_scanner(url):
    print(f"--- WebScanPro: Starting Comprehensive Security Scan ---")
    try:
        requests.get(url, timeout=5)
        check_sql_injection(url)
        check_xss(url)
        check_access_control_week6(url)
        generate_report(url)
    except:
        print("[-] Error: Target unreachable.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', help='The target URL')
    args = parser.parse_args()
    target_url = args.url if args.url else "http://127.0.0.1:3000"
    run_scanner(target_url)
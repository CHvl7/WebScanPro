import requests
import json 
import argparse # <<< ADDED FOR CLI ARGUMENTS

# --- GLOBAL STORAGE FOR REPORTING ---
VULNERABILITY_FINDINGS = []

# --- XSS PAYLOADS LIST (Comprehensive XSS Module) ---
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert('XSS')>",
    "';alert(String.fromCharCode(88,83,83))//",
    "prompt(1)",
    "confirm(1)"
]

# Function to check for SQL Injection 
def check_sql_injection(url):
    global VULNERABILITY_FINDINGS
    
    payload = "' OR 1=1 --"
    test_url = f"{url}/users/login?username={payload}&password=test" 
    
    try:
        response = requests.get(test_url, timeout=5)
        
        if response.status_code == 200 and ("Welcome" in response.text or "Signed in" in response.text):
            VULNERABILITY_FINDINGS.append({
                "type": "SQL Injection",
                "status": "VULNERABLE",
                "severity": "HIGH",
                "details": f"Simple payload worked: {payload}"
            })
        else:
            VULNERABILITY_FINDINGS.append({"type": "SQL Injection", "status": "PASSED", "severity": "LOW"})
            
    except requests.exceptions.RequestException:
        VULNERABILITY_FINDINGS.append({"type": "SQL Injection", "status": "ERROR", "severity": "MEDIUM", "details": "Check failed due to connection error."})

# Function to check for Cross-Site Scripting (XSS) - UPDATED FOR MULTIPLE PAYLOADS
def check_xss(url):
    global VULNERABILITY_FINDINGS
    global XSS_PAYLOADS # Access the new list
    
    # Define a common search path (Juice Shop search page)
    search_path = "/search?q="
    vulnerable_endpoint = None

    try:
        for payload in XSS_PAYLOADS: # NEW LOGIC: Iterating through the payload list
            test_url = f"{url}{search_path}{payload}" 
            response = requests.get(test_url, timeout=5)
            
            # Check if the payload string is reflected in the response body
            if payload in response.text:
                vulnerable_endpoint = test_url
                break # Stop scanning after the first successful hit

        if vulnerable_endpoint:
            VULNERABILITY_FINDINGS.append({
                "type": "Reflected XSS (Comprehensive)",
                "status": "VULNERABLE",
                "severity": "MEDIUM",
                "details": f"One of {len(XSS_PAYLOADS)} payloads was reflected at: {search_path}"
            })
        else:
            VULNERABILITY_FINDINGS.append({"type": "Reflected XSS (Comprehensive)", "status": "PASSED", "severity": "LOW"})
            
    except requests.exceptions.RequestException:
        VULNERABILITY_FINDINGS.append({"type": "Reflected XSS (Comprehensive)", "status": "ERROR", "severity": "MEDIUM", "details": "Check failed due to connection error."})


# Function to check for Broken Access Control (BAC/IDOR)
def check_access_control(url):
    global VULNERABILITY_FINDINGS
    
    test_path = "/ftp" 
    test_url = url + test_path
    
    try:
        response = requests.get(test_url, timeout=5)
        
        if response.status_code == 200:
            VULNERABILITY_FINDINGS.append({
                "type": "Broken Access Control (BAC)",
                "status": "VULNERABLE",
                "severity": "HIGH",
                "details": f"Unauthenticated access granted to: {test_path}"
            })
        else:
            VULNERABILITY_FINDINGS.append({"type": "Broken Access Control (BAC)", "status": "PASSED", "severity": "LOW"})
            
    except requests.exceptions.RequestException:
        VULNERABILITY_FINDINGS.append({"type": "Broken Access Control (BAC)", "status": "ERROR", "severity": "MEDIUM", "details": "Check failed due to connection error."})

# --- FUNCTION: GENERATE FINAL REPORT (Includes JSON output) ---
def generate_report(url):
    # 1. Generate Terminal Output 
    print("\n" + "="*50)
    print(f"| WEB SCANNER REPORT | TARGET: {url} |")
    print("="*50)
    
    if not VULNERABILITY_FINDINGS:
        print("| No scan results found. |")
        print("="*50)
        return

    # Print summary table
    print(f"| {'TYPE':<25} | {'STATUS':<10} | {'SEVERITY':<10} |")
    print("-" * 50)
    
    total_vulnerabilities = 0
    
    for finding in VULNERABILITY_FINDINGS:
        status = finding.get("status", "N/A")
        print(f"| {finding['type']:<25} | {status:<10} | {finding['severity']:<10} |")
        if status == "VULNERABLE":
            total_vulnerabilities += 1
            
    print("="*50)
    print(f"| TOTAL VULNERABILITIES FOUND: {total_vulnerabilities:<20} |")
    print("="*50)
    
    # 2. Generate JSON File
    report_data = {
        "target": url,
        "total_vulnerabilities": total_vulnerabilities,
        "findings": VULNERABILITY_FINDINGS
    }
    
    file_name = "security_report.json"
    
    try:
        with open(file_name, 'w') as f:
            json.dump(report_data, f, indent=4)
        print(f"\n[INFO] JSON report saved to: {file_name}")
    except Exception as e:
        print(f"[-] Error saving JSON report: {e}")


# Main scanner function
def run_scanner(url):
    print(f"Starting scan for {url}")
    
    try:
        response = requests.get(url, timeout=5)
        print(f"Status Code: {response.status_code}")
        
        if "OWASP Juice Shop" in response.text:
            # RUN ALL VULNERABILITY CHECKS
            check_sql_injection(url)  
            check_xss(url)            
            check_access_control(url)
            
            # --- FINAL STEP: GENERATE REPORT ---
            generate_report(url)
            # -----------------------------------
            
    except requests.exceptions.ConnectionError:
        print("[-] Fatal Error: Initial connection failed (Is Docker running?).")
    except requests.exceptions.RequestException:
        print("[-] Fatal Error: Initial connection failed due to an unknown error.")

# Execution block uses argparse to get the target URL
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="WebScanPro: A simple web security scanner.")
    parser.add_argument(
        '-u', '--url', 
        type=str, 
        required=True, 
        help='The target URL to scan (e.g., http://127.0.0.1:3000)'
    )
    args = parser.parse_args()
    
    target_url = args.url # Use the URL provided by the user
    run_scanner(target_url)
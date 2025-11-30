import requests
import json # <<< ADDED FOR JSON OUTPUT

# --- GLOBAL STORAGE FOR REPORTING (Change 1) ---
VULNERABILITY_FINDINGS = []

# Function to check for SQL Injection (Updated to use global list)
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

# Function to check for Cross-Site Scripting (XSS) (Updated to use global list)
def check_xss(url):
    global VULNERABILITY_FINDINGS
    
    payload = "<script>alert('XSS-Test')</script>"
    test_url = f"{url}/search?q={payload}" 
    
    try:
        response = requests.get(test_url, timeout=5)
        
        if payload in response.text:
            VULNERABILITY_FINDINGS.append({
                "type": "Reflected XSS",
                "status": "VULNERABLE",
                "severity": "MEDIUM",
                "details": f"Payload reflected in response body."
            })
        else:
            VULNERABILITY_FINDINGS.append({"type": "Reflected XSS", "status": "PASSED", "severity": "LOW"})
            
    except requests.exceptions.RequestException:
        VULNERABILITY_FINDINGS.append({"type": "Reflected XSS", "status": "ERROR", "severity": "MEDIUM", "details": "Check failed due to connection error."})

# Function to check for Broken Access Control (BAC/IDOR) (Updated to use global list)
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

# --- NEW FUNCTION: GENERATE FINAL REPORT (Now includes JSON output) ---
def generate_report(url):
    # 1. Generate Terminal Output (Existing Table)
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
    
    # 2. Generate JSON File (NEW LOGIC)
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


# Main scanner function (Updated to call generate_report as final step)
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

# Execution block remains the same
if __name__ == "__main__":
    target_url = "http://127.0.0.1:3000" 
    run_scanner(target_url)
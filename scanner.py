import requests
import json 
import argparse

VULNERABILITY_FINDINGS = []

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert('XSS')>",
    "';alert(String.fromCharCode(88,83,83))//",
    "prompt(1)",
    "confirm(1)"
]


WEAK_CREDENTIALS = [
    ("admin", "admin"),
    ("user", "user"),
    ("test", "test"),
    ("guest", "guest"),
    ("admin", "password")
]


CAPTURED_SESSIONS = {}

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

def check_xss(url):
    global VULNERABILITY_FINDINGS
    global XSS_PAYLOADS
    
    search_path = "/search?q="
    vulnerable_endpoint = None

    try:
        for payload in XSS_PAYLOADS:
            test_url = f"{url}{search_path}{payload}" 
            response = requests.get(test_url, timeout=5)
            
            if payload in response.text:
                vulnerable_endpoint = test_url
                break

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


# Function for Week 5: Check Weak/Default Credentials
def check_weak_credentials(url):
    global VULNERABILITY_FINDINGS
    global WEAK_CREDENTIALS 
    
    login_endpoint = f"{url}/rest/user/login"
    successful_login = False
    
    try:
        for username, password in WEAK_CREDENTIALS:
            
            payload = {
                "email": username,
                "password": password
            }
            
            response = requests.post(login_endpoint, json=payload, timeout=5)
            
            if response.status_code == 200 and "authentication" in response.json().get("status", ""):
                successful_login = True
                token = response.json().get("authentication", {}).get("token", "No Token Found")
                
                VULNERABILITY_FINDINGS.append({
                    "type": "Weak Credential Testing",
                    "status": "VULNERABLE",
                    "severity": "HIGH",
                    "details": f"Successful login with weak credential: {username}/{password}. Captured token for session analysis."
                })
                break 

        if not successful_login:
             VULNERABILITY_FINDINGS.append({"type": "Weak Credential Testing", "status": "PASSED", "severity": "LOW"})

    except requests.exceptions.RequestException:
        VULNERABILITY_FINDINGS.append({"type": "Weak Credential Testing", "status": "ERROR", "severity": "MEDIUM", "details": "Check failed due to connection error."})
    except json.JSONDecodeError:
        pass
        
        

def analyze_session_cookie(url):
    global VULNERABILITY_FINDINGS
    
    try:
        
        response = requests.get(url, timeout=5)
        
    
        set_cookie_header = response.headers.get('Set-Cookie')
        
        
        if set_cookie_header: 
            
            missing_flags = []
            
            if "httponly" not in set_cookie_header.lower():
                missing_flags.append("HttpOnly")
            
            if "secure" not in set_cookie_header.lower():
                missing_flags.append("Secure")
                
            if "samesite" not in set_cookie_header.lower():
                missing_flags.append("SameSite")
            
            if missing_flags:
                VULNERABILITY_FINDINGS.append({
                    "type": "Session Cookie Analysis",
                    "status": "VULNERABLE",
                    "severity": "HIGH",
                    "details": f"Missing critical security flags: {', '.join(missing_flags)}. This exposes the cookie to XSS attacks or CSRF."
                })
            else:
                VULNERABILITY_FINDINGS.append({"type": "Session Cookie Analysis", "status": "PASSED", "severity": "LOW"})

        else:
            VULNERABILITY_FINDINGS.append({"type": "Session Cookie Analysis", "status": "INFO", "severity": "LOW", "details": "No Set-Cookie header detected for analysis on the root page."})

    except requests.exceptions.RequestException:
        VULNERABILITY_FINDINGS.append({"type": "Session Cookie Analysis", "status": "ERROR", "severity": "MEDIUM", "details": "Check failed due to connection error."})



def simulate_brute_force(url):
    global VULNERABILITY_FINDINGS
    
    login_endpoint = f"{url}/rest/user/login"
    test_payload = {"email": "nonexistent@test.com", "password": "wrong_password"}
    ATTEMPT_COUNT = 15 
    RATE_LIMIT_STATUS = 429
    
    try:
        
        initial_response = requests.post(login_endpoint, json=test_payload, timeout=5)

        if initial_response.status_code != 401:
             VULNERABILITY_FINDINGS.append({
                "type": "Brute-Force Simulation",
                "status": "INFO",
                "severity": "LOW",
                "details": f"Initial login attempt did not return 401 (returned {initial_response.status_code}). Skipping rate limit test."
            })
             return

        
        for i in range(ATTEMPT_COUNT):
            response = requests.post(login_endpoint, json=test_payload, timeout=1) 
            
            
            if response.status_code == RATE_LIMIT_STATUS:
                VULNERABILITY_FINDINGS.append({
                    "type": "Brute-Force Simulation",
                    "status": "PASSED",
                    "severity": "LOW",
                    "details": f"Application uses rate limiting. Detected status code {RATE_LIMIT_STATUS} after {i+1} attempts."
                })
                return 

        
        VULNERABILITY_FINDINGS.append({
            "type": "Brute-Force Simulation",
            "status": "VULNERABLE",
            "severity": "HIGH",
            "details": f"No rate limiting or account lockout detected after {ATTEMPT_COUNT} rapid failed logins (status code remained {initial_response.status_code})."
        })

    except requests.exceptions.RequestException:
        VULNERABILITY_FINDINGS.append({"type": "Brute-Force Simulation", "status": "ERROR", "severity": "MEDIUM", "details": "Check failed due to connection error."})


def check_session_fixation(url):
    global VULNERABILITY_FINDINGS
    login_endpoint = f"{url}/rest/user/login"
    
    try:
        
        s = requests.Session()
        initial_response = s.get(url, timeout=5)
        
        
        initial_cookies = s.cookies.get_dict()
        
        if not initial_cookies:
            VULNERABILITY_FINDINGS.append({"type": "Session Fixation Testing", "status": "INFO", "severity": "LOW", "details": "Could not capture an initial session cookie/ID to test."})
            return

        
        cookie_name = list(initial_cookies.keys())[0]
        fixated_id = initial_cookies[cookie_name]
        
        
        login_payload = {
            "email": "admin@juice-sh.op",
            "password": "admin"
        }
        
        login_response = s.post(login_endpoint, json=login_payload, timeout=5)
        
        
        if login_response.status_code == 200:
            final_cookies = s.cookies.get_dict()
            final_id = final_cookies.get(cookie_name)
            
            if final_id and final_id == fixated_id:
                VULNERABILITY_FINDINGS.append({
                    "type": "Session Fixation Testing",
                    "status": "VULNERABLE",
                    "severity": "HIGH",
                    "details": f"Session ID ({cookie_name}) was NOT regenerated after login (Fixated ID: {fixated_id})."
                })
            else:
                VULNERABILITY_FINDINGS.append({"type": "Session Fixation Testing", "status": "PASSED", "severity": "LOW", "details": "Session ID was regenerated after successful login."})
        
        else:
            VULNERABILITY_FINDINGS.append({"type": "Session Fixation Testing", "status": "INFO", "severity": "LOW", "details": "Known login failed (check credentials or target), test inconclusive."})

    except requests.exceptions.RequestException:
        VULNERABILITY_FINDINGS.append({"type": "Session Fixation Testing", "status": "ERROR", "severity": "MEDIUM", "details": "Check failed due to connection error."})

def generate_report(url):
    
    print("\n" + "="*50)
    print(f"| WEB SCANNER REPORT | TARGET: {url} |")
    print("="*50)
    
    if not VULNERABILITY_FINDINGS:
        print("| No scan results found. |")
        print("="*50)
        return

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

def run_scanner(url):
    print(f"Starting scan for {url}")
    
    try:
        response = requests.get(url, timeout=5)
        print(f"Status Code: {response.status_code}")
        
        if "OWASP Juice Shop" in response.text:
            check_sql_injection(url)  
            check_xss(url)            
            check_access_control(url)
            
            # --- WEEK 5 AUTHENTICATION CHECKS ---
            check_weak_credentials(url) 
            analyze_session_cookie(url) 
            simulate_brute_force(url) 
            check_session_fixation(url) # <--- FINAL WEEK 5 CALL
            # ------------------------------------------
            
            generate_report(url)
            
    except requests.exceptions.ConnectionError:
        print("[-] Fatal Error: Initial connection failed (Is Docker running?).")
    except requests.exceptions.RequestException:
        print("[-] Fatal Error: Initial connection failed due to an unknown error.")

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="WebScanPro: A simple web security scanner.")
    parser.add_argument(
        '-u', '--url', 
        type=str, 
        required=True, 
        help='The target URL to scan (e.g., http://127.0.0.1:3000)'
    )
    args = parser.parse_args()
    
    target_url = args.url
    run_scanner(target_url)
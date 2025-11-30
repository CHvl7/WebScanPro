import requests

# Function to check for SQL Injection (Refactored Error Handling)
def check_sql_injection(url):
    print("\n--- Running SQL Injection Check ---")
    
    payload = "' OR 1=1 --"
    test_url = f"{url}/users/login?username={payload}&password=test" 
    
    try:
        response = requests.get(test_url, timeout=5)
        
        # Check for typical success indicators
        if response.status_code == 200 and ("Welcome" in response.text or "Signed in" in response.text):
            print("!!! VULNERABILITY FOUND: SQL Injection may be possible with payload: " + payload)
        else:
            print("SQL Injection check passed (no simple bypass detected).")
            
    except requests.exceptions.Timeout:
        # Handle specific timeout errors
        print("[-] Error: SQL Injection check timed out.")
    except requests.exceptions.ConnectionError:
        # Handle specific connection refusal errors
        print("[-] Error: SQL Injection check failed due to connection error.")
    except requests.exceptions.RequestException:
        # Handle all other request errors
        print("[-] Error: SQL Injection check failed due to an unknown request error.")

# Function to check for Cross-Site Scripting (XSS) (Refactored Error Handling)
def check_xss(url):
    print("\n--- Running XSS Check ---")
    
    payload = "<script>alert('XSS-Test')</script>"
    test_url = f"{url}/search?q={payload}" 
    
    try:
        response = requests.get(test_url, timeout=5)
        
        # Check if the payload is reflected directly in the response body
        if payload in response.text:
            print("!!! VULNERABILITY FOUND: Possible Reflected XSS detected!")
            print("Reflected Payload: " + payload)
        else:
            print("XSS check passed (payload not directly reflected).")
            
    except requests.exceptions.Timeout:
        print("[-] Error: XSS check timed out.")
    except requests.exceptions.ConnectionError:
        print("[-] Error: XSS check failed due to connection error.")
    except requests.exceptions.RequestException:
        print("[-] Error: XSS check failed due to an unknown request error.")

# Function to check for Broken Access Control (BAC/IDOR) (Refactored Error Handling)
def check_access_control(url):
    print("\n--- Running Access Control Check (IDOR/BAC) ---")
    
    test_path = "/ftp" 
    test_url = url + test_path
    
    try:
        response = requests.get(test_url, timeout=5)
        
        # Check for success status codes (200 OK) on protected resources
        if response.status_code == 200:
            print(f"!!! VULNERABILITY FOUND: Access Control bypass (BAC) detected!")
            print(f"Unauthenticated access granted to: {test_path}")
        elif response.status_code == 403:
            print(f"Access Control check passed (access to {test_path} is correctly Forbidden/403).")
        else:
            print(f"Access Control check passed (received status code {response.status_code}).")
            
    except requests.exceptions.Timeout:
        print("[-] Error: Access Control check timed out.")
    except requests.exceptions.ConnectionError:
        print("[-] Error: Access Control check failed due to connection error.")
    except requests.exceptions.RequestException:
        print("[-] Error: Access Control check failed due to an unknown request error.")

# Main scanner function (Refactored Error Handling)
def run_scanner(url):
    print(f"Starting scan for {url}")
    
    # 1. Send a basic GET request
    print(f"Testing URL: {url}")
    try:
        response = requests.get(url, timeout=5)
        print(f"Status Code: {response.status_code}")
        
        if "OWASP Juice Shop" in response.text:
            print("Target identified as Juice Shop.")
            
            # --- VULNERABILITY CHECKS ---
            check_sql_injection(url)  
            check_xss(url)            
            check_access_control(url)
            # ---------------------------
            
    except requests.exceptions.Timeout:
        print("[-] Error: Initial connection timed out.")
    except requests.exceptions.ConnectionError:
        print("[-] Error: Initial connection failed due to target refusal (Is Docker running?).")
    except requests.exceptions.RequestException:
        print("[-] Error: Initial connection failed due to an unknown request error.")

# Execution block remains the same
if __name__ == "__main__":
    target_url = "http://127.0.0.1:3000" 
    run_scanner(target_url)
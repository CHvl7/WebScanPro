import requests

# Function to check for SQL Injection
def check_sql_injection(url):
    print("\n--- Running SQL Injection Check ---")
    
    # Define a simple SQL injection payload
    payload = "' OR 1=1 --"
    
    # Construct the URL for the simulated login test
    test_url = f"{url}/users/login?username={payload}&password=test" 
    
    try:
        response = requests.get(test_url, timeout=5)
        
        # Check for typical success indicators
        if response.status_code == 200 and ("Welcome" in response.text or "Signed in" in response.text):
            print("!!! VULNERABILITY FOUND: SQL Injection may be possible with payload: " + payload)
        else:
            print("SQL Injection check passed (no simple bypass detected).")
            
    except requests.exceptions.RequestException as e:
        print(f"Error during SQL injection check: {e}")

# Function to check for Cross-Site Scripting (XSS)
def check_xss(url):
    print("\n--- Running XSS Check ---")
    
    # Define a simple non-persistent XSS payload
    payload = "<script>alert('XSS-Test')</script>"
    
    # Construct a URL to test for reflected XSS
    test_url = f"{url}/search?q={payload}" 
    
    try:
        response = requests.get(test_url, timeout=5)
        
        # Check if the payload is reflected directly in the response body
        if payload in response.text:
            print("!!! VULNERABILITY FOUND: Possible Reflected XSS detected!")
            print("Reflected Payload: " + payload)
        else:
            print("XSS check passed (payload not directly reflected).")
            
    except requests.exceptions.RequestException as e:
        print(f"Error during XSS check: {e}")

# Function to check for Broken Access Control (BAC/IDOR)
def check_access_control(url):
    print("\n--- Running Access Control Check (IDOR/BAC) ---")
    
    # Define a common path for sensitive files or user data (e.g., /ftp, /admin)
    test_path = "/ftp"  # Testing for access to a protected directory without authorization
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
            
    except requests.exceptions.RequestException as e:
        print(f"Error during access control check: {e}")


# Main scanner function
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
            check_access_control(url) # <<< NEW ACCESS CONTROL CHECK CALL
            # ---------------------------
            
    except requests.exceptions.RequestException as e:
        print(f"Error accessing URL: {e}")

# Execution block remains the same
if __name__ == "__main__":
    target_url = "http://127.0.0.1:3000" 
    run_scanner(target_url)
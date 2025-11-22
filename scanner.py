
import requests

def run_scanner(url):
    print(f"Starting scan for {url}")

    # 1. Send a basic GET request
    print(f"Testing URL: {url}")
    try:
        response = requests.get(url, timeout=5)
        print(f"Status Code: {response.status_code}")

        # 2. Add some basic content check
        if "OWASP Juice Shop" in response.text:
            print("Target identified as Juice Shop.")

    except requests.exceptions.RequestException as e:
        print(f"Error accessing URL: {e}")

# This line ensures the scanner runs when the script is executed directly
if __name__ == "__main__":
    # Note: Replace with your actual Juice Shop URL/IP
    target_url = "http://127.0.0.1:3000" 
    run_scanner(target_url)
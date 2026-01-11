import requests
import sys

FIREWALL_URL = "http://localhost:5001"

def reset_rules():
    print(f"Connecting to Firewall at {FIREWALL_URL}...")
    try:
        response = requests.post(f"{FIREWALL_URL}/clear", timeout=5)
        if response.status_code == 200:
            print("✅ SUCCESS: All learned patterns and rules have been RESET.")
            print("   The system is now in a clean state.")
        else:
            print(f"❌ FAILED: API returned {response.status_code}")
    except Exception as e:
        print(f"❌ FAILED: Could not connect to firewall. Is it running? ({e})")

if __name__ == "__main__":
    reset_rules()

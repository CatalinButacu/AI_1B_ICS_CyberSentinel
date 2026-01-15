"""
Simple Attack Test Script
Just sends SQL injection attacks to the webapp that YOU already started.

Usage:
    1. Start your services manually (webapp, detector, firewall - whatever you want)
    2. Run: python attack_test.py
"""

import requests
import time

# Target - your running webapp
WEBAPP_URL = "http://localhost:5002/login"

# Attack payloads
ATTACKS = [
    "' OR 1=1--",
    "' OR '1'='1",
    "admin'--",
    "' UNION SELECT 1,2,3,4--",
    "' UNION SELECT 1, username, password, role FROM users--",
    "'; DROP TABLE users;--",
    "1' AND 1=1--",
    "' OR 'x'='x",
    "admin' OR '1'='1'--",
    "' UNION SELECT NULL, table_name, NULL, NULL FROM information_schema.tables--",
]

# Colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BOLD = '\033[1m'

def attack(payload):
    """Send one attack and return result."""
    try:
        response = requests.post(WEBAPP_URL, json={'username': payload, 'password': 'x'}, timeout=5)
        return response.json()
    except Exception as e:
        return {'error': str(e)}

def main():
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}       SQL INJECTION ATTACK TEST{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"Target: {WEBAPP_URL}")
    print(f"Attacks: {len(ATTACKS)}\n")
    
    success_count = 0
    blocked_count = 0
    
    for i, payload in enumerate(ATTACKS, 1):
        result = attack(payload)
        
        # Display payload (truncated)
        display_payload = payload[:35] + "..." if len(payload) > 35 else payload
        
        if result.get('error'):
            print(f"[{i:2}] {YELLOW}ERROR{RESET}   | {display_payload}")
            print(f"     -> {result['error']}")
        elif result.get('success'):
            success_count += 1
            data_count = len(result.get('data', []))
            print(f"[{i:2}] {RED}SUCCESS{RESET} | {display_payload}")
            print(f"     -> Got {data_count} records! (DATA LEAKED)")
        else:
            blocked_count += 1
            blocked_by = result.get('blocked_by', 'unknown')
            print(f"[{i:2}] {GREEN}BLOCKED{RESET} | {display_payload}")
            print(f"     -> Blocked by: {blocked_by}")
        
        time.sleep(0.3)
    
    # Summary
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}SUMMARY{RESET}")
    print(f"{'='*60}")
    print(f"  Attacks succeeded (DATA LEAKED): {RED}{success_count}{RESET}")
    print(f"  Attacks blocked:                 {GREEN}{blocked_count}{RESET}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    main()

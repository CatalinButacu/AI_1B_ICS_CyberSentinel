"""
Demo Runner - Benchmark for 3 Defense Cases
Author: Team

This script runs all 3 defense cases sequentially and shows comparison results.
It demonstrates the effectiveness of each defense layer.

Usage:
    py demo_runner.py
"""

import subprocess
import time
import requests
import os
import sys
import signal

# Colors for output
HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'

# URLs
WEBAPP_URL = "http://localhost:5002/login"
DETECTOR_URL = "http://localhost:5000"
FIREWALL_URL = "http://localhost:5001"
RESET_URL = "http://localhost:5001/clear"

# Test payloads (same for all cases)
TEST_PAYLOADS = [
    "' UNION SELECT 1, username, password || ' | ' || phone || ' | ' || address, role FROM users--",
    "' OR '1'='1",
    "admin' --",
    "' UNION SELECT 1,2,3,4--",
    "'; DROP TABLE users; --"
]


def print_header(text):
    print(f"\n{BOLD}{'='*70}{ENDC}")
    print(f"{BOLD}{text.center(70)}{ENDC}")
    print(f"{BOLD}{'='*70}{ENDC}\n")


def print_result(payload_num, payload, success, blocked_by=None):
    status = f"{OKGREEN}SUCCESS{ENDC}" if success else f"{FAIL}BLOCKED ({blocked_by}){ENDC}"
    print(f"  Payload {payload_num}: {payload[:40]:40s} -> {status}")


def wait_for_service(url, name, timeout=10):
    """Wait for a service to be available."""
    print(f"Waiting for {name}...", end=" ", flush=True)
    start = time.time()
    while time.time() - start < timeout:
        try:
            requests.get(url.replace('/login', '/health').replace('/check', '/health'), timeout=1)
            print(f"{OKGREEN}OK{ENDC}")
            return True
        except:
            time.sleep(0.5)
    print(f"{FAIL}TIMEOUT{ENDC}")
    return False


def run_attack(payload):
    """Run a single attack and return result."""
    try:
        response = requests.post(WEBAPP_URL, json={'username': payload, 'password': 'x'}, timeout=5)
        data = response.json()
        
        if data.get('success'):
            return {'success': True, 'data_count': len(data.get('data', []))}
        elif data.get('blocked_by'):
            return {'success': False, 'blocked_by': data.get('blocked_by')}
        else:
            return {'success': False, 'blocked_by': 'invalid_credentials'}
    except Exception as e:
        return {'success': False, 'blocked_by': f'error: {e}'}


def reset_firewall():
    """Reset firewall rules for clean test."""
    try:
        requests.post(RESET_URL, timeout=2)
    except:
        pass


def run_case(case_num, webapp_process_args):
    """Run a complete test for one case."""
    global webapp_proc
    
    case_names = {
        1: "NO DEFENSE",
        2: "INLINE ML DETECTION",
        3: "FULL PIPELINE"
    }
    
    print_header(f"CASE {case_num}: {case_names[case_num]}")
    
    # Start webapp with specific case
    print(f"Starting webapp with --case {case_num}...")
    
    webapp_proc = subprocess.Popen(
        ['py', 'webapp.py', '--case', str(case_num)],
        cwd=os.path.join(os.path.dirname(__file__), 'webapp'),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0
    )
    
    time.sleep(3)  # Wait for startup
    
    results = {'success': 0, 'blocked': 0, 'blocked_by': {}}
    
    for i, payload in enumerate(TEST_PAYLOADS, 1):
        result = run_attack(payload)
        
        if result['success']:
            results['success'] += 1
            print_result(i, payload, True)
        else:
            results['blocked'] += 1
            blocked_by = result['blocked_by']
            results['blocked_by'][blocked_by] = results['blocked_by'].get(blocked_by, 0) + 1
            print_result(i, payload, False, blocked_by)
        
        time.sleep(0.5)  # Small delay between attacks
    
    # Stop webapp
    webapp_proc.terminate()
    try:
        webapp_proc.wait(timeout=3)
    except:
        webapp_proc.kill()
    
    return results


def run_benchmark():
    """Run complete benchmark for all 3 cases."""
    print_header("ICS SECURITY BENCHMARK")
    print(f"Testing {len(TEST_PAYLOADS)} attack payloads across 3 defense configurations\n")
    
    all_results = {}
    
    # Case 1: No Defense
    all_results[1] = run_case(1, [])
    
    # Case 2: ML Detection (need detector running)
    print(f"\n{WARNING}[!] Case 2 requires detector service at {DETECTOR_URL}{ENDC}")
    input("Press Enter when detector is running (or Ctrl+C to skip)...")
    all_results[2] = run_case(2, [])
    
    # Case 3: Full Pipeline (need firewall + detector)
    print(f"\n{WARNING}[!] Case 3 requires firewall at {FIREWALL_URL} AND detector at {DETECTOR_URL}{ENDC}")
    reset_firewall()
    input("Press Enter when both services are running (or Ctrl+C to skip)...")
    all_results[3] = run_case(3, [])
    
    # Summary
    print_header("BENCHMARK SUMMARY")
    
    print(f"{'Case':<30} | {'Attacks Succeeded':<20} | {'Attacks Blocked':<20}")
    print("-" * 75)
    
    for case_num in [1, 2, 3]:
        r = all_results.get(case_num, {'success': 0, 'blocked': 0})
        case_names = {
            1: "Case 1: No Defense",
            2: "Case 2: ML Detection",
            3: "Case 3: Full Pipeline"
        }
        success_rate = f"{r['success']}/{len(TEST_PAYLOADS)}"
        blocked_rate = f"{r['blocked']}/{len(TEST_PAYLOADS)}"
        
        color = FAIL if r['success'] == len(TEST_PAYLOADS) else (OKGREEN if r['blocked'] == len(TEST_PAYLOADS) else WARNING)
        print(f"{case_names[case_num]:<30} | {color}{success_rate:<20}{ENDC} | {blocked_rate:<20}")
    
    print("-" * 75)
    print(f"\n{BOLD}Conclusion:{ENDC}")
    print(f"  - Case 1 (No Defense): All attacks succeed - data fully exposed")
    print(f"  - Case 2 (ML Detection): ML identifies attacks, returns NULL")
    print(f"  - Case 3 (Full Pipeline): First attack detected by ML, subsequent blocked by Firewall")
    print(f"\n{OKGREEN}Benchmark complete!{ENDC}\n")


if __name__ == "__main__":
    try:
        run_benchmark()
    except KeyboardInterrupt:
        print(f"\n{WARNING}Benchmark interrupted.{ENDC}")

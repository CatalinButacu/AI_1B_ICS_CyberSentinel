import subprocess
import time
import requests
import sys
import os
import signal

# Configuration
PYTHON_CMD = sys.executable
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, 'src')

DETECTOR_PORT = 5000
FIREWALL_PORT = 5001
WEBAPP_PORT = 5002

FAIL = '\033[91m'
OKGREEN = '\033[92m'
ENDC = '\033[0m'

processes = []

def start_service(name, script_path, port):
    print(f"[*] Starting {name} on port {port}...")
    log_file = open(f"{name.lower().replace(' ', '_')}.log", "w")
    proc = subprocess.Popen(
        [PYTHON_CMD, script_path],
        cwd=os.path.dirname(script_path),
        stdout=log_file,
        stderr=subprocess.STDOUT
    )
    processes.append(proc)
    
    # Wait for service to be ready
    url = f"http://localhost:{port}/health"
    if name == "WebApp": url = f"http://localhost:{port}/login" # Webapp might not have health
    if name == "Firewall": url = f"http://localhost:{port}/status"

    for i in range(20):
        try:
            requests.get(url, timeout=1)
            print(f"    {OKGREEN}-> {name} is UP!{ENDC}")
            return True
        except:
            time.sleep(1)
    
    print(f"    {FAIL}-> {name} failed to start. Check log file.{ENDC}")
    return False

def run_test():
    print("\n[+] All services running. Executing Test Attack...")
    
    # Payload: ' OR 1=1--  (Should be caught by Detector -> Blocked by Firewall)
    payload = "' OR 1=1--"
    target_url = f"http://localhost:{FIREWALL_PORT}/filter"
    
    print(f"    Sending payload: {payload}")
    print(f"    To: {target_url}")
    
    try:
        response = requests.post(target_url, json={"payload": payload})
        data = response.json()
        
        print("\n[RESULT]")
        print(f"Response Code: {response.status_code}")
        print(f"Response Body: {data}")
        
        if data.get('action') == 'BLOCKED' and data.get('blocked_by') == 'detector':
            print(f"\n{OKGREEN}SUCCESS! The CNN model detected the attack and the Firewall blocked it.{ENDC}")
        else:
            print(f"\n{FAIL}FAILURE! The attack was not handled as expected.{ENDC}")
            
    except Exception as e:
        print(f"{FAIL}Error during request: {e}{ENDC}")

def cleanup():
    print("\n[*] Stopping services...")
    for proc in processes:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except:
            proc.kill()
    print("Done.")

def main():
    try:
        # 1. Start Detector (Your CNN)
        if not start_service("Detector", os.path.join(SRC_DIR, 'defensive', 'detector.py'), DETECTOR_PORT):
            return

        # 2. Start Firewall
        if not start_service("Firewall", os.path.join(SRC_DIR, 'firewall', 'firewall.py'), FIREWALL_PORT):
            return
            
        # 3. Start WebApp (Case 3 = Full Pipeline)
        # Note: WebApp needs arguments
        print(f"[*] Starting WebApp (Case 3)...")
        wa_log = open("webapp.log", "w")
        wa_proc = subprocess.Popen(
            [PYTHON_CMD, 'webapp.py', '--case', '3'],
            cwd=os.path.join(SRC_DIR, 'webapp'),
            stdout=wa_log,
            stderr=subprocess.STDOUT
        )
        processes.append(wa_proc)
        time.sleep(3) # Give it time blindly as it might take a moment
        
        # 4. Run Verification
        run_test()
        
    except KeyboardInterrupt:
        print("\nAborted.")
    finally:
        cleanup()

if __name__ == "__main__":
    main()

"""
Firewall Benchmark - Large Scale Testing
Tests the firewall with hundreds of payloads and measures performance.

Usage:
    1. Start services: detector.py, firewall.py --case 2, webapp.py
    2. Run: python benchmark_firewall.py
"""

import requests
import time
import random
import string
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
FIREWALL_URL = "http://localhost:5001"
DETECTOR_URL = "http://localhost:5000"
NUM_ATTACKS = 100
NUM_SAFE = 50
CONCURRENT_WORKERS = 5

# Colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

# ============================================================
# PAYLOAD GENERATORS
# ============================================================

SQL_INJECTION_TEMPLATES = [
    "' OR {n}={n}--",
    "' OR '{c}'='{c}",
    "admin'{comment}",
    "' UNION SELECT {cols}--",
    "' UNION SELECT NULL,{cols}--",
    "'; DROP TABLE {table};--",
    "' AND {n}={n}--",
    "' OR 'x'='x",
    "1' AND SLEEP({n})--",
    "' UNION SELECT username,password FROM {table}--",
    "' OR EXISTS(SELECT * FROM {table})--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 {col} FROM {table}))--",
    "'; EXEC xp_cmdshell('dir');--",
    "' HAVING 1=1--",
    "' GROUP BY {col} HAVING 1=1--",
    "' ORDER BY {n}--",
    "' AND ASCII(SUBSTRING((SELECT {col} FROM {table}),1,1))>{n}--",
    "'; WAITFOR DELAY '0:0:{n}';--",
    "' OR {n} BETWEEN {n} AND {n2}--",
    "' UNION ALL SELECT {cols}--",
]

TABLES = ['users', 'accounts', 'admin', 'customers', 'orders', 'products']
COLUMNS = ['username', 'password', 'email', 'id', 'name', 'credit_card']
COMMENTS = ['--', '/*', '#', '-- -', '/**/']

SAFE_QUERIES = [
    "SELECT name FROM products WHERE id={n}",
    "INSERT INTO logs (action) VALUES ('login')",
    "UPDATE users SET last_login=NOW() WHERE id={n}",
    "john.doe@email.com",
    "Hello World",
    "user_{n}",
    "search query: {word}",
    "product name with spaces",
    "simple text input",
    "12345",
]

def generate_attack_payload():
    """Generate a random SQL injection payload."""
    template = random.choice(SQL_INJECTION_TEMPLATES)
    
    payload = template.format(
        n=random.randint(1, 100),
        n2=random.randint(101, 200),
        c=random.choice(string.ascii_lowercase),
        cols=','.join([str(i) for i in range(1, random.randint(3, 6))]),
        table=random.choice(TABLES),
        col=random.choice(COLUMNS),
        comment=random.choice(COMMENTS),
        word=''.join(random.choices(string.ascii_lowercase, k=5))
    )
    return payload

def generate_safe_payload():
    """Generate a random safe query."""
    template = random.choice(SAFE_QUERIES)
    return template.format(
        n=random.randint(1, 1000),
        word=''.join(random.choices(string.ascii_lowercase, k=8))
    )

# ============================================================
# TESTING FUNCTIONS
# ============================================================

def test_single_payload(payload, endpoint, expected_attack=True):
    """Test a single payload and return results."""
    start_time = time.time()
    
    try:
        if endpoint == "detector":
            response = requests.post(
                f"{DETECTOR_URL}/check",
                json={"payload": payload},
                timeout=10
            )
        else:  # firewall
            response = requests.post(
                f"{FIREWALL_URL}/filter",
                json={"payload": payload},
                timeout=10
            )
        
        elapsed = (time.time() - start_time) * 1000  # ms
        data = response.json()
        
        # Determine if correctly classified
        if endpoint == "detector":
            detected = data.get('is_attack', False)
        else:
            detected = data.get('action') == 'BLOCKED'
        
        correct = (detected == expected_attack)
        
        return {
            'payload': payload,
            'expected_attack': expected_attack,
            'detected': detected,
            'correct': correct,
            'response_time_ms': elapsed,
            'confidence': data.get('confidence', 0),
            'blocked_by': data.get('blocked_by', 'N/A'),
            'error': None
        }
        
    except Exception as e:
        return {
            'payload': payload,
            'expected_attack': expected_attack,
            'detected': False,
            'correct': False,
            'response_time_ms': 0,
            'error': str(e)
        }

def run_benchmark(endpoint="firewall"):
    """Run the full benchmark."""
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}      FIREWALL BENCHMARK - LARGE SCALE TESTING{RESET}")
    print(f"{BOLD}{'='*70}{RESET}")
    print(f"Target: {FIREWALL_URL if endpoint == 'firewall' else DETECTOR_URL}")
    print(f"Attack payloads: {NUM_ATTACKS}")
    print(f"Safe payloads: {NUM_SAFE}")
    print(f"Concurrent workers: {CONCURRENT_WORKERS}")
    print(f"{'='*70}\n")
    
    # Generate payloads
    print(f"{CYAN}[1/4] Generating payloads...{RESET}")
    attacks = [(generate_attack_payload(), True) for _ in range(NUM_ATTACKS)]
    safe = [(generate_safe_payload(), False) for _ in range(NUM_SAFE)]
    all_payloads = attacks + safe
    random.shuffle(all_payloads)
    print(f"      Generated {len(all_payloads)} total payloads\n")
    
    # Run tests
    print(f"{CYAN}[2/4] Running tests...{RESET}")
    results = []
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
        futures = {
            executor.submit(test_single_payload, payload, endpoint, is_attack): (payload, is_attack)
            for payload, is_attack in all_payloads
        }
        
        completed = 0
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            completed += 1
            
            # Progress indicator
            if completed % 20 == 0:
                print(f"      Progress: {completed}/{len(all_payloads)}")
    
    total_time = time.time() - start_time
    print(f"      Completed in {total_time:.2f}s\n")
    
    # Analyze results
    print(f"{CYAN}[3/4] Analyzing results...{RESET}\n")
    
    # Separate attack and safe results
    attack_results = [r for r in results if r['expected_attack']]
    safe_results = [r for r in results if not r['expected_attack']]
    
    # Calculate metrics
    true_positives = sum(1 for r in attack_results if r['detected'])
    false_negatives = sum(1 for r in attack_results if not r['detected'])
    true_negatives = sum(1 for r in safe_results if not r['detected'])
    false_positives = sum(1 for r in safe_results if r['detected'])
    
    # Response times
    response_times = [r['response_time_ms'] for r in results if r['error'] is None]
    
    # Blocked by analysis (for firewall)
    blocked_by_counts = {}
    for r in results:
        if r.get('blocked_by') and r['detected']:
            key = r['blocked_by']
            blocked_by_counts[key] = blocked_by_counts.get(key, 0) + 1
    
    # Print results
    print(f"{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}                         BENCHMARK RESULTS{RESET}")
    print(f"{'='*70}\n")
    
    # Detection metrics
    detection_rate = (true_positives / len(attack_results) * 100) if attack_results else 0
    false_positive_rate = (false_positives / len(safe_results) * 100) if safe_results else 0
    accuracy = ((true_positives + true_negatives) / len(results) * 100) if results else 0
    
    precision = (true_positives / (true_positives + false_positives) * 100) if (true_positives + false_positives) > 0 else 0
    recall = (true_positives / (true_positives + false_negatives) * 100) if (true_positives + false_negatives) > 0 else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0
    
    print(f"{BOLD}DETECTION METRICS:{RESET}")
    print(f"  {'Attack Detection Rate:':<30} {GREEN}{detection_rate:>6.1f}%{RESET} ({true_positives}/{len(attack_results)} attacks caught)")
    print(f"  {'False Positive Rate:':<30} {YELLOW if false_positive_rate > 10 else GREEN}{false_positive_rate:>6.1f}%{RESET} ({false_positives}/{len(safe_results)} safe blocked)")
    print(f"  {'Overall Accuracy:':<30} {accuracy:>6.1f}%")
    print(f"  {'Precision:':<30} {precision:>6.1f}%")
    print(f"  {'Recall:':<30} {recall:>6.1f}%")
    print(f"  {'F1 Score:':<30} {f1:>6.1f}%")
    
    print(f"\n{BOLD}CONFUSION MATRIX:{RESET}")
    print(f"                    Predicted")
    print(f"                 ATTACK    SAFE")
    print(f"  Actual ATTACK   {GREEN}{true_positives:>4}{RESET}    {RED}{false_negatives:>4}{RESET}")
    print(f"  Actual SAFE     {YELLOW}{false_positives:>4}{RESET}    {GREEN}{true_negatives:>4}{RESET}")
    
    if response_times:
        print(f"\n{BOLD}PERFORMANCE METRICS:{RESET}")
        print(f"  {'Total test time:':<30} {total_time:>6.2f}s")
        print(f"  {'Requests per second:':<30} {len(results)/total_time:>6.1f}")
        print(f"  {'Avg response time:':<30} {statistics.mean(response_times):>6.1f}ms")
        print(f"  {'Median response time:':<30} {statistics.median(response_times):>6.1f}ms")
        print(f"  {'Min response time:':<30} {min(response_times):>6.1f}ms")
        print(f"  {'Max response time:':<30} {max(response_times):>6.1f}ms")
        if len(response_times) > 1:
            print(f"  {'Std deviation:':<30} {statistics.stdev(response_times):>6.1f}ms")
    
    if blocked_by_counts:
        print(f"\n{BOLD}BLOCKED BY BREAKDOWN:{RESET}")
        for method, count in sorted(blocked_by_counts.items(), key=lambda x: -x[1]):
            pct = count / true_positives * 100 if true_positives > 0 else 0
            print(f"  {method:<30} {count:>4} ({pct:.1f}%)")
    
    # Show some missed attacks
    missed = [r for r in attack_results if not r['detected']][:5]
    if missed:
        print(f"\n{BOLD}{RED}SAMPLE MISSED ATTACKS (False Negatives):{RESET}")
        for r in missed:
            print(f"  {r['payload'][:60]}...")
    
    # Show false positives
    fps = [r for r in safe_results if r['detected']][:5]
    if fps:
        print(f"\n{BOLD}{YELLOW}SAMPLE FALSE POSITIVES:{RESET}")
        for r in fps:
            print(f"  {r['payload'][:60]}...")
    
    print(f"\n{'='*70}")
    print(f"{BOLD}BENCHMARK COMPLETE{RESET}")
    print(f"{'='*70}\n")
    
    return results

def check_services():
    """Check if services are running."""
    print(f"{CYAN}Checking services...{RESET}")
    
    try:
        r = requests.get(f"{DETECTOR_URL}/health", timeout=2)
        print(f"  Detector: {GREEN}OK{RESET}")
    except:
        print(f"  Detector: {RED}NOT RUNNING{RESET}")
        return False
    
    try:
        r = requests.get(f"{FIREWALL_URL}/status", timeout=2)
        data = r.json()
        print(f"  Firewall: {GREEN}OK{RESET} (Case {data.get('case', '?')}, {data.get('patterns_count', 0)} patterns)")
    except:
        print(f"  Firewall: {RED}NOT RUNNING{RESET}")
        return False
    
    return True

if __name__ == "__main__":
    print(f"\n{BOLD}ICS SECURITY BENCHMARK{RESET}")
    print(f"Testing firewall defense effectiveness at scale\n")
    
    if not check_services():
        print(f"\n{RED}ERROR: Services not running. Start detector and firewall first.{RESET}")
        exit(1)
    
    # Reset firewall before test
    print(f"\n{CYAN}Resetting firewall for clean test...{RESET}")
    try:
        requests.post(f"{FIREWALL_URL}/reset", timeout=5)
        print(f"  {GREEN}Reset complete{RESET}\n")
    except:
        print(f"  {YELLOW}Could not reset (continuing anyway){RESET}\n")
    
    # Run benchmark
    run_benchmark("firewall")

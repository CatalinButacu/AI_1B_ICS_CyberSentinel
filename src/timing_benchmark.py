"""
Response Time Benchmark - Measures timing for each defense scenario
"""

import requests
import time
import statistics

FIREWALL_URL = "http://localhost:5001"
DETECTOR_URL = "http://localhost:5000"

# Colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Test payloads for each scenario
KNOWN_ATTACK_PATTERNS = [  # Should be blocked by firewall pattern
    "' UNION SELECT 1,2,3,4--",
    "' OR 1=1--",
    "' AND 1=1--",
]

NEW_ATTACKS = [  # Blocked by ML (not yet in patterns)
    "' HAVING 1=1--",
    "'; SHUTDOWN;--",
    "' AND ASCII(SUBSTRING(password,1,1))>50--",
    "1' AND (SELECT COUNT(*) FROM users)>0--",
]

SAFE_QUERIES = [  # Should pass both firewall and ML
    "john.doe@email.com",
    "Hello World",
    "normal search query",
    "user123",
    "product name here",
]

def measure_response(url, payload, runs=10):
    """Measure response time for a payload."""
    times = []
    results = []
    
    for _ in range(runs):
        start = time.perf_counter()
        try:
            response = requests.post(url, json={"payload": payload}, timeout=10)
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
            results.append(response.json())
        except Exception as e:
            pass
    
    if not times:
        return None, None, None
    
    return statistics.median(times), min(times), max(times), results[0] if results else {}

def run_timing_benchmark():
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}      RESPONSE TIME BENCHMARK BY SCENARIO{RESET}")
    print(f"{'='*70}\n")
    
    # Check firewall status
    try:
        status = requests.get(f"{FIREWALL_URL}/status").json()
        print(f"Firewall Case: {status.get('case')}")
        print(f"Known Patterns: {status.get('patterns_count')}")
        print()
    except:
        print(f"{RED}Firewall not reachable!{RESET}")
        return
    
    scenarios = {
        "Firewall REJECT (Pattern Match)": [],
        "Firewall PASS → ML REJECT": [],
        "Firewall PASS → ML PASS": [],
    }
    
    # ============================================================
    # Scenario 1: Firewall Pattern Reject (fastest)
    # ============================================================
    print(f"{CYAN}Testing Scenario 1: Firewall Pattern Reject...{RESET}")
    for payload in KNOWN_ATTACK_PATTERNS:
        result = measure_response(f"{FIREWALL_URL}/filter", payload)
        if result[0]:
            median, min_t, max_t, resp = result
            blocked_by = resp.get('blocked_by', 'unknown')
            if blocked_by == 'firewall_pattern':
                scenarios["Firewall REJECT (Pattern Match)"].append(median)
                print(f"  ✓ {payload[:30]:30} → {median:.1f}ms (pattern)")
            else:
                # Not actually blocked by pattern, might be ML
                scenarios["Firewall PASS → ML REJECT"].append(median)
                print(f"  ⚠ {payload[:30]:30} → {median:.1f}ms ({blocked_by})")
    
    # ============================================================
    # Scenario 2: Firewall Pass → ML Reject
    # ============================================================
    print(f"\n{CYAN}Testing Scenario 2: Firewall Pass → ML Reject...{RESET}")
    for payload in NEW_ATTACKS:
        result = measure_response(f"{FIREWALL_URL}/filter", payload)
        if result[0]:
            median, min_t, max_t, resp = result
            blocked_by = resp.get('blocked_by', 'unknown')
            if 'ml' in blocked_by.lower():
                scenarios["Firewall PASS → ML REJECT"].append(median)
                print(f"  ✓ {payload[:30]:30} → {median:.1f}ms (ML)")
            elif blocked_by == 'firewall_pattern':
                scenarios["Firewall REJECT (Pattern Match)"].append(median)
                print(f"  ⚠ {payload[:30]:30} → {median:.1f}ms (already learned)")
    
    # ============================================================
    # Scenario 3: Firewall Pass → ML Pass (allowed)
    # ============================================================
    print(f"\n{CYAN}Testing Scenario 3: Firewall Pass → ML Pass...{RESET}")
    for payload in SAFE_QUERIES:
        result = measure_response(f"{FIREWALL_URL}/filter", payload)
        if result[0]:
            median, min_t, max_t, resp = result
            action = resp.get('action', 'unknown')
            if action == 'ALLOWED':
                scenarios["Firewall PASS → ML PASS"].append(median)
                print(f"  ✓ {payload[:30]:30} → {median:.1f}ms (allowed)")
    
    # ============================================================
    # Summary
    # ============================================================
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}                    TIMING SUMMARY{RESET}")
    print(f"{'='*70}\n")
    
    print(f"{'Scenario':<40} | {'Median':>10} | {'Min':>10} | {'Max':>10}")
    print("-" * 75)
    
    for scenario, times in scenarios.items():
        if times:
            median = statistics.median(times)
            min_t = min(times)
            max_t = max(times)
            
            # Color based on speed
            if median < 20:
                color = GREEN
            elif median < 100:
                color = YELLOW
            else:
                color = RED
            
            print(f"{scenario:<40} | {color}{median:>8.1f}ms{RESET} | {min_t:>8.1f}ms | {max_t:>8.1f}ms")
        else:
            print(f"{scenario:<40} | {'N/A':>10} | {'N/A':>10} | {'N/A':>10}")
    
    print("-" * 75)
    
    # Speed comparison
    print(f"\n{BOLD}SPEED COMPARISON:{RESET}")
    
    fw_times = scenarios["Firewall REJECT (Pattern Match)"]
    ml_times = scenarios["Firewall PASS → ML REJECT"]
    safe_times = scenarios["Firewall PASS → ML PASS"]
    
    if fw_times and ml_times:
        speedup = statistics.median(ml_times) / statistics.median(fw_times)
        print(f"  Pattern matching is {GREEN}{speedup:.1f}x faster{RESET} than ML detection")
    
    print(f"\n{BOLD}INTERPRETATION:{RESET}")
    print(f"  • Firewall Pattern Match: Fastest (no ML call needed)")
    print(f"  • ML Reject: Slower (requires ML inference)")
    print(f"  • ML Pass: Similar to ML Reject (full pipeline)")
    
    print(f"\n{'='*70}\n")

if __name__ == "__main__":
    run_timing_benchmark()

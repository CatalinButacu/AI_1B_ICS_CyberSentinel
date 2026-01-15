import requests
import concurrent.futures
import time
import os
import sys

# --- CONFIGURATION ---
INPUT_FILE = 'attacks.txt'  # Ensure this matches your file name
API_URL = "http://localhost:5000/check"
MAX_WORKERS = 20  # 20 Parallel threads


def check_query(session, query):
    """Sends a single query using a shared session"""
    try:
        # Timeout ensures we don't get stuck if server hangs
        response = session.post(API_URL, json={"query": query}, timeout=2)
        if response.status_code == 200:
            data = response.json()
            return data.get("is_attack", False)
    except:
        return False
    return False


def main():
    if not os.path.exists(INPUT_FILE):
        print(f" Error: File '{INPUT_FILE}' not found.")
        return

    print("Loading dataset...")
    with open(INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        attacks = [line.strip() for line in f if line.strip()]

    total = len(attacks)
    print(f"🚀 Starting Test on {total} queries...")
    print(f"⚡ Threads: {MAX_WORKERS}")

    detected = 0
    start_time = time.time()

    # Reuse TCP connections with Session (Huge speed boost)
    with requests.Session() as session:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Submit all tasks
            future_to_query = {executor.submit(check_query, session, q): q for q in attacks}

            # Process results as they come in
            for i, future in enumerate(concurrent.futures.as_completed(future_to_query)):
                if future.result():
                    detected += 1

                # Update progress bar every 200 items (Reduces console lag)
                if i % 200 == 0:
                    elapsed = time.time() - start_time
                    speed = (i + 1) / (elapsed + 0.001)
                    sys.stdout.write(
                        f"\rProgress: {100 * i / total:.1f}% | Speed: {speed:.0f} req/s | Detected: {detected}")
                    sys.stdout.flush()

    duration = time.time() - start_time
    recall = (detected / total) * 100 if total > 0 else 0

    print(f"\n\n{'=' * 40}")
    print(f"FINAL RESULTS (Time: {duration:.2f}s)")
    print(f"{'=' * 40}")
    print(f"Total Queries:     {total}")
    print(f"Detected Attacks:  {detected}")
    print(f"RECALL SCORE:      {recall:.2f}%")
    print(f"{'=' * 40}")


if __name__ == "__main__":
    main()
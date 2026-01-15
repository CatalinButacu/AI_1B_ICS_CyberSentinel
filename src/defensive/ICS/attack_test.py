import requests
import concurrent.futures
import time
import os

INPUT_FILE = 'attacks.txt'
API_URL = "http://localhost:5000/check"
MAX_WORKERS = 20


def check_query(session, query):
    try:
        response = session.post(API_URL, json={"query": query})
        if response.status_code == 200:
            data = response.json()
            return data.get("is_attack", False)
    except:
        return False
    return False


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"File {INPUT_FILE} not found.")
        return

    with open(INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        attacks = [line.strip() for line in f if line.strip()]

    total = len(attacks)
    print(f"Testing {total} queries...")
    print(f"Threads: {MAX_WORKERS} | Target: {API_URL}")

    detected = 0
    start_time = time.time()

    with requests.Session() as session:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_query = {executor.submit(check_query, session, q): q for q in attacks}

            for i, future in enumerate(concurrent.futures.as_completed(future_to_query)):
                is_attack = future.result()
                if is_attack:
                    detected += 1

                if i % 500 == 0:
                    percent = (i / total) * 100
                    elapsed = time.time() - start_time
                    speed = (i + 1) / elapsed
                    print(f"Progress: {percent:.1f}% | Speed: {speed:.0f} req/sec | Detected: {detected}", end='\r')

    duration = time.time() - start_time
    recall = (detected / total) * 100

    print(f"\n\n{'=' * 40}")
    print(f"FINAL REPORT (Time: {duration:.2f}s)")
    print(f"{'=' * 40}")
    print(f"Total Queries:     {total}")
    print(f"Detected Attacks:  {detected}")
    print(f"Recall Score:      {recall:.2f}%")
    print(f"{'=' * 40}")


if __name__ == "__main__":
    main()
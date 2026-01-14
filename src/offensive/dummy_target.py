from flask import Flask, request, jsonify
import re

app = Flask(__name__)

# Basic WAF Logic
BLACKLIST = [
    r"union",
    r"select",
    r"drop",
    r"--"
]

def check_waf(payload):
    payload_lower = payload.lower()
    for pattern in BLACKLIST:
        if pattern in payload_lower:
            return True, pattern
    return False, None

@app.route('/login', methods=['GET'])
def login():
    query = request.args.get('q', '')
    
    # Simulate WAF
    is_blocked, reason = check_waf(query)
    if is_blocked:
        return f"Blocked by WAF! Pattern: {reason}", 403
    
    # Simulate Vulnerable Backend
    # If the WAF didn't catch it, and it looks like a SQLi, it 'succeeds'
    if "'" in query:
        return "Internal Server Error: Syntax error in SQL statement...", 200 # 200 for 'success' in bypassing WAF logic
        
    return "Login Failed", 401

if __name__ == '__main__':
    print("Starting Dummy Target on Port 5000...")
    app.run(port=5000)

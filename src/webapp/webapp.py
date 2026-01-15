"""
Vulnerable Web Application - Target for SQL Injection Testing
Author: Team

WARNING: This application is INTENTIONALLY VULNERABLE.
         Use only for educational purposes in isolated environments.

This simulates a real e-commerce database with:
- Users table (credentials, emails, phone, address)
- Products table (inventory)
- Orders table (purchase history with shipping details)

Supports 3 defense cases:
- Case 1: No defense (fully vulnerable)
- Case 2: Inline ML detection (Beatrice)
- Case 3: Full pipeline (Firewall + Beatrice)
"""

import os
import sys
import sqlite3
import argparse
from flask import Flask, request, jsonify, render_template, redirect, url_for

# Add parent directory for shared imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from shared.pipeline import DefensePipeline
from shared.config import DETECTOR_URL, FIREWALL_URL, WEBAPP_URL, ENVIRONMENT

app = Flask(__name__)

DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'data', 'shop.db')

# Pipeline will be stored in app.config['pipeline']


def get_database_connection():
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # Allow accessing columns by name
    return conn


def initialize_database():
    conn = get_database_connection()
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT,
            address TEXT,
            credit_card TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            total REAL,
            shipping_address TEXT,
            phone TEXT,
            status TEXT DEFAULT 'pending',
            order_date TEXT
        )
    ''')
    
    # Insert sample data (sensitive information)
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        users = [
            ('admin', 'admin123', 'admin@eshop.ro', '0721-111-111', 'Str. Victoriei 10, Bucuresti', '4111-1111-1111-1111', 'admin'),
            ('ion_popescu', 'parola123', 'ion.popescu@yahoo.com', '0722-222-222', 'Bd. Unirii 45, Apt. 12, Sector 3, Bucuresti', '4222-2222-2222-2222', 'user'),
            ('maria_ionescu', 'maria2023', 'maria.ionescu@gmail.com', '0733-333-333', 'Str. Libertatii 78, Bl. A3, Sc. B, Et. 4, Ap. 16, Cluj-Napoca', '4333-3333-3333-3333', 'user'),
            ('alex_radu', 'dinamo1948', 'alex.radu@outlook.com', '0744-444-444', 'Aleea Florilor 23, Timisoara, Jud. Timis', '4444-4444-4444-4444', 'user'),
            ('vip_client', 'b banii', 'vip@business.ro', '0755-555-555', 'Str. Republicii 1, Penthouse, Brasov', '4555-5555-5555-5555', 'vip'),
        ]
        cursor.executemany(
            "INSERT INTO users (username, password, email, phone, address, credit_card, role) VALUES (?, ?, ?, ?, ?, ?, ?)",
            users
        )
        
        products = [
            ('Laptop Apple MacBook Air 13 M1, 8GB RAM, 256GB SSD, Space Grey', 4299.99, 15),
            ('Telefon mobil Samsung Galaxy S24 Ultra, Dual SIM, 12GB RAM, 512GB, Titanium Black', 6299.99, 50),
            ('Televizor Samsung LED 50CU7172, 125 cm, Smart, 4K Ultra HD, Clasa G', 1899.00, 30),
            ('Masina de spalat rufe Arctic APL71012BDW0, 7 kg, 1000 RPM, Clasa D, Alb', 1199.99, 20),
            ('Consola PlayStation 5 (PS5) Slim, 1TB SSD, D-Chassis', 2699.99, 100),
            ('Monitor Gaming LED IPS ASUS TUF 27", Full HD, 165Hz, 1ms, FreeSync Premium', 899.99, 45),
            ('Casti Wireless Over-Ear Sony WH-1000XM5, Noise Cancelling, Microfon, Bluetooth', 1399.00, 60),
            ('Scaun Gaming Dr.Shield, King Size, Piele Ecologica, Negru/Rosu', 649.99, 10),
            ('Espressor automat Philips Seria 5400 EP5443/90, Sistem LatteGo', 2999.99, 25),
            ('Mouse Gaming Wireless Logitech G502 LIGHTSPEED HERO 25K', 449.99, 80),
        ]
        cursor.executemany(
            "INSERT INTO products (name, price, stock) VALUES (?, ?, ?)",
            products
        )
        
        # Insert sample orders with shipping details
        orders = [
            (2, 1, 1, 4299.99, 'Bd. Unirii 45, Apt. 12, Sector 3, Bucuresti', '0722-222-222', 'delivered', '2026-01-05'),
            (3, 5, 2, 5399.98, 'Str. Libertatii 78, Bl. A3, Sc. B, Et. 4, Ap. 16, Cluj-Napoca', '0733-333-333', 'shipped', '2026-01-08'),
            (4, 2, 1, 6299.99, 'Aleea Florilor 23, Timisoara, Jud. Timis', '0744-444-444', 'pending', '2026-01-10'),
            (5, 9, 1, 2999.99, 'Str. Republicii 1, Penthouse, Brasov', '0755-555-555', 'delivered', '2026-01-02'),
            (2, 7, 1, 1399.00, 'Bd. Unirii 45, Apt. 12, Sector 3, Bucuresti', '0722-222-222', 'shipped', '2026-01-09'),
        ]
        cursor.executemany(
            "INSERT INTO orders (user_id, product_id, quantity, total, shipping_address, phone, status, order_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            orders
        )
        
        print("Database initialized with realistic eShop data (including PII)")
    
    conn.commit()
    conn.close()


# =============================================================================
# VULNERABLE ENDPOINTS
# =============================================================================

@app.route('/')
def home():
    conn = get_database_connection()
    products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()
    return render_template('index.html', products=products)


@app.route('/login', methods=['GET', 'POST'])
def vulnerable_login():
    """
    VULNERABLE: Direct string concatenation allows SQL injection.
    Supports both JSON (for attacker agent) and Form Data (for browser UI).
    """
    if request.method == 'GET':
        return render_template('login.html')

    # Handle both JSON and Form Data
    if request.is_json:
        data = request.json
        username = data.get('username', '')
        password = data.get('password', '')
        is_api = True
    else:
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        is_api = False
    
    conn = get_database_connection()
    cursor = conn.cursor()
    
    # INLINE DEFENSE CHECK (before SQL execution)
    pipeline = app.config.get('pipeline')
    
    if pipeline and pipeline.case > 1:
        is_allowed, reason, details = pipeline.check_request(username)
        
        if not is_allowed:
            conn.close()
            print(f"[BLOCKED] {reason}: {username[:40]}...")
            
            if is_api:
                return jsonify({
                    'success': False,
                    'message': 'Request blocked by security layer',
                    'blocked_by': reason,
                    'data': None  # Return NULL as specified
                })
            else:
                return render_template('login.html', error=f"Blocked: {reason}", blocked=True)
    
    # VULNERABLE: SQL Injection here! (only reached if allowed or Case 1)
    query = f"SELECT id, username, email, role FROM users WHERE username='{username}' AND password='{password}'"
    
    print(f"[QUERY] {query}")
    
    try:
        cursor.execute(query)
        result = cursor.fetchall()  # Use fetchall to get ALL data if injected
        conn.close()
        
        if result:
            user_data = [{'id': r['id'], 'username': r['username'], 'email': r['email'], 'role': r['role']} for r in result]
            
            if is_api:
                return jsonify({
                    'success': True, 
                    'message': 'Login successful',
                    'data': user_data,
                    'query_executed': query
                })
            else:
                return render_template('login.html', success=True, user=result[0], data=user_data, query_executed=query)
        else:
            if is_api:
                return jsonify({
                    'success': False, 
                    'message': 'Invalid credentials',
                    'query_executed': query
                })
            else:
                return render_template('login.html', error="Date incorecte", query_executed=query)
            
    except Exception as e:
        conn.close()
        if is_api:
            return jsonify({'success': False, 'error': str(e), 'query_executed': query}), 500
        else:
            return render_template('login.html', error=f"Database Error: {str(e)}", query_executed=query)


@app.route('/search', methods=['GET'])
def vulnerable_search():
    """VULNERABLE: Product search with SQL injection."""
    query_param = request.args.get('q', '')
    
    conn = get_database_connection()
    cursor = conn.cursor()
    
    # VULNERABLE: SQL Injection here!
    # Normal: SELECT * FROM products WHERE name LIKE '%laptop%'
    # Attack: SELECT * FROM products WHERE name LIKE '%' UNION SELECT 1,username,password,4 FROM users--%'
    
    if not query_param:
        return redirect(url_for('home'))

    query = f"SELECT id, name, price, stock FROM products WHERE name LIKE '%{query_param}%'"
    
    print(f"[QUERY] {query}")
    
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        conn.close()
        
        # If API request (check Accept header or something, but defaulting to HTML for browser)
        # For simplicity, we return HTML if not explicitly asking for JSON
        
        products = [{'id': r['id'], 'name': r['name'], 'price': r['price'], 'stock': r['stock']} for r in result]
        
        return render_template('index.html', products=products, query_executed=query)
        
    except Exception as e:
        conn.close()
        return render_template('index.html', products=[], error=str(e), query_executed=query)


# =============================================================================
# INFO ENDPOINTS
# =============================================================================

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'vulnerable', 'database': 'sqlite'})


def main():
    """Start the vulnerable web application.
    
    The webapp now auto-detects if Defense services are available:
    - If Firewall (5001) + Detector (5000) are up → Full Pipeline (Case 3)
    - If only Detector (5000) is up → ML Detection (Case 2)
    - If nothing is up → No Defense (Case 1)
    
    Control scenarios from Defense machine by starting/stopping services.
    """
    import requests
    
    # Auto-detect which defense services are available
    detector_available = False
    firewall_available = False
    
    try:
        r = requests.get(f'{DETECTOR_URL}/health', timeout=1)
        detector_available = r.status_code == 200
    except:
        pass
    
    try:
        r = requests.get(f'{FIREWALL_URL}/status', timeout=1)
        firewall_available = r.status_code == 200
    except:
        pass
    
    # Determine case based on available services
    if firewall_available and detector_available:
        case = 3
    elif detector_available:
        case = 2
    else:
        case = 1
    
    # Initialize defense pipeline
    app.config['pipeline'] = DefensePipeline(case=case)
    
    print("="*60)
    case_names = {
        1: "NO DEFENSE (Fully Vulnerable)",
        2: "INLINE ML DETECTION",
        3: "FULL PIPELINE (Firewall + ML)"
    }
    print(f"E-SHOP - CASE {case}: {case_names[case]}")
    print("="*60)
    
    if case == 1:
        print("\nNo defense services detected - running vulnerable!")
    elif case == 2:
        print(f"\nDetector found at {DETECTOR_URL}")
    elif case == 3:
        print(f"\nFirewall found at {FIREWALL_URL}")
        print(f"Detector found at {DETECTOR_URL}")
    
    print("\nUse only for educational testing.\n")
    
    initialize_database()
    
    print(f"\nStarting on http://0.0.0.0:5002")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5002, debug=False)


if __name__ == "__main__":
    main()

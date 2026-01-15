import pickle
import os
import pandas as pd

MODEL_PATH = r'c:\Users\catalin.butacu\Downloads\ICS\src\defensive\models\sqli_detector.pkl'

def test_differentiation():
    if not os.path.exists(MODEL_PATH):
        print("Model file not found!")
        return

    with open(MODEL_PATH, 'rb') as f:
        bundle = pickle.load(f)
        model = bundle['model']
        vectorizer = bundle['vectorizer']

    test_queries = {
        "Hacker - Classic SQLi": "' OR 1=1 --",
        "Hacker - Union Select": "' UNION SELECT username, password FROM users --",
        "Hacker - Drop Table": "'; DROP TABLE sensitive_data; --",
        "Hacker - Blind SQLi": "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
        
        "Dev - Complex Join": "SELECT a.name, b.total FROM users a JOIN (SELECT user_id, SUM(amount) as total FROM orders GROUP BY user_id) b ON a.id = b.user_id WHERE b.total > 1000",
        "Dev - CTE & Window": "WITH MonthlySales AS (SELECT product_id, sale_date, amount, SUM(amount) OVER (PARTITION BY product_id ORDER BY sale_date) as running_total FROM sales) SELECT * FROM MonthlySales WHERE running_total > 5000",
        "Dev - Nested Aggregation": "SELECT category, AVG(price) FROM products WHERE id IN (SELECT product_id FROM order_items GROUP BY product_id HAVING COUNT(*) > 10) GROUP BY category",
        "Dev - Multi-line Complex": "SELECT u.id, u.email, profile.bio, stats.last_login\nFROM users u\nLEFT JOIN profiles profile ON u.id = profile.user_id\nLEFT JOIN (SELECT user_id, MAX(login_time) as last_login FROM logins GROUP BY user_id) stats ON u.id = stats.user_id\nWHERE u.status = 'active' AND profile.verified = 1"
    }

    print(f"{'Type - Description':<40} | {'Prediction':<10} | {'Confidence (Normal/Attack)':<30}")
    print("-" * 85)

    for desc, query in test_queries.items():
        vec = vectorizer.transform([query])
        prediction = model.predict(vec)[0]
        proba = model.predict_proba(vec)[0]
        
        label = "ATTACK" if prediction == 1 else "NORMAL"
        print(f"{desc:<40} | {label:<10} | {proba[0]:.2f} / {proba[1]:.2f}")

if __name__ == "__main__":
    test_differentiation()

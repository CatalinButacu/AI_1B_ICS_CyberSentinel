"""
Generate Labeled Dataset for ML Detector Training
Creates a balanced dataset with both attack and benign SQL queries.

Output format: CSV with columns [query, label]
- label = 1: Attack (malicious SQL injection)
- label = 0: Benign (normal SQL query)
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.generator import generate_dataset
import random
import csv

# Benign SQL queries (normal database operations)
BENIGN_QUERIES = [
    # SELECT queries
    "SELECT * FROM users WHERE id = 1",
    "SELECT name, email FROM customers WHERE active = 1",
    "SELECT COUNT(*) FROM orders WHERE date > '2024-01-01'",
    "SELECT product_name, price FROM products WHERE category = 'electronics'",
    "SELECT * FROM users WHERE username = 'john_doe'",
    "SELECT id, name FROM employees WHERE department = 'IT'",
    "SELECT AVG(salary) FROM employees WHERE hire_date > '2020-01-01'",
    "SELECT * FROM posts WHERE published = 1 ORDER BY created_at DESC",
    "SELECT user_id, SUM(amount) FROM transactions GROUP BY user_id",
    "SELECT * FROM products WHERE price BETWEEN 10 AND 100",
    
    # INSERT queries
    "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')",
    "INSERT INTO orders (user_id, total) VALUES (5, 99.99)",
    "INSERT INTO products (name, price, stock) VALUES ('Laptop', 899.99, 50)",
    "INSERT INTO logs (message, timestamp) VALUES ('User login', NOW())",
    
    # UPDATE queries
    "UPDATE users SET last_login = NOW() WHERE id = 10",
    "UPDATE products SET stock = stock - 1 WHERE id = 25",
    "UPDATE orders SET status = 'shipped' WHERE order_id = 1234",
    "UPDATE customers SET email = 'newemail@example.com' WHERE id = 5",
    
    # DELETE queries
    "DELETE FROM sessions WHERE expires_at < NOW()",
    "DELETE FROM temp_data WHERE created_at < '2024-01-01'",
    "DELETE FROM cart WHERE user_id = 10 AND product_id = 5",
    
    # JOIN queries
    "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id",
    "SELECT p.name, c.name FROM products p JOIN categories c ON p.category_id = c.id",
    "SELECT e.name, d.name FROM employees e LEFT JOIN departments d ON e.dept_id = d.id",
    
    # Parameterized queries (safe)
    "SELECT * FROM users WHERE email = ?",
    "INSERT INTO logs (user_id, action) VALUES (?, ?)",
    "UPDATE products SET price = ? WHERE id = ?",
    
    # Common web app queries
    "SELECT * FROM users WHERE username = 'admin' AND password_hash = 'abc123'",
    "SELECT session_id FROM sessions WHERE user_id = 42",
    "SELECT COUNT(*) FROM notifications WHERE user_id = 10 AND read = 0",
    "SELECT * FROM settings WHERE key = 'site_name'",
]

def generate_benign_variations(base_queries, count):
    """Generate variations of benign queries to reach target count."""
    variations = []
    
    while len(variations) < count:
        base = random.choice(base_queries)
        
        # Apply random variations
        variation_type = random.randint(0, 5)
        
        if variation_type == 0:
            # Change numeric values
            import re
            varied = re.sub(r'\d+', lambda m: str(random.randint(1, 1000)), base)
        elif variation_type == 1:
            # Change string values
            varied = base.replace('john', random.choice(['alice', 'bob', 'charlie', 'david']))
            varied = varied.replace('John', random.choice(['Alice', 'Bob', 'Charlie', 'David']))
        elif variation_type == 2:
            # Add/remove whitespace
            varied = base.replace(' ', '  ') if random.random() > 0.5 else base.replace('  ', ' ')
        elif variation_type == 3:
            # Change case (SQL is case-insensitive)
            if random.random() > 0.5:
                varied = base.upper()
            else:
                varied = base.lower()
        elif variation_type == 4:
            # Add extra spaces around operators
            varied = base.replace('=', ' = ').replace('>', ' > ').replace('<', ' < ')
        else:
            # Keep original
            varied = base
        
        if varied not in variations:
            variations.append(varied)
    
    return variations[:count]

def generate_labeled_dataset(output_file="data/labeled_dataset.csv", 
                            num_attacks=50000, 
                            num_benign=50000):
    """
    Generate a balanced labeled dataset for ML training.
    
    Args:
        output_file: Output CSV file path
        num_attacks: Number of attack samples
        num_benign: Number of benign samples
    """
    print(f"Generating Labeled Dataset for ML Detector Training")
    print(f"=" * 60)
    print(f"Attack samples: {num_attacks}")
    print(f"Benign samples: {num_benign}")
    print(f"Total samples: {num_attacks + num_benign}")
    print(f"Output: {output_file}")
    print(f"=" * 60)
    
    # Generate attack samples (obfuscated SQL injections)
    print("\n[1/3] Generating attack samples...")
    attack_data = generate_dataset(num_attacks)
    attack_samples = [(target, 1) for src, target in attack_data]  # label = 1 for attacks
    print(f"✓ Generated {len(attack_samples)} attack samples")
    
    # Generate benign samples
    print("\n[2/3] Generating benign samples...")
    benign_samples = generate_benign_variations(BENIGN_QUERIES, num_benign)
    benign_samples = [(query, 0) for query in benign_samples]  # label = 0 for benign
    print(f"✓ Generated {len(benign_samples)} benign samples")
    
    # Combine and shuffle
    print("\n[3/3] Combining and shuffling dataset...")
    all_samples = attack_samples + benign_samples
    random.shuffle(all_samples)
    
    # Write to CSV
    print(f"\nWriting to {output_file}...")
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['query', 'label'])  # Header
        
        for i, (query, label) in enumerate(all_samples):
            writer.writerow([query, label])
            
            if (i + 1) % 10000 == 0:
                print(f"  Written: {i + 1}/{len(all_samples)} samples...", end='\r', flush=True)
    
    print(f"\n\n{'=' * 60}")
    print(f"✓ Dataset generation complete!")
    print(f"{'=' * 60}")
    print(f"File: {output_file}")
    print(f"Total samples: {len(all_samples)}")
    print(f"Attack samples: {num_attacks} ({(num_attacks/len(all_samples))*100:.1f}%)")
    print(f"Benign samples: {num_benign} ({(num_benign/len(all_samples))*100:.1f}%)")
    print(f"\nDataset is ready for ML detector training!")

if __name__ == "__main__":
    # Generate balanced dataset (50k attacks + 50k benign = 100k total)
    generate_labeled_dataset(
        output_file="data/labeled_dataset.csv",
        num_attacks=50000,
        num_benign=50000
    )

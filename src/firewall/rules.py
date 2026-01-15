import os
import hashlib
from datetime import datetime

RULES_DIRECTORY = os.path.join(os.path.dirname(__file__), 'rules')
RULES_FILE = os.path.join(RULES_DIRECTORY, 'ai_learned.rules')
SID_BASE = 9000000


def ensure_rules_directory():
    os.makedirs(RULES_DIRECTORY, exist_ok=True)


def escape_for_snort(content):
    content = content.replace('\\', '\\\\')
    content = content.replace('"', '\\"')
    content = content.replace(';', '|3B|')
    content = content.replace('|', '|7C|')
    return content


def generate_sid(pattern_string):
    pattern_hash = hashlib.md5(pattern_string.encode()).hexdigest()[:6]
    return SID_BASE + int(pattern_hash, 16) % 100000


def validate_snort_rule(rule):
    if not rule or not rule.strip():
        return False, "Empty rule"
    
    if not rule.startswith('alert '):
        return False, "Must start with 'alert'"
    
    if '(' not in rule or ')' not in rule:
        return False, "Missing parentheses"
    
    required_parts = ['msg:', 'sid:', 'content:']
    for part in required_parts:
        if part not in rule:
            return False, f"Missing: {part}"
    
    return True, None


def create_snort_rule_from_pattern(attack_pattern):
    sid = generate_sid(attack_pattern)
    escaped_pattern = escape_for_snort(attack_pattern)
    date_created = datetime.now().strftime("%Y%m%d")
    preview = attack_pattern[:20].replace('"', "'")
    
    rule = (
        f'alert tcp any any -> any any ('
        f'msg:"AI-Learned: {preview}"; '
        f'flow:to_server,established; '
        f'content:"{escaped_pattern}"; nocase; '
        f'classtype:web-application-attack; '
        f'sid:{sid}; rev:1; '
        f'metadata:created {date_created};'
        f')'
    )
    
    return rule


def append_rule_to_file(snort_rule):
    ensure_rules_directory()
    
    is_valid, error = validate_snort_rule(snort_rule)
    if not is_valid:
        print(f"[INVALID RULE] {error}")
        return False
    
    try:
        with open(RULES_FILE, 'a') as file:
            file.write(snort_rule + '\n')
        return True
    except Exception as error:
        print(f"[SAVE ERROR] {error}")
        return False


def load_all_rules():
    if not os.path.exists(RULES_FILE):
        return []
    
    with open(RULES_FILE, 'r') as file:
        rules = [line.strip() for line in file if line.strip() and not line.startswith('#')]
    
    return rules


def get_total_rule_count():
    return len(load_all_rules())


def clear_all_rules():
    ensure_rules_directory()
    
    with open(RULES_FILE, 'w') as file:
        file.write(f"# AI-Generated Snort Rules\n")
        file.write(f"# Cleared: {datetime.now().isoformat()}\n\n")


if __name__ == "__main__":
    print("Testing Rule Generator...")
    
    test_patterns = ["' OR ", "UNION SELECT", "/**/"]
    
    clear_all_rules()
    
    for pattern in test_patterns:
        rule = create_snort_rule_from_pattern(pattern)
        print(f"Pattern: '{pattern}' -> Rule created")
        append_rule_to_file(rule)
    
    print(f"Total rules: {get_total_rule_count()}")
    print(f"File: {RULES_FILE}")

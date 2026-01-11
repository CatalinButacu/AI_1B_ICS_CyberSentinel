"""
Snort IDS Rule Generator
Author: Catalin (Firewall Team)

TODO: Add PCRE support for regex patterns
TODO: Add rule validation before saving
TODO: Implement rule testing against sample traffic
TODO: Support Suricata rule format
"""

import os
import hashlib
from datetime import datetime

RULES_DIRECTORY = os.path.join(os.path.dirname(__file__), 'rules')
RULES_FILE_PATH = os.path.join(RULES_DIRECTORY, 'ai_learned.rules')
RULE_SID_BASE = 9000000


def ensure_rules_directory_exists():
    os.makedirs(RULES_DIRECTORY, exist_ok=True)


def escape_content_for_snort(content):
    content = content.replace('\\', '\\\\')
    content = content.replace('"', '\\"')
    content = content.replace(';', '|3B|')
    content = content.replace('|', '|7C|')
    return content


def generate_unique_sid(pattern_string):
    pattern_hash = hashlib.md5(pattern_string.encode()).hexdigest()[:6]
    return RULE_SID_BASE + int(pattern_hash, 16) % 100000


def create_snort_rule_from_pattern(attack_pattern, message_prefix="AI-Detected"):
    rule_sid = generate_unique_sid(attack_pattern)
    escaped_pattern = escape_content_for_snort(attack_pattern)
    creation_date = datetime.now().strftime("%Y%m%d")
    pattern_preview = attack_pattern[:20].replace('"', "'")
    
    snort_rule = (
        f'alert tcp any any -> any any ('
        f'msg:"{message_prefix}: {pattern_preview}"; '
        f'flow:to_server,established; '
        f'content:"{escaped_pattern}"; nocase; '
        f'classtype:web-application-attack; '
        f'sid:{rule_sid}; '
        f'rev:1; '
        f'metadata:created {creation_date};'
        f')'
    )
    
    return snort_rule


def append_rule_to_file(snort_rule):
    ensure_rules_directory_exists()
    
    try:
        with open(RULES_FILE_PATH, 'a') as rules_file:
            rules_file.write(snort_rule + '\n')
        return True
    except Exception as error:
        print(f"Error saving rule: {error}")
        return False


def load_all_rules():
    if not os.path.exists(RULES_FILE_PATH):
        return []
    
    with open(RULES_FILE_PATH, 'r') as rules_file:
        rules = [line.strip() for line in rules_file if line.strip() and not line.startswith('#')]
    
    return rules


def get_total_rule_count():
    return len(load_all_rules())


def clear_all_rules():
    ensure_rules_directory_exists()
    
    with open(RULES_FILE_PATH, 'w') as rules_file:
        rules_file.write(f"# AI-Generated Snort Rules\n")
        rules_file.write(f"# Last cleared: {datetime.now().isoformat()}\n\n")


def trigger_snort_reload():
    print("[INFO] Snort reload would be triggered here")
    return True


if __name__ == "__main__":
    print("Testing Rule Generator...")
    
    test_patterns = ["' OR ", "UNION SELECT", "/**/"]
    
    clear_all_rules()
    
    for pattern in test_patterns:
        rule = create_snort_rule_from_pattern(pattern)
        print(f"\nPattern: '{pattern}'")
        print(f"Rule: {rule}")
        append_rule_to_file(rule)
    
    print(f"\nTotal rules saved: {get_total_rule_count()}")
    print(f"Rules file: {RULES_FILE_PATH}")

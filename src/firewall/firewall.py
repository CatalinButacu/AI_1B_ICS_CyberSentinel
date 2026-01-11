"""
AI Firewall - Smart Pre-Filter and Feedback Receiver
Author: Catalin (Firewall Team)

FLOW:
  Attack → /filter → [match pattern?] → YES: BLOCK immediately
                                      → NO: forward to Beatrice → /feedback → learn

TODO: Add Isolation Forest for anomaly detection on unknown patterns
"""

import os
import sys
import json
import requests
from datetime import datetime
from flask import Flask, request, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from config import RESOURCES, DETECTOR_URL, WEBAPP_URL, API_TIMEOUT
from interfaces import BaseFirewall

from patterns import AttackPatternExtractor
from rules import create_snort_rule_from_pattern, append_rule_to_file, load_all_rules, get_total_rule_count, clear_all_rules

app = Flask(__name__)

DATA_DIRECTORY = os.path.join(os.path.dirname(__file__), 'data')
PAYLOADS_STORAGE_FILE = os.path.join(DATA_DIRECTORY, 'collected_payloads.json')
PATTERNS_STORAGE_FILE = os.path.join(DATA_DIRECTORY, 'learned_patterns.json')
MIN_PAYLOADS_FOR_RULE_GENERATION = 1

class SmartFirewall(BaseFirewall):
    
    def __init__(self):
        self.collected_payloads = []
        self.learned_patterns = []
        
        self.stats = {
            'payloads_received': 0,
            'rules_generated': 0,
            'attacks_blocked_by_pattern': 0,
            'attacks_forwarded_to_detector': 0,
            'target_compromised': 0,
            'service_started': datetime.now().isoformat()
        }
        
        self.load_data()

    def load_data(self):
        os.makedirs(DATA_DIRECTORY, exist_ok=True)
        
        if os.path.exists(PAYLOADS_STORAGE_FILE):
            with open(PAYLOADS_STORAGE_FILE, 'r') as f:
                self.collected_payloads = json.load(f)
        
        if os.path.exists(PATTERNS_STORAGE_FILE):
            with open(PATTERNS_STORAGE_FILE, 'r') as f:
                self.learned_patterns = json.load(f)
        
        print(f"Loaded {len(self.learned_patterns)} patterns, {len(self.collected_payloads)} payloads")

    def save_data(self):
        os.makedirs(DATA_DIRECTORY, exist_ok=True)
        with open(PAYLOADS_STORAGE_FILE, 'w') as f:
            json.dump(self.collected_payloads, f)
        
        with open(PATTERNS_STORAGE_FILE, 'w') as f:
            json.dump(self.learned_patterns, f)

    def match_pattern(self, payload):
        # TODO(firewall_layer): Improve pattern matching with regex
        # Current: simple substring match. Add:
        # - re.IGNORECASE for case variations (SELECT vs select)
        # - Whitespace normalization (SELECT/**/FROM)
        # - Regex patterns instead of exact strings
        for item in self.learned_patterns:
            pattern = item.get('pattern') if isinstance(item, dict) else item
            if pattern and pattern in payload:
                print(f"[BLOCKED BY FIREWALL] Pattern '{pattern}' -> {payload[:40]}...")
                return True
        return False

    def update_rules(self, new_patterns):
        """Authentication of BaseFirewall interface."""
        if not new_patterns:
            return
            
        count = 0
        existing_pattern_strings = set()
        for item in self.learned_patterns:
            p_str = item.get('pattern') if isinstance(item, dict) else item
            existing_pattern_strings.add(p_str)

        for p_obj in new_patterns:
            # p_obj matches output from AttackPatternExtractor (dict)
            p_str = p_obj.get('pattern') if isinstance(p_obj, dict) else p_obj
            
            if p_str and p_str not in existing_pattern_strings:
                # Store full object if dict, else create one
                to_store = p_obj if isinstance(p_obj, dict) else {
                    'pattern': p_str, 'learned_at': datetime.now().isoformat()
                }
                
                self.learned_patterns.append(to_store)
                existing_pattern_strings.add(p_str)
                print(f"[NEW PATTERN] Learned: '{p_str}'")
                
                try:
                    rule = create_snort_rule_from_pattern(p_str)
                    append_rule_to_file(rule)
                    self.stats['rules_generated'] += 1
                except Exception as e:
                    print(f"Rule generation error: {e}")
                
                count += 1
        
        if count > 0:
            self.save_data()

    def learn_from_feedback(self, payload):
        if payload not in self.collected_payloads:
            self.collected_payloads.append(payload)
            self.save_data()
        
        if len(self.collected_payloads) >= MIN_PAYLOADS_FOR_RULE_GENERATION:
            self.run_clustering()

    def run_clustering(self):
        print(f"Extracting patterns from {len(self.collected_payloads)} payloads...")
        extractor = AttackPatternExtractor(min_occurrence_ratio=0.1) # low threshold for demo
        # Fix: Method name is extract_attack_patterns
        patterns = extractor.extract_attack_patterns(self.collected_payloads)
        
        print(f"Found {len(patterns)} patterns")
        self.update_rules(patterns)


# Global Instance
firewall = SmartFirewall()


# =============================================================================
# FORWARDING LOGIC (Layer Transition)
# =============================================================================

def forward_to_detector(payload):
    """Layer 2: ML Inspection"""
    try:
        response = requests.post(
            f"{DETECTOR_URL}/check",
            json={"payload": payload},
            timeout=API_TIMEOUT
        )
        return response.json()
    except Exception as e:
        return {"error": str(e), "is_attack": False}


def forward_to_webapp(payload):
    """Layer 3: Target Application"""
    try:
        # We default to a test password, but in a real attack, the payload might bypass auth
        # depending on where it's injected. Here we simulate the login endpoint injection.
        response = requests.post(
            f"{WEBAPP_URL}/login",
            json={"username": payload, "password": "x"}, # 'x' matches many SQLi scenarios
            timeout=API_TIMEOUT
        )
        result = response.json()
        
        if result.get('success'):
            print(f"[TARGET COMPROMISED] Data extracted! Payload: {payload[:30]}...")
            firewall.stats['target_compromised'] += 1
        
        return result
    except Exception as e:
        return {"error": str(e), "target_available": False}


# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.route('/filter', methods=['POST'])
def smart_filter():
    """
    Main entry point for traffic.
    Layer 1 (Pattern) -> Layer 2 (ML) -> Layer 3 (Target)
    """
    request_data = request.json or {}
    payload = request_data.get('payload', '')
    
    firewall.stats['payloads_received'] += 1
    
    # Layer 1: Pattern Match
    if firewall.match_pattern(payload):
        firewall.stats['attacks_blocked_by_pattern'] += 1
        return jsonify({
            'action': 'BLOCKED',
            'blocked_by': 'firewall_pattern',
            'message': 'Known attack pattern'
        })
    
    # Layer 2: Detector
    firewall.stats['attacks_forwarded_to_detector'] += 1
    detector_res = forward_to_detector(payload)
    
    if detector_res.get('is_attack'):
        confidence = detector_res.get('confidence', 0)
        print(f"[DETECTED BY BEATRICE] {payload[:40]}... (conf: {confidence:.0%})")
        
        # Automatic Feedback Loop: Learn from Detector's findings
        firewall.learn_from_feedback(payload)
        
        return jsonify({
            'action': 'BLOCKED', 
            'blocked_by': 'detector', 
            'confidence': confidence, 
            'message': 'ML detection'
        })

    # Layer 3: Webapp
    print(f"[FORWARDING TO TARGET] {payload[:40]}...")
    webapp_res = forward_to_webapp(payload)
    
    return jsonify({
        'action': 'ALLOWED',
        'message': 'Forwarded', 
        'webapp_response': webapp_res
    })


@app.route('/feedback', methods=['POST'])
def receive_feedback():
    data = request.json or {}
    print(f"[FEEDBACK RECEIVED] Attack: {data.get('is_attack')}")
    if data.get('is_attack'):
        firewall.learn_from_feedback(data.get('payload'))
    return jsonify({'status': 'received'})


@app.route('/patterns', methods=['GET'])
def get_patterns():
    return jsonify({'patterns': firewall.learned_patterns})


@app.route('/rules', methods=['GET'])
def get_rules():
    return jsonify({'rules': load_all_rules()})


@app.route('/status', methods=['GET'])
def status():
    return jsonify(firewall.stats)


@app.route('/clear', methods=['POST'])
def clear_data():
    firewall.collected_payloads = []
    firewall.learned_patterns = []
    firewall.save_data()
    clear_all_rules()
    return jsonify({'status': 'cleared'})


@app.route('/check-pattern', methods=['POST'])
def check_pattern():
    """
    Check if payload matches any known attack patterns.
    Used by webapp's inline defense (Case III) to check BEFORE executing SQL.
    Does NOT forward to detector - just pattern matching.
    """
    data = request.json or {}
    payload = data.get('payload', '')
    
    if firewall.match_pattern(payload):
        return jsonify({
            'blocked': True,
            'reason': 'pattern_match',
            'pattern': 'known_attack_pattern'
        })
    
    return jsonify({
        'blocked': False,
        'reason': 'no_match'
    })


def main():
    print("="*60)
    print("AI SMART FIREWALL")
    print("="*60 + "\n")
    print(f"Patterns loaded: {len(firewall.learned_patterns)}")
    print(f"Payloads stored: {len(firewall.collected_payloads)}\n")
    
    app.run(host='0.0.0.0', port=5001, debug=False)


if __name__ == "__main__":
    main()

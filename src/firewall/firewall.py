import os
import sys
import re
import json
import argparse
import requests
from datetime import datetime
from flask import Flask, request, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from config import DETECTOR_URL, WEBAPP_URL, API_TIMEOUT
from interfaces import BaseFirewall
from patterns import AttackPatternExtractor
from rules import create_snort_rule_from_pattern, append_rule_to_file, clear_all_rules

app = Flask(__name__)

DATA_DIRECTORY = os.path.join(os.path.dirname(__file__), 'data')
PAYLOADS_FILE = os.path.join(DATA_DIRECTORY, 'collected_payloads.json')
PATTERNS_FILE = os.path.join(DATA_DIRECTORY, 'learned_patterns.json')
MIN_PAYLOADS_FOR_CLUSTERING = 1


class SmartFirewall(BaseFirewall):
    
    def __init__(self, case_number):
        self.case_number = case_number
        self.is_passthrough = (case_number == 0)
        self.is_ml_only = (case_number == 1)
        self.is_full_pipeline = (case_number == 2)
        
        self.collected_payloads = []
        self.learned_patterns = []
        self.stats = self.initialize_stats()
        
        self.load_stored_data()
    
    def initialize_stats(self):
        return {
            'payloads_received': 0,
            'blocked_by_pattern': 0,
            'blocked_by_ml': 0,
            'forwarded_to_target': 0,
            'target_compromised': 0,
            'rules_generated': 0
        }
    
    def load_stored_data(self):
        os.makedirs(DATA_DIRECTORY, exist_ok=True)
        
        if os.path.exists(PAYLOADS_FILE):
            with open(PAYLOADS_FILE, 'r') as file:
                self.collected_payloads = json.load(file)
        
        if os.path.exists(PATTERNS_FILE):
            with open(PATTERNS_FILE, 'r') as file:
                self.learned_patterns = json.load(file)
        
        print(f"Loaded {len(self.learned_patterns)} patterns, {len(self.collected_payloads)} payloads")
    
    def save_stored_data(self):
        os.makedirs(DATA_DIRECTORY, exist_ok=True)
        with open(PAYLOADS_FILE, 'w') as file:
            json.dump(self.collected_payloads, file)
        with open(PATTERNS_FILE, 'w') as file:
            json.dump(self.learned_patterns, file)
    
    def normalize_for_matching(self, text):
        text = text.lower()
        text = re.sub(r'/\*.*?\*/', ' ', text)
        text = re.sub(r'--.*', '', text)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()
    
    def payload_matches_known_pattern(self, payload):
        normalized_payload = self.normalize_for_matching(payload)
        
        for item in self.learned_patterns:
            pattern = item.get('pattern') if isinstance(item, dict) else item
            if not pattern:
                continue
            
            normalized_pattern = self.normalize_for_matching(pattern)
            if normalized_pattern in normalized_payload:
                print(f"[PATTERN MATCH] '{pattern}' in '{payload[:40]}...'")
                return True
        
        return False
    
    def match_pattern(self, payload):
        return self.payload_matches_known_pattern(payload)
    
    def add_payload_to_collection(self, payload):
        if payload not in self.collected_payloads:
            self.collected_payloads.append(payload)
            self.save_stored_data()
        
        if len(self.collected_payloads) >= MIN_PAYLOADS_FOR_CLUSTERING:
            self.extract_and_learn_patterns()
    
    def extract_and_learn_patterns(self):
        print(f"Extracting patterns from {len(self.collected_payloads)} payloads...")
        extractor = AttackPatternExtractor(min_occurrence_ratio=0.1)
        new_patterns = extractor.extract_attack_patterns(self.collected_payloads)
        
        existing_pattern_strings = set()
        for item in self.learned_patterns:
            pattern_str = item.get('pattern') if isinstance(item, dict) else item
            existing_pattern_strings.add(pattern_str)
        
        for pattern_obj in new_patterns:
            pattern_str = pattern_obj.get('pattern') if isinstance(pattern_obj, dict) else pattern_obj
            
            if pattern_str and pattern_str not in existing_pattern_strings:
                self.learned_patterns.append(pattern_obj)
                existing_pattern_strings.add(pattern_str)
                
                snort_rule = create_snort_rule_from_pattern(pattern_str)
                if append_rule_to_file(snort_rule):
                    self.stats['rules_generated'] += 1
                    print(f"[NEW RULE] {pattern_str}")
        
        self.save_stored_data()
    
    def update_rules(self, patterns):
        pass


firewall = None


def send_to_ml_detector(payload):
    try:
        response = requests.post(
            f"{DETECTOR_URL}/check",
            json={"payload": payload},
            timeout=API_TIMEOUT
        )
        return response.json()
    except Exception as error:
        print(f"[ML ERROR] {error}")
        return {"error": str(error), "is_attack": False}


def send_to_webapp(payload):
    try:
        response = requests.post(
            f"{WEBAPP_URL}/login",
            json={"username": payload, "password": "x"},
            timeout=API_TIMEOUT
        )
        result = response.json()
        
        if result.get('success'):
            print(f"[COMPROMISED] {payload[:30]}...")
            firewall.stats['target_compromised'] += 1
        
        return result
    except Exception as error:
        print(f"[WEBAPP ERROR] {error}")
        return {"error": str(error), "success": False}


@app.route('/filter', methods=['POST'])
def filter_request():
    request_data = request.json or {}
    payload = request_data.get('payload', '')
    
    firewall.stats['payloads_received'] += 1
    print(f"[RECEIVED] Case {firewall.case_number}: {payload[:50]}...")
    
    if firewall.is_passthrough:
        webapp_response = send_to_webapp(payload)
        firewall.stats['forwarded_to_target'] += 1
        return jsonify({
            'action': 'ALLOWED',
            'mode': 'passthrough',
            'webapp_response': webapp_response
        })
    
    if firewall.is_ml_only:
        ml_response = send_to_ml_detector(payload)
        
        if ml_response.get('is_attack'):
            firewall.stats['blocked_by_ml'] += 1
            return jsonify({
                'action': 'BLOCKED',
                'blocked_by': 'ml_detector',
                'confidence': ml_response.get('confidence', 0)
            })
        
        webapp_response = send_to_webapp(payload)
        firewall.stats['forwarded_to_target'] += 1
        return jsonify({
            'action': 'ALLOWED',
            'mode': 'ml_only',
            'webapp_response': webapp_response
        })
    
    if firewall.is_full_pipeline:
        if firewall.payload_matches_known_pattern(payload):
            firewall.stats['blocked_by_pattern'] += 1
            return jsonify({
                'action': 'BLOCKED',
                'blocked_by': 'firewall_pattern'
            })
        
        ml_response = send_to_ml_detector(payload)
        
        if ml_response.get('is_attack'):
            firewall.stats['blocked_by_ml'] += 1
            firewall.add_payload_to_collection(payload)
            return jsonify({
                'action': 'BLOCKED',
                'blocked_by': 'ml_detector',
                'confidence': ml_response.get('confidence', 0),
                'pattern_learned': True
            })
        
        webapp_response = send_to_webapp(payload)
        firewall.stats['forwarded_to_target'] += 1
        return jsonify({
            'action': 'ALLOWED',
            'mode': 'full_pipeline',
            'webapp_response': webapp_response
        })
    
    return jsonify({'error': 'Unknown case'}), 400


@app.route('/feedback', methods=['POST'])
def receive_feedback():
    request_data = request.json or {}
    payload = request_data.get('payload', '')
    
    if not payload:
        return jsonify({'error': 'Missing payload'}), 400
    
    firewall.add_payload_to_collection(payload)
    return jsonify({'status': 'learned', 'total_payloads': len(firewall.collected_payloads)})


@app.route('/status', methods=['GET'])
def get_status():
    return jsonify({
        'case': firewall.case_number,
        'patterns_count': len(firewall.learned_patterns),
        'payloads_count': len(firewall.collected_payloads),
        'stats': firewall.stats
    })


@app.route('/patterns', methods=['GET'])
def get_patterns():
    return jsonify({'patterns': firewall.learned_patterns})


@app.route('/reset', methods=['POST'])
def reset_learned_data():
    firewall.collected_payloads = []
    firewall.learned_patterns = []
    firewall.save_stored_data()
    clear_all_rules()
    return jsonify({'status': 'reset_complete'})


@app.route('/check', methods=['POST'])
def check_pattern_only():
    request_data = request.json or {}
    payload = request_data.get('payload', '')
    
    is_blocked = firewall.payload_matches_known_pattern(payload)
    return jsonify({'blocked': is_blocked})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', type=int, choices=[0, 1, 2], default=0)
    args = parser.parse_args()
    
    global firewall
    firewall = SmartFirewall(case_number=args.case)
    
    case_descriptions = {
        0: "PASSTHROUGH (No Defense)",
        1: "ML ONLY (Every Query goes through ML)",
        2: "FULL PIPELINE (Pattern + ML + Learning)"
    }
    
    print("=" * 60)
    print(f"SMART FIREWALL - Case {args.case}: {case_descriptions[args.case]}")
    print("=" * 60)
    print(f"Patterns: {len(firewall.learned_patterns)}")
    print(f"Payloads: {len(firewall.collected_payloads)}")
    print("")
    
    app.run(host='0.0.0.0', port=5001, debug=False)


if __name__ == "__main__":
    main()

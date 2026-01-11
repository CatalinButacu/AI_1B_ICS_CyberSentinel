"""
SQL Injection Detection REST API
Author: Beatrice (Defensive Team)
"""

import os
import sys
import pickle
import requests
from datetime import datetime
from flask import Flask, request, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from config import FIREWALL_URL, FEEDBACK_CONFIDENCE_THRESHOLD, API_TIMEOUT
from interfaces import BaseDetector

app = Flask(__name__)
MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')
MODEL_PATH = os.path.join(MODELS_DIR, 'sqli_detector.pkl')

class RandomForestDetector(BaseDetector):
    
    def __init__(self, model_path):
        self.model_path = model_path
        self.classifier = None
        self.vectorizer = None
        self.load_model()
        
    def load_model(self):
        if not os.path.exists(self.model_path):
            print(f"[ERROR] Model not found: {self.model_path}")
            return False
            
        with open(self.model_path, 'rb') as f:
            bundle = pickle.load(f)
            
        self.classifier = bundle['model']
        self.vectorizer = bundle['vectorizer']
        print(f"Model loaded: {self.model_path}")
        return True

    def extract_features(self, payload):
        # TODO(ml_detection_layer): Improve feature extraction
        # Current: basic TF-IDF. Add:
        # - Character n-grams (3-5)
        # - SQL keyword counts (UNION, SELECT, --, etc.)
        # - Encoding pattern detection (%27, 0x27, etc.)
        if self.vectorizer is None: 
            return None
        return self.vectorizer.transform([payload])

    def predict(self, payload):
        """Authentication of BaseDetector interface."""
        if self.classifier is None:
            return 0.0, False
            
        features = self.extract_features(payload)
        prediction = self.classifier.predict(features)[0]
        probs = self.classifier.predict_proba(features)[0]
        confidence = float(max(probs))
        
        return confidence, bool(prediction == 1)

# Global Instance
detector = RandomForestDetector(MODEL_PATH)

detection_stats = {
    'total_checks': 0,
    'attacks_blocked': 0,
    'safe_requests': 0,
    'feedback_sent_count': 0,
    'service_started': datetime.now().isoformat()
}

def send_attack_feedback_to_firewall(payload, confidence):
    if confidence < FEEDBACK_CONFIDENCE_THRESHOLD:
        return False
    try:
        response = requests.post(
            f"{FIREWALL_URL}/feedback",
            json={
                'payload': payload,
                'confidence': float(confidence),
                'is_attack': True,
                'source': 'sqli_detector',
                'timestamp': datetime.now().isoformat()
            },
            timeout=API_TIMEOUT
        )
        if response.status_code == 200:
            detection_stats['feedback_sent_count'] += 1
            return True
        return False
    except Exception:
        return False

@app.route('/check', methods=['POST'])
def check_for_sqli():
    if detector.classifier is None:
        return jsonify({'error': 'Model not loaded'}), 500
    
    payload = (request.json or {}).get('payload', '')
    if not payload:
        return jsonify({'error': 'No payload provided'}), 400
    
    confidence, is_attack = detector.predict(payload)
    
    detection_stats['total_checks'] += 1
    if is_attack:
        detection_stats['attacks_blocked'] += 1
        print(f"[BLOCKED] {payload[:50]}... (conf: {confidence:.0%})")
        feedback_sent = send_attack_feedback_to_firewall(payload, confidence)
    else:
        detection_stats['safe_requests'] += 1
        feedback_sent = False
    
    return jsonify({
        'payload': payload,
        'is_attack': is_attack,
        'confidence': confidence,
        'feedback_sent': feedback_sent
    })

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'model_loaded': detector.classifier is not None})

@app.route('/stats', methods=['GET'])
def get_detection_stats():
    return jsonify(detection_stats)

@app.route('/', methods=['GET'])
def api_info():
    return jsonify({
        'service': 'SQLi Detection API',
        'endpoints': {
            'POST /check': 'Check payload',
            'GET /health': 'Health check',
            'GET /stats': 'Statistics'
        }
    })

def main():
    print("="*60)
    print("SQL INJECTION DETECTOR API")
    print("="*60 + "\n")
    print("\nStarting API on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)

if __name__ == "__main__":
    main()

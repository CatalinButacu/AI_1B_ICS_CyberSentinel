from flask import Flask, request, jsonify
import tensorflow as tf
import pickle
import numpy as np
from tensorflow.keras.preprocessing.sequence import pad_sequences
import os
import sys
from datetime import datetime
import requests

# Add shared module to path for config
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from config import FIREWALL_URL, FEEDBACK_CONFIDENCE_THRESHOLD, API_TIMEOUT

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')

# Load Model and Tokenizer
try:
    model_path = os.path.join(MODELS_DIR, 'sqli_cnn.h5')
    tokenizer_path = os.path.join(MODELS_DIR, 'tokenizer.pickle')
    
    if os.path.exists(model_path):
        model = tf.keras.models.load_model(model_path)
        print(f"Loaded model from {model_path}")
    else:
        print("Model not found. Please run train.py first.")
        model = None

    if os.path.exists(tokenizer_path):
        with open(tokenizer_path, 'rb') as handle:
            tokenizer = pickle.load(handle)
        print(f"Loaded tokenizer from {tokenizer_path}")
    else:
        print("Tokenizer not found.")
        tokenizer = None

except Exception as e:
    print(f"Error loading artifacts: {e}")
    model = None
    tokenizer = None

max_length = 100
threshold = 0.2

detection_stats = {
    'total_checks': 0,
    'attacks_blocked': 0,
    'safe_requests': 0,
    'model_type': 'CNN-User-Provided'
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
                'source': 'sqli_detector_cnn',
                'timestamp': datetime.now().isoformat()
            },
            timeout=API_TIMEOUT
        )
        return response.status_code == 200
    except Exception:
        return False

@app.route('/check', methods=['POST'])
def check_query():
    """
    Input: JSON {"query": "SELECT * FROM..."} OR {"payload": "..."}
    Output: JSON {"is_attack": true, "confidence": 0.99}
    """
    if model is None or tokenizer is None:
         print("[ERROR] Request received but model/tokenizer not loaded!", flush=True)
         return jsonify({"error": "Model not loaded"}), 500

    try:
        data = request.get_json(force=True) or {}
        # Support both user's preferred 'query' and system's 'payload'
        query_text = data.get('query', data.get('payload', ''))

        print(f"[DEBUG] Received request. Payload: {query_text[:30]}...", flush=True)

        #preprocess the incoming query
        print("[DEBUG] Tokenizing...", flush=True)
        seq = tokenizer.texts_to_sequences([query_text])
        padded = pad_sequences(seq, maxlen=max_length)

        #predict
        print("[DEBUG] Starting model.predict()...", flush=True)
        prediction_score = model.predict(padded, verbose=0)[0][0]
        print(f"[DEBUG] Prediction finished: {prediction_score}", flush=True)
        
        confidence = float(prediction_score)
        is_attack = bool(prediction_score > threshold)

        # Update stats
        detection_stats['total_checks'] += 1
        feedback_sent = False
        if is_attack:
            detection_stats['attacks_blocked'] += 1
            print(f"[BLOCKED] {query_text[:50]}... (conf: {confidence:.2f})", flush=True)
            feedback_sent = send_attack_feedback_to_firewall(query_text, confidence)
        else:
             detection_stats['safe_requests'] += 1
             print(f"[SAFE] {query_text[:30]}... (conf: {confidence:.2f})", flush=True)

        return jsonify({
            "is_attack": is_attack,
            "confidence": confidence,
            "payload": query_text, # Returning payload helps the firewall know what was checked
            "feedback_sent": feedback_sent
        })

    except Exception as e:
        print(f"Error processing request: {e}", flush=True)
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'model_loaded': model is not None})

@app.route('/stats', methods=['GET'])
def get_stats():
    return jsonify(detection_stats)

if __name__ == '__main__':
    # Force CPU to avoid GPU/CUDA hangs on Windows if drivers are mismatched
    os.environ['CUDA_VISIBLE_DEVICES'] = '-1'
    
    print("Starting CNN Detector API on port 5000...")
    # Disable threading to avoid TensorFlow thread-safety locking issues in simple Flask apps
    app.run(host='0.0.0.0', port=5000, threaded=False)

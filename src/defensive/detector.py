import os
import sys
import pickle
from datetime import datetime
from flask import Flask, request, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from config import FIREWALL_URL, API_TIMEOUT, ENVIRONMENT

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
CNN_MODEL_PATH = os.path.join(MODELS_DIR, 'sqli_cnn.h5')
TOKENIZER_PATH = os.path.join(MODELS_DIR, 'tokenizer.pickle')
PKL_MODEL_PATH = os.path.join(MODELS_DIR, 'sqli_detector.pkl')

model = None
tokenizer = None
vectorizer = None
model_type = None
tf_module = None
DETECTION_THRESHOLD = 0.2
MAX_SEQUENCE_LENGTH = 100


def log_request(action, payload, confidence=None, extra=""):
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    payload_preview = payload[:50].replace('\n', ' ') if payload else "EMPTY"
    
    if confidence is not None:
        conf_bar = "█" * int(confidence * 10) + "░" * (10 - int(confidence * 10))
        print(f"[{timestamp}] {action:12} | Conf: {confidence:7.2%} [{conf_bar}] | {payload_preview}... {extra}")
    else:
        print(f"[{timestamp}] {action:12} | {payload_preview}... {extra}")


def load_cnn_model():
    global model, tokenizer, model_type, tf_module
    
    print("[CNN] Attempting to load CNN model...")
    
    if not os.path.exists(CNN_MODEL_PATH):
        print(f"[CNN] Model file not found: {CNN_MODEL_PATH}")
        return False
    
    if not os.path.exists(TOKENIZER_PATH):
        print(f"[CNN] Tokenizer not found: {TOKENIZER_PATH}")
        return False
    
    try:
        os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
        os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
        
        import tensorflow as tf
        tf_module = tf
        
        # Try loading with compile=False to ignore optimizer config issues
        try:
            model = tf.keras.models.load_model(CNN_MODEL_PATH, compile=False)
        except:
            # Fallback: try with safe_mode=False for older model formats
            model = tf.keras.models.load_model(CNN_MODEL_PATH, compile=False, safe_mode=False)
        
        with open(TOKENIZER_PATH, 'rb') as file:
            tokenizer = pickle.load(file)
        
        model_type = "CNN"
        print(f"[CNN] ✅ Successfully loaded: {CNN_MODEL_PATH}")
        return True
        
    except Exception as error:
        print(f"[CNN] ❌ Failed to load: {error}")
        return False


def load_sklearn_model():
    global model, vectorizer, model_type
    
    print("[SKLEARN] Loading RandomForest fallback...")
    
    if not os.path.exists(PKL_MODEL_PATH):
        print(f"[SKLEARN] Model not found: {PKL_MODEL_PATH}")
        return False
    
    try:
        with open(PKL_MODEL_PATH, 'rb') as file:
            data = pickle.load(file)
        
        model = data.get('model')
        vectorizer = data.get('vectorizer')
        model_type = "RandomForest"
        
        print(f"[SKLEARN] ✅ Loaded: {type(model).__name__}")
        return True
        
    except Exception as error:
        print(f"[SKLEARN] ❌ Failed: {error}")
        return False


def predict_attack(payload):
    if model is None:
        return False, 0.0
    
    try:
        if model_type == "CNN":
            sequences = tokenizer.texts_to_sequences([payload])
            padded = tf_module.keras.preprocessing.sequence.pad_sequences(
                sequences, maxlen=MAX_SEQUENCE_LENGTH
            )
            prediction = model.predict(padded, verbose=0)
            confidence = float(prediction[0][0])
        else:
            features = vectorizer.transform([payload])
            if hasattr(model, 'predict_proba'):
                probabilities = model.predict_proba(features)
                confidence = float(probabilities[0][1])
            else:
                prediction = model.predict(features)
                confidence = float(prediction[0])
        
        return confidence > DETECTION_THRESHOLD, confidence
        
    except Exception as error:
        print(f"[PREDICT ERROR] {error}")
        return False, 0.0


@app.route('/check', methods=['POST'])
def check_payload():
    request_data = request.json or {}
    payload = request_data.get('payload') or request_data.get('query', '')
    
    if not payload:
        return jsonify({"error": "No payload"}), 400
    
    is_attack, confidence = predict_attack(payload)
    
    if is_attack:
        log_request("⛔ ATTACK", payload, confidence, "BLOCKED")
    else:
        log_request("✓ SAFE", payload, confidence, "ALLOWED")
    
    return jsonify({
        "is_attack": bool(is_attack),
        "confidence": float(confidence),
        "model_type": model_type,
        "threshold": DETECTION_THRESHOLD
    })


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "model_loaded": model is not None,
        "model_type": model_type,
        "environment": ENVIRONMENT
    })


def main():
    print("=" * 60)
    print("  SQL INJECTION DETECTOR")
    print("  CNN Model (with fallback on RandomForest)")
    print("=" * 60)
    print(f"[ENV] {ENVIRONMENT}")
    print("")
    
    # Try CNN first (works on Windows with AVX)
    cnn_loaded = load_cnn_model()
    
    if not cnn_loaded:
        print("")
        print("[FALLBACK] CNN failed, trying RandomForest...")
        sklearn_loaded = load_sklearn_model()
        
        if not sklearn_loaded:
            print("[FATAL] No model could be loaded. Exiting.")
            sys.exit(1)
    
    print("")
    print("=" * 60)
    print(f"  ACTIVE MODEL: {model_type}")
    print(f"  THRESHOLD: {DETECTION_THRESHOLD}")
    print(f"  PORT: 5000")
    print("=" * 60)
    print("Waiting for requests...")
    print("")
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)


if __name__ == "__main__":
    main()

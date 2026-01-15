from flask import Flask, request, jsonify
import tensorflow as tf
import pickle
import numpy as np
import re
from urllib.parse import unquote
from tensorflow.keras.preprocessing.sequence import pad_sequences
import os

app = Flask(__name__)

# --- LOAD ARTIFACTS ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'sql_model.h5')
TOKEN_PATH = os.path.join(BASE_DIR, 'tokenizer.pickle')

print("Loading Engine...")
model = tf.keras.models.load_model(MODEL_PATH)
with open(TOKEN_PATH, 'rb') as handle:
    tokenizer = pickle.load(handle)

MAX_LEN = 100


# --- SAME CLEANING LOGIC AS TRAIN.PY ---
def clean_query(query_text):
    if not isinstance(query_text, str): return ""

    # 1. Decode URL (%09 -> \t)
    query_text = unquote(query_text)

    # 2. Decode Hex (0x64626f -> dbo)
    def hex_to_text(match):
        try:
            return bytearray.fromhex(match.group(1)).decode('utf-8', errors='ignore')
        except:
            return match.group(0)

    query_text = re.sub(r'0x([0-9a-fA-F]+)', hex_to_text, query_text)

    # 3. Heal Split Keywords (SE/**/LECT -> SELECT)
    query_text = re.sub(r'/\*.*?\*/', '', query_text)

    # 4. Split Symbols
    query_text = re.sub(r'([^\w\s])', r' \1 ', query_text)

    return " ".join(query_text.split())


@app.route('/check', methods=['POST'])
def check_query():
    try:
        data = request.get_json(force=True)
        raw_query = data.get('query', '')

        # Preprocess
        clean_q = clean_query(raw_query)

        # Tokenize & Predict
        seq = tokenizer.texts_to_sequences([clean_q])
        padded = pad_sequences(seq, maxlen=MAX_LEN)

        score = model.predict(padded, verbose=0)[0][0]

        return jsonify({
            "is_attack": bool(score > 0.2),
            "confidence": float(score)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    if __name__ == '__main__':
        import logging

        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

        print(" Defense Engine Running on Port 5000")
        print(" Optimization: LOGS DISABLED + THREADING ENABLED")

        app.run(host='0.0.0.0', port=5000, threaded=True)
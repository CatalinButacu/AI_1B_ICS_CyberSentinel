from flask import Flask, request, jsonify
import tensorflow as tf
import pickle
import numpy as np
import re
import os
from urllib.parse import unquote
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Model
import logging

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'anomaly_model.keras')
TOKEN_PATH = os.path.join(BASE_DIR, 'anomaly_tokenizer.pickle')
THRESHOLD_PATH = os.path.join(BASE_DIR, 'threshold.txt')
MAX_LEN = 50

model = tf.keras.models.load_model(MODEL_PATH, compile=False)

with open(TOKEN_PATH, 'rb') as handle:
    tokenizer = pickle.load(handle)

with open(THRESHOLD_PATH, 'r') as f:
    ANOMALY_THRESHOLD = float(f.read().strip())

embedding_layer = model.layers[1]
input_layer = model.input
vector_generator = Model(input_layer, embedding_layer(input_layer))

print(f"Threshold: {ANOMALY_THRESHOLD:.6f}")


def clean_minimal(query_text):
    if not isinstance(query_text, str): return ""
    query_text = unquote(query_text)

    query_text = query_text.replace("'", " ").replace('"', " ")

    query_text = re.sub(r'([^\w\s])', r' \1 ', query_text)

    return " ".join(query_text.split()).lower()


@app.route('/check', methods=['POST'])
def check_query():
    try:
        data = request.get_json(force=True)
        raw_query = data.get('query', '')

        raw_query = raw_query.strip("'").strip('"')

        clean_q = clean_minimal(raw_query)

        seq = tokenizer.texts_to_sequences([clean_q])

        print(f"\nOriginal: {raw_query}")
        print(f"Cleaned:  {clean_q}")
        print(f"Tokens:   {seq[0]}")

        padded = pad_sequences(seq, maxlen=MAX_LEN, padding='post', truncating='post')

        reconstructed_vectors = model.predict(padded, verbose=0)

        real_vectors = vector_generator.predict(padded, verbose=0)

        mse = np.mean(np.square(real_vectors - reconstructed_vectors))

        is_attack = bool(mse > ANOMALY_THRESHOLD)

        return jsonify({
            "is_attack": is_attack,
            "confidence": float(mse),
            "threshold": ANOMALY_THRESHOLD
        })

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host='0.0.0.0', port=5000, threaded=True)
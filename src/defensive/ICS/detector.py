from flask import Flask, request, jsonify
import tensorflow as tf
import pickle
import numpy as np
from tensorflow.keras.preprocessing.sequence import pad_sequences
import os

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

model = tf.keras.models.load_model(os.path.join(BASE_DIR, 'my_model.keras'))

with open(os.path.join(BASE_DIR, 'tokenizer.pickle'), 'rb') as handle:
    tokenizer = pickle.load(handle)

max_length = 100
threshold = 0.2

@app.route('/check', methods=['POST'])
def check_query():
    """
    Input: JSON {"query": "SELECT * FROM..."}
    Output: JSON {"is_attack": true, "confidence": 0.99}
    """
    try:
        data = request.get_json(force=True)
        query_text = data.get('query', '')

        #preprocess the incoming query
        seq = tokenizer.texts_to_sequences([query_text])
        padded = pad_sequences(seq, maxlen=max_length)

        #predict
        prediction_score = model.predict(padded, verbose=0)[0][0]
        is_attack = bool(prediction_score > threshold)

        print("Response from AI:", is_attack, prediction_score)

        return jsonify({
            "is_attack": is_attack,
            "confidence": float(prediction_score)
        })

    except Exception as e:
        print(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    import logging

    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    app.run(host='0.0.0.0', port=5000, threaded=True)
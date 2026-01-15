from flask import Flask, request, jsonify
import pickle
import os
import logging

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'rf_model_dirty.pkl')

with open(MODEL_PATH, 'rb') as f:
    pipeline = pickle.load(f)

@app.route('/check', methods=['POST'])
def check_query():
    try:
        data = request.get_json(force=True)
        raw_query = data.get('query', '')

        probabilities = pipeline.predict_proba([raw_query])[0]

        confidence = float(probabilities[1])
        is_attack = confidence > 0.2

        return jsonify({
            "is_attack": is_attack,
            "confidence": confidence,
        })

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    import logging

    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    app.run(host='0.0.0.0', port=5000, threaded=True)
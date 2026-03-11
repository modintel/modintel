from flask import Flask, request, jsonify
import os

app = Flask(__name__)

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    # TODO: Load ONNX model and predict
    # For now, return mock data
    return jsonify({
        "attack_probability": 0.5,
        "decision": "review",
        "explanation": "Mock prediction"
    })

if __name__ == '__main__':
    port = int(os.getenv("PORT", 8083))
    app.run(host='0.0.0.0', port=port)

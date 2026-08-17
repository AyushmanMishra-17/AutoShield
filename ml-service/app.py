import math
import numpy as np
from flask import Flask, jsonify, request
from sklearn.ensemble import IsolationForest

app = Flask(__name__)
FEATURES = ("requests", "failedLogins", "requestRate", "timeGap")

# Small controlled baseline retained from the original project.
X_train = np.array([
    [10, 1, 2, 5], [20, 0, 3, 4], [15, 1, 2, 6], [18, 2, 3, 5],
    [25, 1, 4, 3], [60, 8, 7, 1.2], [380, 1, 18, 0.2], [110, 25, 9, 0.4]
], dtype=float)

model = IsolationForest(contamination=0.25, random_state=42)
model.fit(X_train)
TRAIN_SCORES = model.decision_function(X_train)
SCORE_SCALE = max(float(np.std(TRAIN_SCORES)) * 1.5, 0.03)


def read_features(payload):
    if not isinstance(payload, dict):
        raise ValueError("JSON object expected")
    values = []
    for field in FEATURES:
        if field not in payload:
            raise ValueError(f"Missing field: {field}")
        try:
            value = float(payload[field])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Field must be numeric: {field}") from exc
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"Feature must be a finite non-negative number: {field}")
        values.append(value)
    return np.array([values], dtype=float)


def confidence_from_distance(score):
    # This is a normalized confidence proxy based on separation from the
    # Isolation Forest decision boundary (0), NOT a probability.
    distance = abs(float(score))
    return float(1.0 / (1.0 + math.exp(-distance / SCORE_SCALE)))


def explain(values, score, is_anomaly):
    requests, failed_logins, request_rate, time_gap = values
    if not is_anomaly:
        return "Traffic remains close to the learned baseline."
    if requests > 250 or request_rate > 15:
        return "High request volume and request rate match a DDoS-like pattern."
    if failed_logins > 10:
        return "Repeated failed logins match a brute-force pattern."
    if time_gap < 0.5:
        return "Very small request gaps indicate automated traffic."
    return f"Combined feature drift crossed the anomaly boundary ({score:.3f})."


@app.get("/health")
def health():
    return jsonify({"ok": True, "model": "IsolationForest", "features": FEATURES})


@app.post("/predict")
def predict():
    try:
        features = read_features(request.get_json(silent=True))
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    score = float(model.decision_function(features)[0])
    prediction = int(model.predict(features)[0])
    is_anomaly = prediction == -1
    confidence = confidence_from_distance(score)

    return jsonify({
        "anomaly_score": score,
        "confidence": confidence,
        "confidence_type": "decision-boundary separation",
        "is_anomaly": is_anomaly,
        "explanation": explain(features[0], score, is_anomaly),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
